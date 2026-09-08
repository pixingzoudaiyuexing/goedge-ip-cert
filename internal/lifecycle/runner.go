package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	acmeclient "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/acme"
	certcheck "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/certificate"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/rollback"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/scheduler"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
)

var ErrInjectedCrash = errors.New("injected crash")
var errReissueRequired = errors.New("certificate private key is unavailable; reissue required")

type Issuer interface {
	Obtain(context.Context, string, string) (acmeclient.IssuedCertificate, error)
}

type EdgeClient interface {
	DiscoverServer(context.Context, string) (goedge.ServerTarget, error)
	Policy(context.Context, int64) (goedge.SSLPolicy, error)
	CreateCertificate(context.Context, goedge.CertificateInput) (int64, error)
	UpdateCertificate(context.Context, goedge.CertificateInput) error
	Certificate(context.Context, int64) (goedge.CertificateConfig, error)
	FindCertificateByMarker(context.Context, string, int64) (goedge.CertificateConfig, error)
	VerifyCertificateBound(context.Context, int64, int64) error
}

type CrashHook func(point string) error

type RollbackStore interface {
	Save(rollback.Snapshot) error
	List() ([]rollback.Snapshot, error)
	Delete(string) error
}

type TLSVerifier interface {
	Verify(context.Context, string, string) error
}

type RunMode uint8

const (
	RunModeInteractive RunMode = iota
	RunModeTimer
	RunModeManualFirstIssueRetry
)

type Runner struct {
	State            *state.Store
	Challenges       challenge.Store
	Edge             EdgeClient
	Issuer           Issuer
	Rollbacks        RollbackStore
	TLS              TLSVerifier
	Schedule         scheduler.Policy
	AccountReference string
	Now              func() time.Time
	Hook             CrashHook
	Mode             RunMode
}

type DryRunResult struct {
	IPv4      string
	ServerID  int64
	PolicyID  int64
	CertID    int64
	Managed   bool
	ExpiresAt int64
	Due       bool
}

func (r *Runner) Validate() error {
	if r.State == nil || r.Challenges == nil || r.Edge == nil {
		return errors.New("lifecycle dependencies 不完整")
	}
	if err := r.Schedule.Validate(); err != nil {
		return err
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Mode > RunModeManualFirstIssueRetry {
		return errors.New("lifecycle run mode 无效")
	}
	return nil
}

func (r *Runner) DryRun(ctx context.Context, ip string) (DryRunResult, error) {
	if err := r.Validate(); err != nil {
		return DryRunResult{}, err
	}
	if err := r.Challenges.CheckSchema(ctx); err != nil {
		return DryRunResult{}, err
	}
	target, err := r.Edge.DiscoverServer(ctx, ip)
	if err != nil {
		return DryRunResult{}, err
	}
	if _, err := r.Edge.Policy(ctx, target.PolicyID); err != nil {
		return DryRunResult{}, err
	}
	result := DryRunResult{IPv4: ip, ServerID: target.ID, PolicyID: target.PolicyID}
	managed, err := r.State.Managed(ctx, ip)
	if errors.Is(err, state.ErrNotFound) {
		return result, nil
	}
	if err != nil {
		return DryRunResult{}, err
	}
	result.Managed = true
	result.CertID = managed.CertID
	result.ExpiresAt = managed.ExpiresAt
	result.Due = r.Schedule.Due(r.Now(), time.Unix(managed.NextRenewalAt, 0))
	if managed.ServerID != target.ID || managed.PolicyID != target.PolicyID {
		return DryRunResult{}, errors.New("本地 state 与当前 Server/Policy 不一致，拒绝自动修改")
	}
	cert, err := r.Edge.Certificate(ctx, managed.CertID)
	if err != nil {
		return DryRunResult{}, err
	}
	if err := validateManagedCertificate(cert, ip); err != nil {
		return DryRunResult{}, err
	}
	if err := r.Edge.VerifyCertificateBound(ctx, managed.PolicyID, managed.CertID); err != nil {
		return DryRunResult{}, err
	}
	return result, nil
}

func (r *Runner) RunOnce(ctx context.Context, ip string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Issuer == nil || r.AccountReference == "" {
		return errors.New("apply 模式缺少 ACME issuer/account reference")
	}
	if r.Rollbacks == nil || r.TLS == nil {
		return errors.New("apply 模式缺少 rollback store 或 TLS verifier")
	}
	if err := r.Challenges.CheckSchema(ctx); err != nil {
		return err
	}
	if err := challenge.Recover(ctx, r.Challenges, r.State); err != nil {
		return fmt.Errorf("恢复 challenge: %w", err)
	}
	if err := r.recoverRollbacks(ctx); err != nil {
		return fmt.Errorf("恢复 rollback: %w", err)
	}
	if err := r.recoverOperations(ctx); err != nil {
		return err
	}
	managed, err := r.State.Managed(ctx, ip)
	if errors.Is(err, state.ErrNotFound) {
		return r.runFirstIssue(ctx, ip)
	}
	if err != nil {
		return err
	}
	retry, err := r.State.LatestRetry(ctx, ip)
	if err != nil {
		return err
	}
	if retry.NextAt > r.Now().Unix() {
		return nil
	}
	target, err := r.Edge.DiscoverServer(ctx, ip)
	if err != nil {
		return err
	}
	if managed.ServerID != target.ID || managed.PolicyID != target.PolicyID {
		return errors.New("Server/Policy 已变化，拒绝自动猜测或重绑")
	}
	current, err := r.Edge.Certificate(ctx, managed.CertID)
	if err != nil {
		return err
	}
	if err := validateManagedCertificate(current, ip); err != nil {
		return err
	}
	if err := r.Edge.VerifyCertificateBound(ctx, managed.PolicyID, managed.CertID); err != nil {
		return err
	}
	if !r.Schedule.Due(r.Now(), time.Unix(managed.NextRenewalAt, 0)) {
		return nil
	}
	return r.startRenew(ctx, managed, retry.Attempt)
}

func (r *Runner) runFirstIssue(ctx context.Context, ip string) error {
	retryAttempt := 0
	operation, err := r.State.LatestOperation(ctx, ip)
	if err == nil {
		if state.IsFirstIssueFailure(operation) {
			if operation.RecoveryMarker != state.RecoveryNeedsAttention {
				if err := r.State.NormalizeFirstIssueFailure(ctx, operation.ID); err != nil {
					return err
				}
			}
			if r.Mode != RunModeManualFirstIssueRetry {
				return nil
			}
			retryAttempt = operation.RetryCount
		} else {
			return fmt.Errorf("target 有 %s operation 但没有 managed certificate，拒绝创建新 order", operation.Stage)
		}
	} else if err != nil && !errors.Is(err, state.ErrNotFound) {
		return err
	} else if r.Mode == RunModeTimer {
		return nil
	} else if r.Mode == RunModeManualFirstIssueRetry {
		return errors.New("target 没有可供手工重试的首次签发失败状态")
	}
	target, err := r.Edge.DiscoverServer(ctx, ip)
	if err != nil {
		return err
	}
	return r.startIssue(ctx, ip, target, retryAttempt)
}

func (r *Runner) startIssue(ctx context.Context, ip string, target goedge.ServerTarget, retryAttempt int) error {
	id, err := state.NewOperationID()
	if err != nil {
		return err
	}
	marker := "goedge-ip-cert/" + ip + "/" + id
	op := state.Operation{ID: id, IPv4: ip, Kind: state.OperationIssue, Stage: state.StateNew,
		Marker: marker, ServerID: target.ID, PolicyID: target.PolicyID, UserID: target.UserID}
	if err := r.State.CreateOperation(ctx, op); err != nil {
		return err
	}
	return r.obtainAndContinue(ctx, op, retryAttempt)
}

func (r *Runner) startRenew(ctx context.Context, managed state.ManagedCert, retryAttempt int) error {
	id, err := state.NewOperationID()
	if err != nil {
		return err
	}
	op := state.Operation{ID: id, IPv4: managed.IPv4, Kind: state.OperationRenew, Stage: state.StateRenewing,
		Marker: "goedge-ip-cert-renew/" + managed.IPv4 + "/" + id, ServerID: managed.ServerID,
		PolicyID: managed.PolicyID, CertID: managed.CertID}
	if err := r.State.BeginRenewal(ctx, op); err != nil {
		return err
	}
	return r.obtainAndContinue(ctx, op, retryAttempt)
}

func (r *Runner) obtainAndContinue(ctx context.Context, op state.Operation, retryAttempt int) error {
	if err := r.State.Transition(ctx, op.ID, op.Stage, state.StateChallengePresent, "awaiting-acme"); err != nil {
		return err
	}
	issued, err := r.Issuer.Obtain(ctx, op.ID, op.IPv4)
	if err != nil {
		nextRetry := r.Now().Add(r.Schedule.RetryDelay(retryAttempt)).Unix()
		marker := "retry-new-order"
		if op.Kind == state.OperationIssue {
			marker = state.RecoveryNeedsAttention
		}
		stateErr := r.State.SetErrorWithRetry(ctx, op.ID, state.StateChallengePresent, string(scheduler.ErrorTransient),
			"ACME issuance failed", marker, retryAttempt+1, nextRetry)
		if stateErr != nil {
			return fmt.Errorf("ACME 失败且无法保存退避状态: %w", stateErr)
		}
		if op.Kind == state.OperationRenew {
			if stateErr := r.State.RecordManagedError(ctx, op.IPv4, string(scheduler.ErrorTransient), "ACME issuance failed", "retry-new-order"); stateErr != nil {
				return fmt.Errorf("ACME 失败且无法保存证书错误状态: %w", stateErr)
			}
		}
		return err
	}
	verified, err := certcheck.Verify(issued.Certificate, issued.PrivateKey, op.IPv4, r.Now())
	if err != nil {
		if stateErr := r.State.SetError(ctx, op.ID, state.StateChallengePresent, string(scheduler.ErrorSecurity), "issued certificate validation failed", "manual-review"); stateErr != nil {
			return fmt.Errorf("证书校验失败且无法保存错误状态: %w", stateErr)
		}
		return err
	}
	if err := r.State.SaveIssued(ctx, op.ID, state.StateChallengePresent, verified.Fingerprint, verified.NotAfter.Unix()); err != nil {
		return err
	}
	if err := r.crash("after-cert-issuance"); err != nil {
		return err
	}
	op, err = r.State.Operation(ctx, op.ID)
	if err != nil {
		return err
	}
	return r.continueRecorded(ctx, op, verified)
}

func (r *Runner) recoverOperations(ctx context.Context) error {
	operations, err := r.State.ListIncompleteOperations(ctx)
	if err != nil {
		return err
	}
	for _, op := range operations {
		switch op.Stage {
		case state.StateNew, state.StateRenewing, state.StateChallengePresent:
			if err := r.State.SetError(ctx, op.ID, op.Stage, string(scheduler.ErrorTransient), "operation interrupted before certificate persisted", "retry-new-order"); err != nil {
				return err
			}
		case state.StateCertIssued, state.StateCertCreated, state.StatePolicyBound:
			if err := r.continueRecorded(ctx, op, nil); errors.Is(err, errReissueRequired) {
				nextRetry := r.Now().Add(r.Schedule.RetryDelay(op.RetryCount)).Unix()
				if stateErr := r.State.SetErrorWithRetry(ctx, op.ID, op.Stage, string(scheduler.ErrorTransient),
					"certificate private key unavailable after restart", "retry-new-order", op.RetryCount+1, nextRetry); stateErr != nil {
					return stateErr
				}
				continue
			} else if err != nil {
				return fmt.Errorf("恢复 operation %s: %w", op.ID, err)
			}
		default:
			return fmt.Errorf("未知 lifecycle stage %q", op.Stage)
		}
	}
	return nil
}

func (r *Runner) recoverRollbacks(ctx context.Context) error {
	snapshots, err := r.Rollbacks.List()
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		op, err := r.State.Operation(ctx, snapshot.OperationID)
		if err != nil {
			return fmt.Errorf("rollback operation %s 不存在: %w", snapshot.OperationID, err)
		}
		if op.Kind != state.OperationRenew || op.IPv4 != snapshot.IPv4 || op.CertID != snapshot.CertID {
			return errors.New("rollback snapshot 与 operation 不一致")
		}
		if err := r.TLS.Verify(ctx, snapshot.IPv4, snapshot.NewFingerprint); err == nil {
			current, readErr := r.Edge.Certificate(ctx, snapshot.CertID)
			if readErr != nil || fingerprint(current.CertData) != snapshot.NewFingerprint {
				return errors.New("TLS 已返回新证书但 EdgeAPI read-back 不一致")
			}
			if op.Stage == state.StateCertIssued {
				if err := r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, op.CertID); err != nil {
					return err
				}
			}
			if err := r.Rollbacks.Delete(snapshot.OperationID); err != nil {
				return err
			}
			continue
		}
		if err := r.restoreOldCertificate(ctx, op, snapshot); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) continueRecorded(ctx context.Context, op state.Operation, verified *certcheck.Verified) error {
	err := r.continueOperation(ctx, op, verified)
	if err == nil {
		return nil
	}
	current, readErr := r.State.Operation(ctx, op.ID)
	if readErr != nil {
		return fmt.Errorf("integration step 失败且无法读取恢复状态: %w", readErr)
	}
	category, marker := classifyError(err)
	if stateErr := r.State.RecordOperationFailure(ctx, op.ID, current.Stage, category, "integration step failed", marker); stateErr != nil {
		return fmt.Errorf("integration step 失败且无法保存恢复状态: %w", stateErr)
	}
	return err
}

func classifyError(err error) (category, marker string) {
	switch {
	case errors.Is(err, goedge.ErrAuthentication):
		return string(scheduler.ErrorAuth), "fix-goedge-credentials"
	case errors.Is(err, challenge.ErrSchemaMismatch):
		return string(scheduler.ErrorSchema), "review-goedge-schema"
	case errors.Is(err, goedge.ErrCertificateNotBound), errors.Is(err, goedge.ErrMultipleServers), errors.Is(err, goedge.ErrServerNotFound):
		return string(scheduler.ErrorConfig), "manual-reconciliation"
	default:
		return string(scheduler.ErrorTransient), "retry-integration-step"
	}
}

func (r *Runner) continueOperation(ctx context.Context, op state.Operation, verified *certcheck.Verified) error {
	var err error
	if op.Stage == state.StateCertIssued {
		if op.Kind == state.OperationIssue {
			err = r.ensureCreated(ctx, &op, verified)
		} else {
			err = r.ensureUpdated(ctx, &op, verified)
		}
		if err != nil {
			return err
		}
		op, err = r.State.Operation(ctx, op.ID)
		if err != nil {
			return err
		}
	}
	if op.Stage == state.StateCertCreated {
		if err := r.Edge.VerifyCertificateBound(ctx, op.PolicyID, op.CertID); err != nil {
			return err
		}
		if op.Kind == state.OperationIssue {
			if err := r.TLS.Verify(ctx, op.IPv4, op.CertFingerprint); err != nil {
				return fmt.Errorf("新证书尚未通过 TLS 验证: %w", err)
			}
		}
		if err := r.crash("after-policy-verification"); err != nil {
			return err
		}
		if err := r.State.SetPolicyBound(ctx, op.ID, state.StateCertCreated); err != nil {
			return err
		}
		op.Stage = state.StatePolicyBound
	}
	if op.Stage == state.StatePolicyBound {
		next := r.Schedule.NextRenewal(op.IPv4, time.Unix(op.ExpiresAt, 0))
		return r.State.SetActive(ctx, op.ID, state.StatePolicyBound, r.AccountReference, next.Unix())
	}
	return nil
}

func (r *Runner) ensureCreated(ctx context.Context, op *state.Operation, verified *certcheck.Verified) error {
	existing, err := r.Edge.FindCertificateByMarker(ctx, op.Marker, op.UserID)
	if err == nil {
		full, readErr := r.Edge.Certificate(ctx, existing.ID)
		if readErr != nil {
			return readErr
		}
		if err := validateManagedCertificate(full, op.IPv4); err != nil {
			return err
		}
		if fingerprint(full.CertData) != op.CertFingerprint || full.TimeEndAt != op.ExpiresAt {
			return errors.New("marker 命中的证书与 pending certificate 不一致")
		}
		op.CertID = existing.ID
		return r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, existing.ID)
	}
	if !errors.Is(err, goedge.ErrCertificateNotFound) {
		return err
	}
	if verified == nil {
		return errReissueRequired
	}
	input := r.inputForOperation(*op, goedge.CertificateConfig{IsOn: true, Name: op.Marker}, verified)
	certID, err := r.Edge.CreateCertificate(ctx, input)
	if err != nil {
		return err
	}
	if err := r.crash("after-cert-create"); err != nil {
		return err
	}
	op.CertID = certID
	return r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, certID)
}

func (r *Runner) ensureUpdated(ctx context.Context, op *state.Operation, verified *certcheck.Verified) error {
	current, err := r.Edge.Certificate(ctx, op.CertID)
	if err != nil {
		return err
	}
	if err := validateManagedCertificate(current, op.IPv4); err != nil {
		return err
	}
	if fingerprint(current.CertData) == op.CertFingerprint && current.TimeEndAt == op.ExpiresAt {
		if err := r.TLS.Verify(ctx, op.IPv4, op.CertFingerprint); err != nil {
			return fmt.Errorf("当前新证书未通过 TLS 验证: %w", err)
		}
		return r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, op.CertID)
	}
	if verified == nil {
		return errReissueRequired
	}
	oldInput := certificateInputFromConfig(current)
	if len(oldInput.CertData) == 0 || len(oldInput.KeyData) == 0 {
		return errors.New("旧证书或私钥为空，拒绝更新")
	}
	oldFingerprint := fingerprint(oldInput.CertData)
	if oldFingerprint == "" {
		return errors.New("无法计算旧证书 fingerprint")
	}
	snapshot := rollback.NewSnapshot(op.ID, op.IPv4, op.CertFingerprint, oldFingerprint, oldInput)
	if err := r.Rollbacks.Save(snapshot); err != nil {
		return fmt.Errorf("保存 rollback snapshot: %w", err)
	}
	if err := r.crash("after-rollback-snapshot"); err != nil {
		return err
	}
	input := r.inputForOperation(*op, current, verified)
	if err := r.Edge.UpdateCertificate(ctx, input); err != nil {
		return r.rollbackAfterFailure(ctx, *op, snapshot, fmt.Errorf("更新新证书: %w", err))
	}
	if err := r.crash("after-cert-update"); err != nil {
		return err
	}
	readBack, err := r.Edge.Certificate(ctx, op.CertID)
	if err != nil {
		return r.rollbackAfterFailure(ctx, *op, snapshot, fmt.Errorf("读取新证书: %w", err))
	}
	if fingerprint(readBack.CertData) != op.CertFingerprint || readBack.TimeEndAt != op.ExpiresAt {
		return r.rollbackAfterFailure(ctx, *op, snapshot, errors.New("证书更新后 read-back 不一致"))
	}
	if err := r.TLS.Verify(ctx, op.IPv4, op.CertFingerprint); err != nil {
		return r.rollbackAfterFailure(ctx, *op, snapshot, fmt.Errorf("新证书 TLS 验证失败: %w", err))
	}
	if err := r.crash("after-tls-verification"); err != nil {
		return err
	}
	if err := r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, op.CertID); err != nil {
		return err
	}
	if err := r.Rollbacks.Delete(op.ID); err != nil {
		return fmt.Errorf("删除 rollback snapshot: %w", err)
	}
	return nil
}

func (r *Runner) rollbackAfterFailure(ctx context.Context, op state.Operation, snapshot rollback.Snapshot, cause error) error {
	if err := r.restoreOldCertificate(ctx, op, snapshot); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

func (r *Runner) restoreOldCertificate(ctx context.Context, op state.Operation, snapshot rollback.Snapshot) error {
	updateErr := r.Edge.UpdateCertificate(ctx, snapshot.Old)
	if err := r.TLS.Verify(ctx, snapshot.IPv4, snapshot.OldFingerprint); err != nil {
		if updateErr != nil {
			return errors.Join(fmt.Errorf("恢复旧证书: %w", updateErr), fmt.Errorf("旧证书 TLS 恢复无法确认: %w", err))
		}
		return fmt.Errorf("旧证书已提交但 TLS 恢复无法确认: %w", err)
	}
	nextRetry := r.Now().Add(r.Schedule.RetryDelay(op.RetryCount)).Unix()
	if op.Stage != state.StateError {
		if err := r.State.SetErrorWithRetry(ctx, op.ID, op.Stage, string(scheduler.ErrorTransient),
			"new certificate failed TLS verification and old certificate was restored", "retry-new-order", op.RetryCount+1, nextRetry); err != nil {
			return err
		}
	}
	if err := r.State.RecordManagedError(ctx, op.IPv4, string(scheduler.ErrorTransient),
		"new certificate failed TLS verification and old certificate was restored", "retry-new-order"); err != nil {
		return err
	}
	if err := r.Rollbacks.Delete(snapshot.OperationID); err != nil {
		return err
	}
	return nil
}

func (r *Runner) inputForOperation(op state.Operation, old goedge.CertificateConfig, verified *certcheck.Verified) goedge.CertificateInput {
	return goedge.CertificateInput{
		ID: op.CertID, UserID: op.UserID, IsOn: old.IsOn, Name: old.Name, Description: old.Description, ServerName: old.ServerName,
		IsCA: false, CertData: verified.CertPEM, KeyData: verified.KeyPEM, TimeBeginAt: verified.NotBefore.Unix(),
		TimeEndAt: verified.NotAfter.Unix(), DNSNames: verified.DNSNames, CommonNames: verified.CommonNames,
	}
}

func certificateInputFromConfig(cert goedge.CertificateConfig) goedge.CertificateInput {
	return goedge.CertificateInput{ID: cert.ID, IsOn: cert.IsOn, Name: cert.Name, Description: cert.Description,
		ServerName: cert.ServerName, IsCA: cert.IsCA, CertData: append([]byte(nil), cert.CertData...),
		KeyData: append([]byte(nil), cert.KeyData...), TimeBeginAt: cert.TimeBeginAt, TimeEndAt: cert.TimeEndAt,
		DNSNames: append([]string(nil), cert.DNSNames...), CommonNames: append([]string(nil), cert.CommonNames...)}
}

func (r *Runner) crash(point string) error {
	if r.Hook == nil {
		return nil
	}
	return r.Hook(point)
}

func fingerprint(certPEM []byte) string {
	cert, err := certcheck.ParseFirstCertificate(certPEM)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(digest[:])
}

func validateManagedCertificate(cert goedge.CertificateConfig, ip string) error {
	if cert.ID <= 0 || cert.IsCA || cert.IsACME {
		return errors.New("GoEdge cert 不是可由外部 Manager 管理的证书")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != ip {
		return errors.New("GoEdge cert SAN metadata 与受管 IPv4 不一致")
	}
	return nil
}
