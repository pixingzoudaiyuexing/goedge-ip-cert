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
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/scheduler"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
)

var ErrInjectedCrash = errors.New("injected crash")

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
	BindCertificate(context.Context, int64, int64) (bool, error)
}

type CrashHook func(point string) error

type Runner struct {
	State            *state.Store
	Challenges       challenge.Store
	Edge             EdgeClient
	Issuer           Issuer
	Schedule         scheduler.Policy
	AccountReference string
	Now              func() time.Time
	Hook             CrashHook
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
	return result, nil
}

func (r *Runner) RunOnce(ctx context.Context, ip string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.Issuer == nil || r.AccountReference == "" {
		return errors.New("apply 模式缺少 ACME issuer/account reference")
	}
	if err := r.Challenges.CheckSchema(ctx); err != nil {
		return err
	}
	if err := challenge.Recover(ctx, r.Challenges, r.State); err != nil {
		return fmt.Errorf("恢复 challenge: %w", err)
	}
	if err := r.recoverOperations(ctx); err != nil {
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
	managed, err := r.State.Managed(ctx, ip)
	if errors.Is(err, state.ErrNotFound) {
		return r.startIssue(ctx, ip, target, retry.Attempt)
	}
	if err != nil {
		return err
	}
	if managed.ServerID != target.ID || managed.PolicyID != target.PolicyID {
		return errors.New("Server/Policy 已变化，拒绝自动猜测或重绑")
	}
	if !r.Schedule.Due(r.Now(), time.Unix(managed.NextRenewalAt, 0)) {
		return nil
	}
	return r.startRenew(ctx, managed, retry.Attempt)
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
		stateErr := r.State.SetErrorWithRetry(ctx, op.ID, state.StateChallengePresent, string(scheduler.ErrorTransient),
			"ACME issuance failed", "retry-new-order", retryAttempt+1, nextRetry)
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
	if err := r.State.SaveIssued(ctx, op.ID, state.StateChallengePresent, verified.CertPEM, verified.KeyPEM, verified.Fingerprint, verified.NotAfter.Unix()); err != nil {
		return err
	}
	if err := r.crash("after-cert-issuance"); err != nil {
		return err
	}
	op, err = r.State.Operation(ctx, op.ID)
	if err != nil {
		return err
	}
	return r.continueRecorded(ctx, op)
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
			if err := r.continueRecorded(ctx, op); err != nil {
				return fmt.Errorf("恢复 operation %s: %w", op.ID, err)
			}
		default:
			return fmt.Errorf("未知 lifecycle stage %q", op.Stage)
		}
	}
	return nil
}

func (r *Runner) continueRecorded(ctx context.Context, op state.Operation) error {
	err := r.continueOperation(ctx, op)
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
	case errors.Is(err, goedge.ErrPolicyDrift), errors.Is(err, goedge.ErrMultipleServers), errors.Is(err, goedge.ErrServerNotFound):
		return string(scheduler.ErrorConfig), "manual-reconciliation"
	default:
		return string(scheduler.ErrorTransient), "retry-integration-step"
	}
}

func (r *Runner) continueOperation(ctx context.Context, op state.Operation) error {
	var err error
	if op.Stage == state.StateCertIssued {
		if op.Kind == state.OperationIssue {
			err = r.ensureCreated(ctx, &op)
		} else {
			err = r.ensureUpdated(ctx, &op)
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
		if _, err := r.Edge.BindCertificate(ctx, op.PolicyID, op.CertID); err != nil {
			return err
		}
		if err := r.crash("after-policy-bind"); err != nil {
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

func (r *Runner) ensureCreated(ctx context.Context, op *state.Operation) error {
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
	input, err := r.inputForOperation(*op, goedge.CertificateConfig{IsOn: true, Name: op.Marker})
	if err != nil {
		return err
	}
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

func (r *Runner) ensureUpdated(ctx context.Context, op *state.Operation) error {
	current, err := r.Edge.Certificate(ctx, op.CertID)
	if err != nil {
		return err
	}
	if err := validateManagedCertificate(current, op.IPv4); err != nil {
		return err
	}
	if fingerprint(current.CertData) == op.CertFingerprint && current.TimeEndAt == op.ExpiresAt {
		return r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, op.CertID)
	}
	input, err := r.inputForOperation(*op, current)
	if err != nil {
		return err
	}
	if err := r.Edge.UpdateCertificate(ctx, input); err != nil {
		return err
	}
	if err := r.crash("after-cert-update"); err != nil {
		return err
	}
	readBack, err := r.Edge.Certificate(ctx, op.CertID)
	if err != nil {
		return err
	}
	if fingerprint(readBack.CertData) != op.CertFingerprint || readBack.TimeEndAt != op.ExpiresAt {
		return errors.New("证书更新后 read-back 不一致")
	}
	return r.State.SetCertCreated(ctx, op.ID, state.StateCertIssued, op.CertID)
}

func (r *Runner) inputForOperation(op state.Operation, old goedge.CertificateConfig) (goedge.CertificateInput, error) {
	verified, err := certcheck.Verify(op.CertPEM, op.KeyPEM, op.IPv4, r.Now())
	if err != nil {
		return goedge.CertificateInput{}, err
	}
	return goedge.CertificateInput{
		ID: op.CertID, UserID: op.UserID, IsOn: old.IsOn, Name: old.Name, Description: old.Description, ServerName: old.ServerName,
		IsCA: false, CertData: op.CertPEM, KeyData: op.KeyPEM, TimeBeginAt: verified.NotBefore.Unix(),
		TimeEndAt: verified.NotAfter.Unix(), DNSNames: verified.DNSNames, CommonNames: verified.CommonNames,
	}, nil
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
