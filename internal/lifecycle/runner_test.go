package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	acmeclient "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/acme"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/rollback"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/scheduler"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/testutil"
)

type noOpChallenges struct{}

func (noOpChallenges) CheckSchema(context.Context) error { return nil }
func (noOpChallenges) Create(context.Context, challenge.Challenge) (challenge.Challenge, error) {
	return challenge.Challenge{}, errors.New("not used")
}
func (noOpChallenges) Delete(context.Context, challenge.Challenge) error {
	return errors.New("not used")
}
func (noOpChallenges) FindOwned(context.Context, string, string, int64) ([]challenge.Challenge, error) {
	return nil, nil
}

type fakeIssuer struct {
	mu    sync.Mutex
	now   *time.Time
	calls int
	err   error
}

func (f *fakeIssuer) Obtain(_ context.Context, _, ip string) (acmeclient.IssuedCertificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return acmeclient.IssuedCertificate{}, f.err
	}
	certPEM, keyPEM, err := testutil.Certificate(testutil.CertOptions{IP: ip, NotBefore: f.now.Add(-time.Minute), NotAfter: f.now.Add(160 * time.Hour)})
	return acmeclient.IssuedCertificate{Certificate: certPEM, PrivateKey: keyPEM}, err
}

type fakeEdge struct {
	mu               sync.Mutex
	target           goedge.ServerTarget
	policy           goedge.SSLPolicy
	nextID           int64
	certs            map[int64]goedge.CertificateConfig
	createCalls      int
	updateCalls      int
	policyWrites     int
	lastCreateUserID int64
	lastFindUserID   int64
	bindOnCreate     bool
	rollbacks        *memoryRollbackStore
	tls              *fakeTLSVerifier
}

func newFakeEdge() *fakeEdge {
	edge := &fakeEdge{target: goedge.ServerTarget{ID: 117, UserID: 42, PolicyID: 113, HTTPSIsOn: true},
		policy: goedge.SSLPolicy{ID: 113, IsOn: true, MinVersion: "TLS 1.2", HTTP2Enabled: true},
		nextID: 200, certs: map[int64]goedge.CertificateConfig{}}
	edge.rollbacks = &memoryRollbackStore{items: map[string]rollback.Snapshot{}}
	edge.tls = &fakeTLSVerifier{edge: edge}
	return edge
}

type memoryRollbackStore struct {
	mu      sync.Mutex
	items   map[string]rollback.Snapshot
	deletes int
}

func (s *memoryRollbackStore) Save(snapshot rollback.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[snapshot.OperationID] = snapshot
	return nil
}

func (s *memoryRollbackStore) List() ([]rollback.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]rollback.Snapshot, 0, len(s.items))
	for _, snapshot := range s.items {
		result = append(result, snapshot)
	}
	return result, nil
}

func (s *memoryRollbackStore) Delete(operationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, operationID)
	s.deletes++
	return nil
}

type fakeTLSVerifier struct {
	mu       sync.Mutex
	edge     *fakeEdge
	failNext int
	calls    int
}

func (v *fakeTLSVerifier) Verify(_ context.Context, ip, expectedFingerprint string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.failNext > 0 {
		v.failNext--
		return errors.New("injected TLS verification failure")
	}
	v.edge.mu.Lock()
	defer v.edge.mu.Unlock()
	for _, cert := range v.edge.certs {
		if len(cert.DNSNames) == 1 && cert.DNSNames[0] == ip && fingerprint(cert.CertData) == expectedFingerprint {
			return nil
		}
	}
	return errors.New("expected certificate is not served")
}

func (f *fakeEdge) DiscoverServer(context.Context, string) (goedge.ServerTarget, error) {
	return f.target, nil
}
func (f *fakeEdge) Policy(context.Context, int64) (goedge.SSLPolicy, error) { return f.policy, nil }
func (f *fakeEdge) CreateCertificate(_ context.Context, input goedge.CertificateInput) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	input.ID = f.nextID
	f.certs[input.ID] = lifecycleConfig(input)
	f.createCalls++
	f.lastCreateUserID = input.UserID
	if f.bindOnCreate {
		// 模拟管理员在 EdgeAdmin 中完成绑定，不是 Cert Manager 写 Policy。
		f.policy.CertRefs = append(f.policy.CertRefs, goedge.SSLCertRef{IsOn: true, CertID: input.ID})
	}
	return input.ID, nil
}
func (f *fakeEdge) UpdateCertificate(_ context.Context, input goedge.CertificateInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.certs[input.ID]; !ok {
		return goedge.ErrCertificateNotFound
	}
	f.certs[input.ID] = lifecycleConfig(input)
	f.updateCalls++
	return nil
}
func (f *fakeEdge) Certificate(_ context.Context, id int64) (goedge.CertificateConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cert, ok := f.certs[id]
	if !ok {
		return goedge.CertificateConfig{}, goedge.ErrCertificateNotFound
	}
	return cert, nil
}
func (f *fakeEdge) FindCertificateByMarker(_ context.Context, marker string, userID int64) (goedge.CertificateConfig, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastFindUserID = userID
	var found []goedge.CertificateConfig
	for _, cert := range f.certs {
		if cert.Name == marker {
			found = append(found, cert)
		}
	}
	if len(found) == 0 {
		return goedge.CertificateConfig{}, goedge.ErrCertificateNotFound
	}
	if len(found) != 1 {
		return goedge.CertificateConfig{}, goedge.ErrMultipleCertificates
	}
	return found[0], nil
}
func (f *fakeEdge) VerifyCertificateBound(_ context.Context, policyID, certID int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.policy.ID != policyID {
		return errors.New("wrong policy")
	}
	for _, ref := range f.policy.CertRefs {
		if ref.CertID == certID && ref.IsOn {
			return nil
		}
	}
	return fmt.Errorf("%w: certificate ID %d, policy ID %d", goedge.ErrCertificateNotBound, certID, policyID)
}

func (f *fakeEdge) manualBind(certID int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policy.CertRefs = append(f.policy.CertRefs, goedge.SSLCertRef{IsOn: true, CertID: certID})
}

func (f *fakeEdge) onlyCert() goedge.CertificateConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, cert := range f.certs {
		return cert
	}
	return goedge.CertificateConfig{}
}

func (s *memoryRollbackStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

func TestInitialCertificateWaitsForManualPolicyBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, &fakeIssuer{now: &now}, &now)
	err := runner.RunOnce(ctx, "8.8.8.8")
	cert := edge.onlyCert()
	if !errors.Is(err, goedge.ErrCertificateNotBound) || !strings.Contains(err.Error(), fmt.Sprintf("certificate ID %d", cert.ID)) || !strings.Contains(err.Error(), "policy ID 113") {
		t.Fatalf("missing binding err=%v cert=%d", err, cert.ID)
	}
	if cert.ID <= 0 || edge.policyWrites != 0 {
		t.Fatalf("cert=%d policyWrites=%d", cert.ID, edge.policyWrites)
	}
	if _, err := store.Managed(ctx, "8.8.8.8"); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("unbound certificate became active: %v", err)
	}
	edge.manualBind(cert.ID)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, err := store.Managed(ctx, "8.8.8.8")
	if err != nil || managed.CertID != cert.ID || managed.State != state.StateActive || edge.policyWrites != 0 {
		t.Fatalf("managed=%+v err=%v policyWrites=%d", managed, err, edge.policyWrites)
	}
}

func TestIssueRecoversEveryPersistedCrashPointWithoutDuplicateCert(t *testing.T) {
	for _, crashPoint := range []string{"after-cert-create", "after-policy-verification"} {
		t.Run(crashPoint, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
			edge := newFakeEdge()
			edge.bindOnCreate = true
			issuer := &fakeIssuer{now: &now}
			store := openLifecycleState(t, path)
			runner := newRunner(store, edge, issuer, &now)
			runner.Hook = func(point string) error {
				if point == crashPoint {
					return ErrInjectedCrash
				}
				return nil
			}
			if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, ErrInjectedCrash) {
				t.Fatalf("first run err=%v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			store = reopenLifecycleState(t, path)
			runner = newRunner(store, edge, issuer, &now)
			if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
				t.Fatal(err)
			}
			managed, err := store.Managed(ctx, "8.8.8.8")
			if err != nil || managed.State != state.StateActive || managed.CertID <= 0 {
				t.Fatalf("managed=%+v err=%v", managed, err)
			}
			if edge.createCalls != 1 || edge.policyWrites != 0 || issuer.calls != 1 || edge.lastCreateUserID != 42 || edge.lastFindUserID != 42 {
				t.Fatalf("create=%d policyWrites=%d issue=%d createUser=%d findUser=%d", edge.createCalls, edge.policyWrites,
					issuer.calls, edge.lastCreateUserID, edge.lastFindUserID)
			}
		})
	}
}

func TestCrashAfterIssuanceRequiresExplicitFirstIssueRetry(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, path)
	runner := newRunner(store, edge, issuer, &now)
	runner.Hook = func(point string) error {
		if point == "after-cert-issuance" {
			return ErrInjectedCrash
		}
		return nil
	}
	if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("first run err=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = reopenLifecycleState(t, path)
	runner = newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 || edge.createCalls != 0 {
		t.Fatalf("immediate restart reissued or deployed: issuer=%d create=%d", issuer.calls, edge.createCalls)
	}
	now = now.Add(16 * time.Minute)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 || edge.createCalls != 0 {
		t.Fatalf("first issuance crash retried automatically: issuer=%d create=%d", issuer.calls, edge.createCalls)
	}
	runner.Mode = RunModeManualFirstIssueRetry
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 2 || edge.createCalls != 1 {
		t.Fatalf("explicit retry did not recover issuance: issuer=%d create=%d", issuer.calls, edge.createCalls)
	}
}

func TestRenewCrashRecoveryKeepsSameCertificateID(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, path)
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Managed(ctx, "8.8.8.8")
	now = time.Unix(before.NextRenewalAt+1, 0)
	runner.Hook = func(point string) error {
		if point == "after-cert-update" {
			return ErrInjectedCrash
		}
		return nil
	}
	if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("renew err=%v", err)
	}
	if edge.rollbacks.count() != 1 {
		t.Fatalf("rollback snapshots=%d after crash", edge.rollbacks.count())
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = reopenLifecycleState(t, path)
	runner = newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	after, err := store.Managed(ctx, "8.8.8.8")
	if err != nil || after.CertID != before.CertID {
		t.Fatalf("before=%+v after=%+v err=%v", before, after, err)
	}
	if edge.createCalls != 1 || edge.updateCalls != 1 || len(edge.certs) != 1 || issuer.calls != 2 {
		t.Fatalf("create=%d update=%d certs=%d issue=%d", edge.createCalls, edge.updateCalls, len(edge.certs), issuer.calls)
	}
	if edge.rollbacks.count() != 0 || edge.policyWrites != 0 {
		t.Fatalf("rollback snapshots=%d policyWrites=%d", edge.rollbacks.count(), edge.policyWrites)
	}
}

func TestRenewFailsClosedBeforeIssuanceWhenCertRecordWasDeleted(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, _ := store.Managed(ctx, "8.8.8.8")
	edge.mu.Lock()
	delete(edge.certs, managed.CertID)
	edge.mu.Unlock()
	now = time.Unix(managed.NextRenewalAt+1, 0)
	if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, goedge.ErrCertificateNotFound) {
		t.Fatalf("deleted cert error=%v", err)
	}
	if issuer.calls != 1 || edge.createCalls != 1 || edge.updateCalls != 0 || edge.policyWrites != 0 {
		t.Fatalf("issuer=%d create=%d update=%d policyWrites=%d", issuer.calls, edge.createCalls, edge.updateCalls, edge.policyWrites)
	}
}

func TestRenewTLSFailureRestoresOldCertificateAndCleansSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, &fakeIssuer{now: &now}, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, _ := store.Managed(ctx, "8.8.8.8")
	old := edge.onlyCert()
	oldFingerprint := fingerprint(old.CertData)
	now = time.Unix(managed.NextRenewalAt+1, 0)
	edge.tls.failNext = 1
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("new TLS failure was ignored")
	}
	current := edge.onlyCert()
	if current.ID != managed.CertID || fingerprint(current.CertData) != oldFingerprint {
		t.Fatalf("old certificate was not restored: id=%d", current.ID)
	}
	if edge.createCalls != 1 || edge.updateCalls != 2 || len(edge.certs) != 1 || edge.rollbacks.count() != 0 || edge.policyWrites != 0 {
		t.Fatalf("create=%d update=%d certs=%d snapshots=%d policyWrites=%d", edge.createCalls, edge.updateCalls,
			len(edge.certs), edge.rollbacks.count(), edge.policyWrites)
	}
}

func TestRollbackSnapshotRemainsWhenOldTLSCannotBeConfirmed(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, &fakeIssuer{now: &now}, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, _ := store.Managed(ctx, "8.8.8.8")
	now = time.Unix(managed.NextRenewalAt+1, 0)
	edge.tls.failNext = 2
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("rollback TLS failure was ignored")
	}
	if edge.rollbacks.count() != 1 {
		t.Fatalf("unconfirmed rollback snapshot count=%d, want 1", edge.rollbacks.count())
	}
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if edge.rollbacks.count() != 0 {
		t.Fatalf("recovered rollback snapshot count=%d", edge.rollbacks.count())
	}
}

func TestCrashAfterRollbackSnapshotRestoresOldCertificateFailSafe(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, &fakeIssuer{now: &now}, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, _ := store.Managed(ctx, "8.8.8.8")
	oldFingerprint := fingerprint(edge.onlyCert().CertData)
	now = time.Unix(managed.NextRenewalAt+1, 0)
	runner.Hook = func(point string) error {
		if point == "after-rollback-snapshot" {
			return ErrInjectedCrash
		}
		return nil
	}
	if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, ErrInjectedCrash) {
		t.Fatalf("crash err=%v", err)
	}
	if edge.rollbacks.count() != 1 || edge.updateCalls != 0 {
		t.Fatalf("snapshots=%d updates=%d", edge.rollbacks.count(), edge.updateCalls)
	}
	runner = newRunner(store, edge, &fakeIssuer{now: &now}, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if fingerprint(edge.onlyCert().CertData) != oldFingerprint || edge.updateCalls != 1 || edge.rollbacks.count() != 0 {
		t.Fatalf("old cert recovery failed: updates=%d snapshots=%d", edge.updateCalls, edge.rollbacks.count())
	}
}

func TestDryRunPerformsNoMutation(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	edge := newFakeEdge()
	runner := newRunner(store, edge, nil, &now)
	result, err := runner.DryRun(context.Background(), "8.8.8.8")
	if err != nil || result.ServerID != 117 || result.PolicyID != 113 || result.Managed || edge.createCalls != 0 || edge.updateCalls != 0 || edge.policyWrites != 0 {
		t.Fatalf("result=%+v err=%v mutations=%d/%d/%d", result, err, edge.createCalls, edge.updateCalls, edge.policyWrites)
	}
}

func TestInvalidIssuedCertificateIsNeverUploaded(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	edge := newFakeEdge()
	issuer := &wrongIPIssuer{now: &now}
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("wrong-IP certificate was accepted")
	}
	if edge.createCalls != 0 || edge.updateCalls != 0 || edge.policyWrites != 0 {
		t.Fatalf("invalid cert reached EdgeAPI: %d/%d/%d", edge.createCalls, edge.updateCalls, edge.policyWrites)
	}
}

type wrongIPIssuer struct{ now *time.Time }

func (i *wrongIPIssuer) Obtain(context.Context, string, string) (acmeclient.IssuedCertificate, error) {
	certPEM, keyPEM, err := testutil.Certificate(testutil.CertOptions{IP: "1.1.1.1", NotBefore: i.now.Add(-time.Minute), NotAfter: i.now.Add(160 * time.Hour)})
	return acmeclient.IssuedCertificate{Certificate: certPEM, PrivateKey: keyPEM}, err
}

func TestFirstIssuanceFailureDoesNotRetryAfterBackoff(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	issuer := &fakeIssuer{now: &now, err: errors.New("temporary CA outage")}
	runner := newRunner(store, newFakeEdge(), issuer, &now)

	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("first issuance failure was ignored")
	}
	now = now.Add(16 * time.Minute)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatalf("paused first issuance returned an error: %v", err)
	}
	if issuer.calls != 1 {
		t.Fatalf("first issuance was retried automatically, calls=%d", issuer.calls)
	}
	op, err := store.LatestOperation(ctx, "8.8.8.8")
	if err != nil || op.Stage != state.StateError || op.Kind != state.OperationIssue || op.CertID != 0 ||
		op.RecoveryMarker != state.RecoveryNeedsAttention || op.RetryCount != 1 || op.ErrorMessage == "" {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
}

func TestNeedsAttentionTimerTenRunsDoNotRetry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	issuer := &fakeIssuer{now: &now, err: errors.New("temporary CA outage")}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("ACME failure was ignored")
	}
	runner.Mode = RunModeTimer
	now = now.Add(24 * time.Hour)
	for range 10 {
		if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
			t.Fatal(err)
		}
	}
	if issuer.calls != 1 {
		t.Fatalf("timer retried NEEDS_ATTENTION target, calls=%d", issuer.calls)
	}
}

func TestNeedsAttentionSurvivesStoreRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	issuer := &fakeIssuer{now: &now, err: errors.New("temporary CA outage")}
	store := openLifecycleState(t, path)
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("ACME failure was ignored")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = reopenLifecycleState(t, path)
	runner = newRunner(store, newFakeEdge(), issuer, &now)
	runner.Mode = RunModeTimer
	now = now.Add(24 * time.Hour)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 {
		t.Fatalf("restart lost NEEDS_ATTENTION pause, calls=%d", issuer.calls)
	}
}

func TestManualFirstIssueRetryRequiresExplicitMode(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	issuer := &fakeIssuer{now: &now, err: errors.New("temporary CA outage")}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("ACME failure was ignored")
	}
	now = now.Add(24 * time.Hour)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 {
		t.Fatalf("manual path retried without explicit confirmation mode, calls=%d", issuer.calls)
	}
	runner.Mode = RunModeManualFirstIssueRetry
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("explicit retry failure was ignored")
	}
	if issuer.calls != 2 {
		t.Fatalf("explicit confirmation did not cause exactly one retry, calls=%d", issuer.calls)
	}
}

func TestTimerNeverStartsFirstIssuance(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	runner.Mode = RunModeTimer
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 0 {
		t.Fatalf("timer started first issuance, calls=%d", issuer.calls)
	}
}

func TestManualRetryModeRejectsFreshTarget(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	runner.Mode = RunModeManualFirstIssueRetry
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("manual retry mode accepted a fresh target")
	}
	if issuer.calls != 0 {
		t.Fatalf("manual retry mode created a fresh order, calls=%d", issuer.calls)
	}
}

func TestActiveRenewalFailureKeepsAutomaticBackoffRetry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	edge.bindOnCreate = true
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	managed, err := store.Managed(ctx, "8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	now = time.Unix(managed.NextRenewalAt+1, 0)
	issuer.err = errors.New("temporary CA outage")
	runner.Mode = RunModeTimer
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("renewal failure was ignored")
	}
	if issuer.calls != 2 {
		t.Fatalf("first renewal attempt calls=%d", issuer.calls)
	}
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 2 {
		t.Fatalf("renewal backoff did not suppress retry, calls=%d", issuer.calls)
	}
	now = now.Add(16 * time.Minute)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("automatic renewal retry failure was ignored")
	}
	if issuer.calls != 3 {
		t.Fatalf("automatic renewal retry did not run, calls=%d", issuer.calls)
	}
	after, err := store.Managed(ctx, "8.8.8.8")
	if err != nil || after.CertID != managed.CertID || edge.createCalls != 1 || edge.updateCalls != 0 {
		t.Fatalf("managed=%+v err=%v create=%d update=%d", after, err, edge.createCalls, edge.updateCalls)
	}
}

func TestCertCreatedTimerOnlyChecksBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	issuer := &fakeIssuer{now: &now}
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, goedge.ErrCertificateNotBound) {
		t.Fatalf("initial binding result=%v", err)
	}
	runner.Mode = RunModeTimer
	for range 3 {
		if err := runner.RunOnce(ctx, "8.8.8.8"); !errors.Is(err, goedge.ErrCertificateNotBound) {
			t.Fatalf("timer binding result=%v", err)
		}
	}
	if issuer.calls != 1 || edge.createCalls != 1 || len(edge.certs) != 1 {
		t.Fatalf("issuer=%d create=%d certs=%d", issuer.calls, edge.createCalls, len(edge.certs))
	}
}

func TestLegacyFirstIssueErrorIsNormalizedAndSkipped(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	op := state.Operation{ID: "legacy-preview4", IPv4: "8.8.8.8", Kind: state.OperationIssue,
		Stage: state.StateNew, Marker: "legacy-marker", ServerID: 117, PolicyID: 113}
	if err := store.CreateOperation(ctx, op); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(ctx, op.ID, state.StateNew, state.StateChallengePresent, "awaiting-acme"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetErrorWithRetry(ctx, op.ID, state.StateChallengePresent, "transient", "ACME issuance failed",
		"retry-new-order", 2, now.Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	issuer := &fakeIssuer{now: &now}
	runner := newRunner(store, newFakeEdge(), issuer, &now)
	runner.Mode = RunModeTimer
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestOperation(ctx, "8.8.8.8")
	if err != nil || latest.RecoveryMarker != state.RecoveryNeedsAttention || latest.RetryCount != 2 || issuer.calls != 0 {
		t.Fatalf("operation=%+v issuer=%d err=%v", latest, issuer.calls, err)
	}
}

func newRunner(store *state.Store, edge *fakeEdge, issuer Issuer, now *time.Time) *Runner {
	return &Runner{State: store, Challenges: noOpChallenges{}, Edge: edge, Issuer: issuer,
		Rollbacks: edge.rollbacks, TLS: edge.tls,
		Schedule:         scheduler.Policy{RenewBefore: 72 * time.Hour, RetryMin: 15 * time.Minute, RetryMax: 6 * time.Hour, JitterMax: time.Minute},
		AccountReference: "account-ref", Now: func() time.Time { return *now }}
}

func openLifecycleState(t *testing.T, path string) *state.Store {
	t.Helper()
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func reopenLifecycleState(t *testing.T, path string) *state.Store {
	t.Helper()
	store := openLifecycleState(t, path)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func lifecycleConfig(input goedge.CertificateInput) goedge.CertificateConfig {
	return goedge.CertificateConfig{ID: input.ID, IsOn: input.IsOn, Name: input.Name, Description: input.Description,
		CertData: append([]byte(nil), input.CertData...), KeyData: append([]byte(nil), input.KeyData...),
		ServerName: input.ServerName, IsCA: input.IsCA, TimeBeginAt: input.TimeBeginAt, TimeEndAt: input.TimeEndAt,
		DNSNames: append([]string(nil), input.DNSNames...), CommonNames: append([]string(nil), input.CommonNames...)}
}
