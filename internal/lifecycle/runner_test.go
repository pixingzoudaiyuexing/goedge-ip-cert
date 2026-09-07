package lifecycle

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	acmeclient "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/acme"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
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
	bindWrites       int
	lastCreateUserID int64
	lastFindUserID   int64
}

func newFakeEdge() *fakeEdge {
	return &fakeEdge{target: goedge.ServerTarget{ID: 117, UserID: 42, PolicyID: 113, HTTPSIsOn: true},
		policy: goedge.SSLPolicy{ID: 113, IsOn: true, MinVersion: "TLS 1.2", HTTP2Enabled: true},
		nextID: 200, certs: map[int64]goedge.CertificateConfig{}}
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
func (f *fakeEdge) BindCertificate(_ context.Context, policyID, certID int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ref := range f.policy.CertRefs {
		if ref.CertID == certID && ref.IsOn {
			return true, nil
		}
	}
	if f.policy.ID != policyID {
		return false, errors.New("wrong policy")
	}
	f.policy.CertRefs = append(f.policy.CertRefs, goedge.SSLCertRef{IsOn: true, CertID: certID})
	f.bindWrites++
	return false, nil
}

func TestIssueRecoversEveryPersistedCrashPointWithoutDuplicateCert(t *testing.T) {
	for _, crashPoint := range []string{"after-cert-issuance", "after-cert-create", "after-policy-bind"} {
		t.Run(crashPoint, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "state.db")
			now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
			edge := newFakeEdge()
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
			if edge.createCalls != 1 || edge.bindWrites != 1 || issuer.calls != 1 || edge.lastCreateUserID != 42 || edge.lastFindUserID != 42 {
				t.Fatalf("create=%d bind=%d issue=%d createUser=%d findUser=%d", edge.createCalls, edge.bindWrites,
					issuer.calls, edge.lastCreateUserID, edge.lastFindUserID)
			}
		})
	}
}

func TestRenewCrashRecoveryKeepsSameCertificateID(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
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
}

func TestDryRunPerformsNoMutation(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	store := openLifecycleState(t, filepath.Join(t.TempDir(), "state.db"))
	edge := newFakeEdge()
	runner := newRunner(store, edge, nil, &now)
	result, err := runner.DryRun(context.Background(), "8.8.8.8")
	if err != nil || result.ServerID != 117 || result.PolicyID != 113 || result.Managed || edge.createCalls != 0 || edge.updateCalls != 0 || edge.bindWrites != 0 {
		t.Fatalf("result=%+v err=%v mutations=%d/%d/%d", result, err, edge.createCalls, edge.updateCalls, edge.bindWrites)
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
	if edge.createCalls != 0 || edge.updateCalls != 0 || edge.bindWrites != 0 {
		t.Fatalf("invalid cert reached EdgeAPI: %d/%d/%d", edge.createCalls, edge.updateCalls, edge.bindWrites)
	}
}

type wrongIPIssuer struct{ now *time.Time }

func (i *wrongIPIssuer) Obtain(context.Context, string, string) (acmeclient.IssuedCertificate, error) {
	certPEM, keyPEM, err := testutil.Certificate(testutil.CertOptions{IP: "1.1.1.1", NotBefore: i.now.Add(-time.Minute), NotAfter: i.now.Add(160 * time.Hour)})
	return acmeclient.IssuedCertificate{Certificate: certPEM, PrivateKey: keyPEM}, err
}

func TestACMEFailureBackoffSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state.db")
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	edge := newFakeEdge()
	issuer := &fakeIssuer{now: &now, err: errors.New("temporary CA outage")}
	store := openLifecycleState(t, path)
	runner := newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("ACME failure was ignored")
	}
	if issuer.calls != 1 {
		t.Fatalf("issuer calls=%d", issuer.calls)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = reopenLifecycleState(t, path)
	runner = newRunner(store, edge, issuer, &now)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 1 {
		t.Fatalf("backoff did not suppress retry, calls=%d", issuer.calls)
	}
	now = now.Add(16 * time.Minute)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err == nil {
		t.Fatal("second ACME failure was ignored")
	}
	if issuer.calls != 2 {
		t.Fatalf("second retry did not run, calls=%d", issuer.calls)
	}
	retry, err := store.LatestRetry(ctx, "8.8.8.8")
	if err != nil || retry.Attempt != 2 || retry.NextAt != now.Add(30*time.Minute).Unix() {
		t.Fatalf("persisted retry=%+v err=%v, want attempt=2 next=%d", retry, err, now.Add(30*time.Minute).Unix())
	}
	now = now.Add(20 * time.Minute)
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 2 {
		t.Fatalf("persisted exponential backoff did not suppress retry, calls=%d", issuer.calls)
	}
	now = now.Add(11 * time.Minute)
	issuer.err = nil
	if err := runner.RunOnce(ctx, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	if issuer.calls != 3 {
		t.Fatalf("retry did not run after backoff, calls=%d", issuer.calls)
	}
}

func newRunner(store *state.Store, edge *fakeEdge, issuer Issuer, now *time.Time) *Runner {
	return &Runner{State: store, Challenges: noOpChallenges{}, Edge: edge, Issuer: issuer,
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
