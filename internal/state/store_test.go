package state

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreTransitionIsCrashSafeAndCASProtected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{ID: "operation-1", IPv4: "8.8.8.8", Kind: OperationIssue, Stage: StateNew, Marker: "marker-1"}
	if err := store.CreateOperation(context.Background(), op); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(context.Background(), op.ID, StateNew, StateChallengePresent, "present"); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(context.Background(), op.ID, StateNew, StateCertIssued, "wrong"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale transition err=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.Operation(context.Background(), op.ID)
	if err != nil || got.Stage != StateChallengePresent || got.RecoveryMarker != "present" {
		t.Fatalf("operation=%+v err=%v", got, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state mode=%v err=%v", info.Mode().Perm(), err)
	}
}

func TestStoreAllowsOnlyOneIncompleteOperationPerIPv4(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.CreateOperation(ctx, Operation{ID: "first", IPv4: "8.8.8.8", Kind: OperationIssue, Marker: "first"}); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOperation(ctx, Operation{ID: "second", IPv4: "8.8.8.8", Kind: OperationIssue, Marker: "second"}); err == nil {
		t.Fatal("second in-flight operation was accepted")
	}
	if err := store.SetError(ctx, "first", StateNew, "transient", "failed", "retry"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateOperation(ctx, Operation{ID: "second", IPv4: "8.8.8.8", Kind: OperationIssue, Marker: "second"}); err != nil {
		t.Fatalf("new operation after terminal error rejected: %v", err)
	}
}
