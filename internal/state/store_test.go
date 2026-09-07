package state

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSQLiteNeverStoresCertificatePrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.CreateOperation(ctx, Operation{ID: "private-key-check", IPv4: "8.8.8.8", Kind: OperationIssue, Marker: "marker"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(ctx, "private-key-check", StateNew, StateChallengePresent, "test"); err != nil {
		t.Fatal(err)
	}
	privateKey := []byte("-----BEGIN PRIVATE KEY-----\nstage2-1-private-key-probe\n-----END PRIVATE KEY-----")
	if err := store.SaveIssued(ctx, "private-key-check", StateChallengePresent, "fingerprint", 123); err != nil {
		t.Fatal(err)
	}
	var privateKeyColumn int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pragma_table_info('operations') WHERE name='key_pem'`).Scan(&privateKeyColumn); err != nil {
		t.Fatal(err)
	}
	if privateKeyColumn != 0 {
		t.Fatal("operations schema still contains key_pem")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, privateKey) || bytes.Contains(data, []byte("stage2-1-private-key-probe")) {
			t.Fatalf("private key persisted in %s", candidate)
		}
	}
}

func TestOpenMigratesV1AndScrubsLegacyPrivateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path))
	if err != nil {
		t.Fatal(err)
	}
	legacyKey := "-----BEGIN PRIVATE KEY-----\nstage2-1-legacy-private-key\n-----END PRIVATE KEY-----"
	for _, statement := range []string{
		`PRAGMA secure_delete=OFF`,
		`CREATE TABLE schema_meta (version INTEGER NOT NULL)`,
		`INSERT INTO schema_meta(version) VALUES (1)`,
		`CREATE TABLE operations (
			id TEXT PRIMARY KEY, ipv4 TEXT NOT NULL, kind TEXT NOT NULL, stage TEXT NOT NULL,
			marker TEXT NOT NULL UNIQUE, server_id INTEGER NOT NULL DEFAULT 0,
			policy_id INTEGER NOT NULL DEFAULT 0, cert_id INTEGER NOT NULL DEFAULT 0,
			user_id INTEGER NOT NULL DEFAULT 0, cert_pem BLOB, key_pem BLOB,
			cert_fingerprint TEXT NOT NULL DEFAULT '', expires_at INTEGER NOT NULL DEFAULT 0,
			error_category TEXT NOT NULL DEFAULT '', error_message TEXT NOT NULL DEFAULT '',
			recovery_marker TEXT NOT NULL DEFAULT '', retry_count INTEGER NOT NULL DEFAULT 0,
			next_retry_at INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
		)`,
		`INSERT INTO operations(id, ipv4, kind, stage, marker, cert_pem, key_pem, created_at, updated_at)
		 VALUES ('legacy', '8.8.8.8', 'issue', 'ERROR', 'legacy-marker', 'certificate', '` + legacyKey + `', 1, 1)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var version, pemColumns int
	if err := store.db.QueryRow(`SELECT version FROM schema_meta`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('operations') WHERE name IN ('cert_pem','key_pem')`).Scan(&pemColumns); err != nil {
		t.Fatal(err)
	}
	if version != 2 || pemColumns != 0 {
		t.Fatalf("version=%d pemColumns=%d", version, pemColumns)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte("stage2-1-legacy-private-key")) {
			t.Fatalf("legacy private key survived migration in %s", candidate)
		}
	}
}

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
