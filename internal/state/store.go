package state

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

const schemaVersion = 1

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state path 不能为空")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 state 目录: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("设置 state 目录权限: %w", err)
		}
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("state path 不是普通文件")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("创建 state 文件: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("打开 state SQLite: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.init(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			db.Close()
			return nil, fmt.Errorf("设置 state 文件权限: %w", err)
		}
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) init(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS managed_certs (
			ipv4 TEXT PRIMARY KEY,
			server_id INTEGER NOT NULL,
			policy_id INTEGER NOT NULL,
			cert_id INTEGER NOT NULL,
			account_reference TEXT NOT NULL,
			state TEXT NOT NULL,
			last_success_at INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			next_renewal_at INTEGER NOT NULL,
			last_error_category TEXT NOT NULL DEFAULT '',
			last_error TEXT NOT NULL DEFAULT '',
			recovery_marker TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS operations (
			id TEXT PRIMARY KEY,
			ipv4 TEXT NOT NULL,
			kind TEXT NOT NULL,
			stage TEXT NOT NULL,
			marker TEXT NOT NULL UNIQUE,
			server_id INTEGER NOT NULL DEFAULT 0,
			policy_id INTEGER NOT NULL DEFAULT 0,
			cert_id INTEGER NOT NULL DEFAULT 0,
			user_id INTEGER NOT NULL DEFAULT 0,
			cert_pem BLOB,
			key_pem BLOB,
			cert_fingerprint TEXT NOT NULL DEFAULT '',
			expires_at INTEGER NOT NULL DEFAULT 0,
			error_category TEXT NOT NULL DEFAULT '',
			error_message TEXT NOT NULL DEFAULT '',
			recovery_marker TEXT NOT NULL DEFAULT '',
			retry_count INTEGER NOT NULL DEFAULT 0,
			next_retry_at INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS operations_ipv4_stage ON operations(ipv4, stage)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS operations_one_inflight ON operations(ipv4)
			WHERE stage NOT IN ('ACTIVE', 'ERROR')`,
		`CREATE TABLE IF NOT EXISTS pending_challenges (
			operation_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			token TEXT NOT NULL,
			row_id INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			PRIMARY KEY(operation_id, domain, token),
			FOREIGN KEY(operation_id) REFERENCES operations(id) ON DELETE CASCADE
		)`,
	}
	for _, statement := range statements {
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("初始化 state schema: %w", err)
		}
	}
	var version int
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_meta LIMIT 1`).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		_, err = s.db.ExecContext(ctx, `INSERT INTO schema_meta(version) VALUES (?)`, schemaVersion)
		return err
	}
	if err != nil {
		return fmt.Errorf("读取 state schema 版本: %w", err)
	}
	if version != schemaVersion {
		return fmt.Errorf("不支持的 state schema 版本 %d", version)
	}
	return nil
}

func NewOperationID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func (s *Store) CreateOperation(ctx context.Context, operation Operation) error {
	if operation.ID == "" || operation.IPv4 == "" || operation.Marker == "" {
		return errors.New("operation id/ipv4/marker 不能为空")
	}
	if operation.Kind != OperationIssue && operation.Kind != OperationRenew {
		return errors.New("operation kind 无效")
	}
	if operation.Stage == "" {
		operation.Stage = StateNew
	}
	now := time.Now().UnixNano()
	_, err := s.db.ExecContext(ctx, `INSERT INTO operations
		(id, ipv4, kind, stage, marker, server_id, policy_id, cert_id, user_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, operation.ID, operation.IPv4, operation.Kind, operation.Stage,
		operation.Marker, operation.ServerID, operation.PolicyID, operation.CertID, operation.UserID, now, now)
	if err != nil {
		return fmt.Errorf("创建 lifecycle operation: %w", err)
	}
	return nil
}

func (s *Store) Operation(ctx context.Context, id string) (Operation, error) {
	var op Operation
	var stage string
	err := s.db.QueryRowContext(ctx, `SELECT id, ipv4, kind, stage, marker, server_id, policy_id, cert_id, user_id,
		cert_pem, key_pem, cert_fingerprint, expires_at, error_category, error_message, recovery_marker,
		retry_count, next_retry_at, created_at, updated_at FROM operations WHERE id=?`, id).Scan(&op.ID, &op.IPv4, &op.Kind, &stage,
		&op.Marker, &op.ServerID, &op.PolicyID, &op.CertID, &op.UserID, &op.CertPEM, &op.KeyPEM, &op.CertFingerprint,
		&op.ExpiresAt, &op.ErrorCategory, &op.ErrorMessage, &op.RecoveryMarker, &op.RetryCount, &op.NextRetryAt,
		&op.CreatedAt, &op.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Operation{}, ErrNotFound
	}
	if err != nil {
		return Operation{}, err
	}
	op.Stage = LifecycleState(stage)
	return op, nil
}

func (s *Store) ListIncompleteOperations(ctx context.Context) ([]Operation, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM operations WHERE stage NOT IN (?, ?) ORDER BY created_at`, StateActive, StateError)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]Operation, 0, len(ids))
	for _, id := range ids {
		op, err := s.Operation(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, nil
}

func (s *Store) Transition(ctx context.Context, id string, expected, next LifecycleState, recoveryMarker string) error {
	return s.updateExpected(ctx, id, expected, next, `recovery_marker=?`, recoveryMarker)
}

func (s *Store) SaveIssued(ctx context.Context, id string, expected LifecycleState, certPEM, keyPEM []byte, fingerprint string, expiresAt int64) error {
	if len(certPEM) == 0 || len(keyPEM) == 0 || fingerprint == "" || expiresAt <= 0 {
		return errors.New("已签发证书状态不完整")
	}
	return s.updateExpected(ctx, id, expected, StateCertIssued,
		`cert_pem=?, key_pem=?, cert_fingerprint=?, expires_at=?, recovery_marker=''`, certPEM, keyPEM, fingerprint, expiresAt)
}

func (s *Store) SetCertCreated(ctx context.Context, id string, expected LifecycleState, certID int64) error {
	if certID <= 0 {
		return errors.New("certID 必须大于 0")
	}
	return s.updateExpected(ctx, id, expected, StateCertCreated, `cert_id=?, recovery_marker=''`, certID)
}

func (s *Store) SetPolicyBound(ctx context.Context, id string, expected LifecycleState) error {
	return s.updateExpected(ctx, id, expected, StatePolicyBound, `recovery_marker=''`)
}

func (s *Store) SetError(ctx context.Context, id string, expected LifecycleState, category, message, marker string) error {
	return s.updateExpected(ctx, id, expected, StateError,
		`error_category=?, error_message=?, recovery_marker=?`, category, message, marker)
}

func (s *Store) SetErrorWithRetry(ctx context.Context, id string, expected LifecycleState, category, message, marker string, retryCount int, nextRetryAt int64) error {
	return s.updateExpected(ctx, id, expected, StateError,
		`error_category=?, error_message=?, recovery_marker=?, retry_count=?, next_retry_at=?`,
		category, message, marker, retryCount, nextRetryAt)
}

func (s *Store) RecordOperationFailure(ctx context.Context, id string, expected LifecycleState, category, message, marker string) error {
	return s.updateExpected(ctx, id, expected, expected,
		`error_category=?, error_message=?, recovery_marker=?`, category, message, marker)
}

func (s *Store) LatestRetry(ctx context.Context, ip string) (RetryInfo, error) {
	var stage string
	var info RetryInfo
	err := s.db.QueryRowContext(ctx, `SELECT stage, retry_count, next_retry_at FROM operations
		WHERE ipv4=? ORDER BY updated_at DESC LIMIT 1`, ip).Scan(&stage, &info.Attempt, &info.NextAt)
	if errors.Is(err, sql.ErrNoRows) {
		return RetryInfo{}, nil
	}
	if err != nil {
		return RetryInfo{}, err
	}
	if LifecycleState(stage) != StateError {
		return RetryInfo{}, nil
	}
	return info, nil
}

func (s *Store) SetActive(ctx context.Context, id string, expected LifecycleState, accountReference string, nextRenewalAt int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var op Operation
	var stage string
	err = tx.QueryRowContext(ctx, `SELECT ipv4, server_id, policy_id, cert_id, expires_at, stage FROM operations WHERE id=?`, id).
		Scan(&op.IPv4, &op.ServerID, &op.PolicyID, &op.CertID, &op.ExpiresAt, &stage)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if LifecycleState(stage) != expected {
		return ErrConflict
	}
	now := time.Now().Unix()
	_, err = tx.ExecContext(ctx, `INSERT INTO managed_certs
		(ipv4, server_id, policy_id, cert_id, account_reference, state, last_success_at, expires_at, next_renewal_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ipv4) DO UPDATE SET server_id=excluded.server_id, policy_id=excluded.policy_id,
		cert_id=excluded.cert_id, account_reference=excluded.account_reference, state=excluded.state,
		last_success_at=excluded.last_success_at, expires_at=excluded.expires_at,
		next_renewal_at=excluded.next_renewal_at, last_error_category='', last_error='', recovery_marker=''`,
		op.IPv4, op.ServerID, op.PolicyID, op.CertID, accountReference, StateActive, now, op.ExpiresAt, nextRenewalAt)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE operations SET stage=?, cert_pem=NULL, key_pem=NULL,
		error_category='', error_message='', recovery_marker='', updated_at=? WHERE id=? AND stage=?`,
		StateActive, time.Now().UnixNano(), id, expected)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrConflict
	}
	return tx.Commit()
}

func (s *Store) Managed(ctx context.Context, ip string) (ManagedCert, error) {
	var item ManagedCert
	var stage string
	err := s.db.QueryRowContext(ctx, `SELECT ipv4, server_id, policy_id, cert_id, account_reference, state,
		last_success_at, expires_at, next_renewal_at, last_error_category, last_error, recovery_marker
		FROM managed_certs WHERE ipv4=?`, ip).Scan(&item.IPv4, &item.ServerID, &item.PolicyID, &item.CertID,
		&item.AccountReference, &stage, &item.LastSuccessAt, &item.ExpiresAt, &item.NextRenewalAt,
		&item.LastErrorCategory, &item.LastError, &item.RecoveryMarker)
	if errors.Is(err, sql.ErrNoRows) {
		return ManagedCert{}, ErrNotFound
	}
	if err != nil {
		return ManagedCert{}, err
	}
	item.State = LifecycleState(stage)
	return item, nil
}

func (s *Store) ListManaged(ctx context.Context) ([]ManagedCert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT ipv4 FROM managed_certs ORDER BY ipv4`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]ManagedCert, 0, len(ips))
	for _, ip := range ips {
		item, err := s.Managed(ctx, ip)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Store) RecordManagedError(ctx context.Context, ip, category, message, marker string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE managed_certs SET state=?, last_error_category=?, last_error=?, recovery_marker=? WHERE ipv4=?`,
		StateError, category, message, marker, ip)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) BeginRenewal(ctx context.Context, operation Operation) error {
	operation.Kind = OperationRenew
	operation.Stage = StateRenewing
	return s.CreateOperation(ctx, operation)
}

func (s *Store) updateExpected(ctx context.Context, id string, expected, next LifecycleState, fields string, args ...any) error {
	args = append([]any{next}, args...)
	args = append(args, time.Now().UnixNano(), id, expected)
	result, err := s.db.ExecContext(ctx, `UPDATE operations SET stage=?, `+fields+`, updated_at=? WHERE id=? AND stage=?`, args...)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrConflict
	}
	return nil
}
