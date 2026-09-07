package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
)

func (s *Store) BeginChallenge(ctx context.Context, pending challenge.Pending) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM operations WHERE id=? AND stage=?`, pending.OperationID, StateChallengePresent).Scan(&exists); err != nil {
		return err
	}
	if exists != 1 {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO pending_challenges(operation_id, domain, token, row_id, created_at)
		VALUES (?, ?, ?, 0, ?)`, pending.OperationID, pending.Domain, pending.Token, pending.CreatedAt)
	if err != nil {
		return fmt.Errorf("写入 pending challenge: %w", err)
	}
	return tx.Commit()
}

func (s *Store) SetChallengeRowID(ctx context.Context, pending challenge.Pending, rowID int64) error {
	if rowID <= 0 {
		return errors.New("challenge row ID 必须大于 0")
	}
	result, err := s.db.ExecContext(ctx, `UPDATE pending_challenges SET row_id=?
		WHERE operation_id=? AND domain=? AND token=? AND row_id=0`, rowID, pending.OperationID, pending.Domain, pending.Token)
	if err != nil {
		return err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return ErrConflict
	}
	return nil
}

func (s *Store) PendingChallenge(ctx context.Context, operationID, domain, token string) (challenge.Pending, error) {
	var item challenge.Pending
	err := s.db.QueryRowContext(ctx, `SELECT operation_id, domain, token, row_id, created_at
		FROM pending_challenges WHERE operation_id=? AND domain=? AND token=?`, operationID, domain, token).
		Scan(&item.OperationID, &item.Domain, &item.Token, &item.RowID, &item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return challenge.Pending{}, challenge.ErrNotFound
	}
	return item, err
}

func (s *Store) ListPendingChallenges(ctx context.Context) ([]challenge.Pending, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT operation_id, domain, token, row_id, created_at
		FROM pending_challenges ORDER BY created_at, operation_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []challenge.Pending
	for rows.Next() {
		var item challenge.Pending
		if err := rows.Scan(&item.OperationID, &item.Domain, &item.Token, &item.RowID, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CompleteChallenge(ctx context.Context, pending challenge.Pending) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM pending_challenges
		WHERE operation_id=? AND domain=? AND token=?`, pending.OperationID, pending.Domain, pending.Token)
	return err
}
