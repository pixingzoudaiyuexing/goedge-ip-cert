package challenge

import (
	"context"
	"errors"
)

var (
	ErrSchemaMismatch = errors.New("challenge schema mismatch")
	ErrNotFound       = errors.New("challenge row not found")
	ErrAmbiguous      = errors.New("challenge ownership is ambiguous")
)

type Challenge struct {
	ID        int64
	TaskID    int64
	Domain    string
	Token     string
	Key       string
	CreatedAt int64
}

type Pending struct {
	OperationID string
	Domain      string
	Token       string
	RowID       int64
	CreatedAt   int64
}

type Store interface {
	CheckSchema(context.Context) error
	Create(context.Context, Challenge) (Challenge, error)
	Delete(context.Context, Challenge) error
	FindOwned(context.Context, string, string, int64) ([]Challenge, error)
}

type Journal interface {
	BeginChallenge(context.Context, Pending) error
	SetChallengeRowID(context.Context, Pending, int64) error
	PendingChallenge(context.Context, string, string, string) (Pending, error)
	ListPendingChallenges(context.Context) ([]Pending, error)
	CompleteChallenge(context.Context, Pending) error
}

type CrashHook func(point string) error
