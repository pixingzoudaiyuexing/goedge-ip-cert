package challenge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/ipv4"
)

type Provider struct {
	ctx         context.Context
	operationID string
	store       Store
	journal     Journal
	hook        CrashHook
	mu          sync.Mutex
}

func NewProvider(ctx context.Context, operationID string, store Store, journal Journal) (*Provider, error) {
	if ctx == nil || operationID == "" || store == nil || journal == nil {
		return nil, errors.New("challenge provider 参数不完整")
	}
	return &Provider{ctx: ctx, operationID: operationID, store: store, journal: journal}, nil
}

func (p *Provider) SetCrashHook(hook CrashHook) { p.hook = hook }

func (p *Provider) Present(domain, token, keyAuthorization string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, err := ipv4.ParsePublic(domain); err != nil {
		return fmt.Errorf("challenge domain: %w", err)
	}
	if token == "" || keyAuthorization == "" {
		return errors.New("challenge token/keyAuthorization 不能为空")
	}
	pending := Pending{OperationID: p.operationID, Domain: domain, Token: token, CreatedAt: time.Now().Unix()}
	if err := p.journal.BeginChallenge(p.ctx, pending); err != nil {
		return fmt.Errorf("记录 pending challenge: %w", err)
	}
	created, err := p.store.Create(p.ctx, Challenge{TaskID: 0, Domain: domain, Token: token, Key: keyAuthorization, CreatedAt: pending.CreatedAt})
	if err != nil {
		_ = p.journal.CompleteChallenge(p.ctx, pending)
		return err
	}
	if p.hook != nil {
		if err := p.hook("after-challenge-create"); err != nil {
			return err
		}
	}
	if err := p.journal.SetChallengeRowID(p.ctx, pending, created.ID); err != nil {
		cleanupErr := p.store.Delete(p.ctx, created)
		if cleanupErr == nil || errors.Is(cleanupErr, ErrNotFound) {
			_ = p.journal.CompleteChallenge(p.ctx, pending)
		}
		return fmt.Errorf("记录 challenge row ID: %w", err)
	}
	return nil
}

func (p *Provider) CleanUp(domain, token, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	pending, err := p.journal.PendingChallenge(p.ctx, p.operationID, domain, token)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("读取 pending challenge: %w", err)
	}
	item, err := resolveOwned(p.ctx, p.store, pending)
	if err != nil {
		return err
	}
	if err := p.store.Delete(p.ctx, item); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	return p.journal.CompleteChallenge(p.ctx, pending)
}

func Recover(ctx context.Context, store Store, journal Journal) error {
	items, err := journal.ListPendingChallenges(ctx)
	if err != nil {
		return err
	}
	for _, pending := range items {
		item, err := resolveOwned(ctx, store, pending)
		if errors.Is(err, ErrNotFound) {
			if err := journal.CompleteChallenge(ctx, pending); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if err := store.Delete(ctx, item); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := journal.CompleteChallenge(ctx, pending); err != nil {
			return err
		}
	}
	return nil
}

func resolveOwned(ctx context.Context, store Store, pending Pending) (Challenge, error) {
	if pending.RowID > 0 {
		return Challenge{ID: pending.RowID, TaskID: 0, Domain: pending.Domain, Token: pending.Token, CreatedAt: pending.CreatedAt}, nil
	}
	rows, err := store.FindOwned(ctx, pending.Domain, pending.Token, pending.CreatedAt)
	if err != nil {
		return Challenge{}, err
	}
	if len(rows) == 0 {
		return Challenge{}, ErrNotFound
	}
	if len(rows) != 1 {
		return Challenge{}, fmt.Errorf("%w: pending challenge 匹配 %d 行", ErrAmbiguous, len(rows))
	}
	return rows[0], nil
}
