package challenge_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
)

type memoryChallengeStore struct {
	mu          sync.Mutex
	checked     bool
	nextID      int64
	rows        map[int64]challenge.Challenge
	createError error
	deleteError error
}

func newMemoryChallengeStore() *memoryChallengeStore {
	return &memoryChallengeStore{checked: true, nextID: 10, rows: map[int64]challenge.Challenge{}}
}

func (s *memoryChallengeStore) CheckSchema(context.Context) error { return nil }
func (s *memoryChallengeStore) Create(_ context.Context, item challenge.Challenge) (challenge.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.createError != nil {
		return challenge.Challenge{}, s.createError
	}
	s.nextID++
	item.ID = s.nextID
	s.rows[item.ID] = item
	return item, nil
}
func (s *memoryChallengeStore) Delete(_ context.Context, item challenge.Challenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteError != nil {
		return s.deleteError
	}
	stored, ok := s.rows[item.ID]
	if !ok {
		return challenge.ErrNotFound
	}
	if stored.TaskID != item.TaskID || stored.Domain != item.Domain || stored.Token != item.Token {
		return challenge.ErrNotFound
	}
	delete(s.rows, item.ID)
	return nil
}
func (s *memoryChallengeStore) FindOwned(_ context.Context, domain, token string, createdAt int64) ([]challenge.Challenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var result []challenge.Challenge
	for _, item := range s.rows {
		if item.TaskID == 0 && item.Domain == domain && item.Token == token && item.CreatedAt == createdAt {
			result = append(result, item)
		}
	}
	return result, nil
}

func TestProviderCleanupDoesNotDeleteConcurrentOrder(t *testing.T) {
	ctx := context.Background()
	journal := openState(t)
	store := newMemoryChallengeStore()
	opA := createChallengeOperation(t, journal, "op-a")
	opB := createChallengeOperation(t, journal, "op-b")
	providerA, _ := challenge.NewProvider(ctx, opA, store, journal)
	providerB, _ := challenge.NewProvider(ctx, opB, store, journal)
	if err := providerA.Present("8.8.8.8", "token-a", "key-a"); err != nil {
		t.Fatal(err)
	}
	if err := providerB.Present("1.1.1.1", "token-b", "key-b"); err != nil {
		t.Fatal(err)
	}
	if err := providerA.CleanUp("8.8.8.8", "token-a", "key-a"); err != nil {
		t.Fatal(err)
	}
	if err := providerA.CleanUp("8.8.8.8", "token-a", "key-a"); err != nil {
		t.Fatalf("duplicate cleanup is not idempotent: %v", err)
	}
	if len(store.rows) != 1 {
		t.Fatalf("rows=%d, want order B only", len(store.rows))
	}
	for _, row := range store.rows {
		if row.Token != "token-b" {
			t.Fatalf("wrong row survived: %+v", row)
		}
	}
}

func TestProviderPropagatesCreateAndDeleteErrors(t *testing.T) {
	ctx := context.Background()
	t.Run("create", func(t *testing.T) {
		journal := openState(t)
		store := newMemoryChallengeStore()
		store.createError = errors.New("db create failed")
		op := createChallengeOperation(t, journal, "op-create-error")
		provider, _ := challenge.NewProvider(ctx, op, store, journal)
		if err := provider.Present("8.8.8.8", "token", "key"); err == nil {
			t.Fatal("create error was swallowed")
		}
	})
	t.Run("delete", func(t *testing.T) {
		journal := openState(t)
		store := newMemoryChallengeStore()
		op := createChallengeOperation(t, journal, "op-delete-error")
		provider, _ := challenge.NewProvider(ctx, op, store, journal)
		if err := provider.Present("8.8.8.8", "token", "key"); err != nil {
			t.Fatal(err)
		}
		store.deleteError = errors.New("db delete failed")
		if err := provider.CleanUp("8.8.8.8", "token", "key"); err == nil {
			t.Fatal("delete error was swallowed")
		}
	})
}

func TestRecoverChallengeAfterCrashBeforeRowIDJournal(t *testing.T) {
	ctx := context.Background()
	journal := openState(t)
	store := newMemoryChallengeStore()
	op := createChallengeOperation(t, journal, "op-crash")
	provider, _ := challenge.NewProvider(ctx, op, store, journal)
	provider.SetCrashHook(func(point string) error {
		if point == "after-challenge-create" {
			return errors.New("crash")
		}
		return nil
	})
	if err := provider.Present("8.8.8.8", "token-crash", "key-secret"); err == nil {
		t.Fatal("crash hook did not stop Present")
	}
	pending, err := journal.PendingChallenge(ctx, op, "8.8.8.8", "token-crash")
	if err != nil || pending.RowID != 0 || len(store.rows) != 1 {
		t.Fatalf("pending=%+v err=%v rows=%d", pending, err, len(store.rows))
	}
	if err := challenge.Recover(ctx, store, journal); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 0 {
		t.Fatalf("orphan rows=%d", len(store.rows))
	}
}

func openState(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func createChallengeOperation(t *testing.T, store *state.Store, id string) string {
	t.Helper()
	ip := "8.8.8.8"
	if id == "op-b" {
		ip = "1.1.1.1"
	}
	err := store.CreateOperation(context.Background(), state.Operation{ID: id, IPv4: ip, Kind: state.OperationIssue, Stage: state.StateNew, Marker: id})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Transition(context.Background(), id, state.StateNew, state.StateChallengePresent, "test"); err != nil {
		t.Fatal(err)
	}
	return id
}

var _ = time.Second
