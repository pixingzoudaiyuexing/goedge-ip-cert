package lock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquirePreventsConcurrentProcessAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.lock")
	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Acquire(path); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second lock err=%v", err)
	}

	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(t.TempDir(), "symlink.lock")
	if err := os.Symlink(target, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(symlink); err == nil {
		t.Fatal("symlink lock file accepted")
	}
}
