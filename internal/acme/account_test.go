package acme

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAccountStoreCreatesPrivateReusableAccount(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "account")
	store, err := NewAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.LoadOrCreate("ops@example.com", "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatal(err)
	}
	firstRef, err := store.Reference(first)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.LoadOrCreate("ops@example.com", "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		t.Fatal(err)
	}
	secondRef, _ := store.Reference(second)
	if firstRef != secondRef {
		t.Fatalf("account identity changed: %q != %q", firstRef, secondRef)
	}
	for _, name := range []string{"account.key", "account.json"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode=%v err=%v", name, info.Mode().Perm(), err)
		}
	}
}

func TestAccountStoreRejectsDirectoryOrEmailDrift(t *testing.T) {
	store, _ := NewAccountStore(t.TempDir())
	if _, err := store.LoadOrCreate("ops@example.com", "https://acme-v02.api.letsencrypt.org/directory"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate("other@example.com", "https://acme-v02.api.letsencrypt.org/directory"); err == nil {
		t.Fatal("account metadata drift accepted")
	}
}

func TestAccountStoreRejectsInsecureExistingKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewAccountStore(dir)
	if _, err := store.LoadOrCreate("ops@example.com", "https://acme-v02.api.letsencrypt.org/directory"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "account.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadOrCreate("ops@example.com", "https://acme-v02.api.letsencrypt.org/directory"); err == nil {
		t.Fatal("insecure account key permissions accepted")
	}
}
