package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretRefRequiresPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("sensitive-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := (SecretRef{File: path}).Load(); err == nil {
		t.Fatal("world-readable secret file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := (SecretRef{File: path}).Load()
	if err != nil || value != "sensitive-value" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestRedactorRemovesKnownSecretClasses(t *testing.T) {
	privateKey := "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----"
	known := "known-secret-value"
	input := "Authorization: Bearer bearer-secret\n\x1b[31m X-Edge-Access-Token=raw-token; user:db-password@tcp " + privateKey + " " + known + "\u202e"
	output := NewRedactor(known).Redact(input)
	for _, forbidden := range []string{"bearer-secret", "raw-token", "db-password", "abc123", known, "\n", "\x1b", "\u202e"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("redacted output contains %q: %s", forbidden, output)
		}
	}
}
