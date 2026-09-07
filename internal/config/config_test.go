package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `version: 1
target:
  ipv4: 8.8.8.8
goedge:
  endpoint: http://127.0.0.1:8002
  identity_type: admin
  access_key_id:
    env: TEST_ACCESS_KEY_ID
  access_key:
    env: TEST_ACCESS_KEY
database:
  name: edges
  dsn:
    env: TEST_DB_DSN
acme:
  directory_url: https://acme-v02.api.letsencrypt.org/directory
  email: ops@example.com
  account_dir: /var/lib/goedge-ip-cert/account
state:
  path: /var/lib/goedge-ip-cert/state.db
schedule:
  renew_before: 72h
  retry_min: 15m
  retry_max: 6h
  jitter_max: 10m
`

func TestLoadValidConfigAndDurations(t *testing.T) {
	cfg, err := loadText(t, validConfig)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Schedule.RenewBefore.Value() != 72*time.Hour || cfg.GoEdge.RequestTimeout.Value() != 15*time.Second {
		t.Fatalf("durations=%s/%s", cfg.Schedule.RenewBefore.Value(), cfg.GoEdge.RequestTimeout.Value())
	}
}

func TestLoadRejectsUnknownFieldAndPublicEndpoint(t *testing.T) {
	if _, err := loadText(t, validConfig+"unknown: true\n"); err == nil {
		t.Fatal("unknown field accepted")
	}
	public := strings.Replace(validConfig, "http://127.0.0.1:8002", "http://203.0.113.10:8002", 1)
	if _, err := loadText(t, public); err == nil {
		t.Fatal("public EdgeAPI endpoint accepted")
	}
	userinfo := strings.Replace(validConfig, "http://127.0.0.1:8002", "http://user:secret@127.0.0.1:8002", 1)
	if _, err := loadText(t, userinfo); err == nil {
		t.Fatal("userinfo EdgeAPI endpoint accepted")
	}
	relative := strings.Replace(validConfig, "/var/lib/goedge-ip-cert/state.db", "state.db", 1)
	if _, err := loadText(t, relative); err == nil {
		t.Fatal("relative state path accepted")
	}
}

func loadText(t *testing.T, value string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}
