package bootstrap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadGoEdgeDBConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.yaml")
	if err := os.WriteFile(path, []byte("user: root\npassword: secret\nhost: 127.0.0.1:3306\ndatabase: edges\nboolFields: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadGoEdgeDBConfig(path)
	if err != nil || cfg.Database != "edges" || cfg.Host != "127.0.0.1:3306" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

func TestLoadGoEdgeDBConfigRejectsRemoteAndUnsafeDatabase(t *testing.T) {
	for _, data := range []string{
		"user: root\npassword: secret\nhost: 192.0.2.1:3306\ndatabase: edges\n",
		"user: root\npassword: secret\nhost: 127.0.0.1:3306\ndatabase: 'edges`; DROP DATABASE edges'\n",
	} {
		path := filepath.Join(t.TempDir(), "db.yaml")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadGoEdgeDBConfig(path); err == nil {
			t.Fatal("unsafe DB config accepted")
		}
	}
}

func TestLeastPrivilegeSQLIsTableScoped(t *testing.T) {
	create, grant, err := LeastPrivilegeSQL("edges", "Abc_123-safe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(create, "CREATE USER 'goedge_ip_cert'@'127.0.0.1'") {
		t.Fatalf("create=%s", create)
	}
	want := "GRANT SELECT, INSERT, DELETE ON `edges`.`edgeACMEAuthentications` TO 'goedge_ip_cert'@'127.0.0.1'"
	if grant != want || strings.Contains(strings.ToUpper(grant), "GRANT ALL") {
		t.Fatalf("grant=%s", grant)
	}
}

func TestExactLeastPrivilegeGrantsRejectsExtras(t *testing.T) {
	want := "GRANT SELECT, INSERT, DELETE ON `edges`.`edgeACMEAuthentications` TO 'goedge_ip_cert'@'127.0.0.1'"
	usage := "GRANT USAGE ON *.* TO 'goedge_ip_cert'@'127.0.0.1'"
	if !ExactLeastPrivilegeGrants([]string{usage, want}, "edges") {
		t.Fatal("exact grants rejected")
	}
	if ExactLeastPrivilegeGrants([]string{usage, want, "GRANT SELECT ON `edges`.* TO 'goedge_ip_cert'@'127.0.0.1'"}, "edges") {
		t.Fatal("extra grants accepted")
	}
	if !ExactLeastPrivilegeGrants([]string{usage + " IDENTIFIED BY PASSWORD '*0123456789ABCDEF'", want}, "edges") {
		t.Fatal("MySQL 5.7 password suffix rejected")
	}
}
