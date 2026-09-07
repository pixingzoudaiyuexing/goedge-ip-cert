//go:build integration

package bootstrap

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

func TestInitializeDatabaseMySQL57(t *testing.T) {
	adminDSN := os.Getenv("GOEDGE_TEST_MYSQL_DSN")
	if adminDSN == "" {
		t.Skip("GOEDGE_TEST_MYSQL_DSN not set")
	}
	if !strings.Contains(adminDSN, "/stage2_test?") {
		t.Fatal("integration test DSN must target stage2_test")
	}
	parsed, err := mysql.ParseDSN(adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec("DROP USER 'goedge_ip_cert'@'127.0.0.1'")
	t.Cleanup(func() { _, _ = db.Exec("DROP USER 'goedge_ip_cert'@'127.0.0.1'") })
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS edgeACMEAuthentications (
		id bigint unsigned NOT NULL AUTO_INCREMENT, taskId bigint unsigned DEFAULT 0,
		domain varchar(255) DEFAULT NULL, token varchar(255) DEFAULT NULL,
		` + "`key`" + ` varchar(1024) DEFAULT NULL, createdAt bigint unsigned DEFAULT 0,
		PRIMARY KEY (id), KEY token (token)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "db.yaml")
	configData, err := yaml.Marshal(GoEdgeDBConfig{User: parsed.User, Password: parsed.Passwd, Host: parsed.Addr, Database: parsed.DBName})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	dsnPath := filepath.Join(tmp, "mysql-dsn")
	databasePath := filepath.Join(tmp, "database-name")
	if err := InitializeDatabase(context.Background(), configPath, dsnPath, databasePath); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dsnPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("dsn mode=%v", info.Mode().Perm())
		}
	}
	database, err := os.ReadFile(databasePath)
	if err != nil || strings.TrimSpace(string(database)) != "stage2_test" {
		t.Fatalf("database=%q err=%v", database, err)
	}
	if err := InitializeDatabase(context.Background(), configPath, dsnPath, databasePath); err != nil {
		t.Fatalf("idempotent verification failed: %v", err)
	}
}
