//go:build integration

package challenge

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMySQLStoreV139Contract(t *testing.T) {
	dsn := os.Getenv("GOEDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("GOEDGE_TEST_MYSQL_DSN not set")
	}
	if !strings.Contains(dsn, "/stage2_test?") {
		t.Fatal("integration test DSN must target stage2_test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	createSchema(t, db, correctSchema)
	store, _ := NewMySQLStore(db, "stage2_test")
	if err := store.CheckSchema(ctx); err != nil {
		t.Fatal(err)
	}
	createdA, err := store.Create(ctx, Challenge{TaskID: 0, Domain: "8.8.8.8", Token: "token-a", Key: "key-a", CreatedAt: 100})
	if err != nil || createdA.ID <= 0 {
		t.Fatalf("create A=%+v err=%v", createdA, err)
	}
	createdB, err := store.Create(ctx, Challenge{TaskID: 0, Domain: "1.1.1.1", Token: "token-b", Key: "key-b", CreatedAt: 101})
	if err != nil {
		t.Fatal(err)
	}
	wrongSelector := createdA
	wrongSelector.Domain = "1.1.1.1"
	if err := store.Delete(ctx, wrongSelector); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong selector delete err=%v", err)
	}
	var retained int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM edgeACMEAuthentications WHERE id=?`, createdA.ID).Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("wrong selector removed row: count=%d err=%v", retained, err)
	}
	if err := store.Delete(ctx, createdA); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM edgeACMEAuthentications WHERE id=? AND token=?`, createdB.ID, "token-b").Scan(&count); err != nil || count != 1 {
		t.Fatalf("order B count=%d err=%v", count, err)
	}
	if err := store.Delete(ctx, createdB); err != nil {
		t.Fatal(err)
	}
}

func TestMySQLStoreSchemaGuardFailsClosed(t *testing.T) {
	dsn := os.Getenv("GOEDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("GOEDGE_TEST_MYSQL_DSN not set")
	}
	if !strings.Contains(dsn, "/stage2_test?") {
		t.Fatal("integration test DSN must target stage2_test")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	tests := []struct {
		name   string
		schema string
		dbName string
	}{
		{"missing table", "", "stage2_test"},
		{"unexpected column type", strings.Replace(correctSchema, "token varchar(255)", "token varchar(254)", 1), "stage2_test"},
		{"unexpected extra column", strings.Replace(correctSchema, "PRIMARY KEY", "`unknown` varchar(20), PRIMARY KEY", 1), "stage2_test"},
		{"missing token index", strings.Replace(correctSchema, ", KEY token (token)", "", 1), "stage2_test"},
		{"wrong table engine", strings.Replace(strings.Replace(correctSchema, "KEY token (token)", "KEY token (token(191))", 1), "ENGINE=InnoDB", "ENGINE=MyISAM", 1), "stage2_test"},
		{"wrong configured database", correctSchema, "edges"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			createSchema(t, db, test.schema)
			store, err := NewMySQLStore(db, test.dbName)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.CheckSchema(context.Background()); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("schema guard err=%v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := store.Create(ctx, Challenge{Domain: "8.8.8.8", Token: "token", Key: "key"}); !errors.Is(err, ErrSchemaMismatch) {
				t.Fatalf("write after failed guard err=%v", err)
			}
		})
	}
}

func TestMySQLStorePropagatesWriteErrors(t *testing.T) {
	dsn := os.Getenv("GOEDGE_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("GOEDGE_TEST_MYSQL_DSN not set")
	}
	if !strings.Contains(dsn, "/stage2_test?") {
		t.Fatal("integration test DSN must target stage2_test")
	}
	t.Run("create", func(t *testing.T) {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatal(err)
		}
		createSchema(t, db, correctSchema)
		store, _ := NewMySQLStore(db, "stage2_test")
		if err := store.CheckSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Create(context.Background(), Challenge{Domain: "8.8.8.8", Token: "token", Key: "key"}); err == nil {
			t.Fatal("closed DB create error was ignored")
		}
	})
	t.Run("delete", func(t *testing.T) {
		db, err := sql.Open("mysql", dsn)
		if err != nil {
			t.Fatal(err)
		}
		createSchema(t, db, correctSchema)
		store, _ := NewMySQLStore(db, "stage2_test")
		if err := store.CheckSchema(context.Background()); err != nil {
			t.Fatal(err)
		}
		created, err := store.Create(context.Background(), Challenge{Domain: "8.8.8.8", Token: "token", Key: "key"})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(context.Background(), created); err == nil {
			t.Fatal("closed DB delete error was ignored")
		}
	})
}

func createSchema(t *testing.T, db *sql.DB, schema string) {
	t.Helper()
	if _, err := db.Exec(`DROP TABLE IF EXISTS edgeACMEAuthentications`); err != nil {
		t.Fatal(err)
	}
	if schema != "" {
		if _, err := db.Exec(schema); err != nil {
			t.Fatal(err)
		}
	}
}

const correctSchema = `CREATE TABLE edgeACMEAuthentications (
  id bigint unsigned NOT NULL AUTO_INCREMENT,
  taskId bigint unsigned DEFAULT 0,
  domain varchar(255) DEFAULT NULL,
  token varchar(255) DEFAULT NULL,
  ` + "`key`" + ` varchar(1024) DEFAULT NULL,
  createdAt bigint unsigned DEFAULT 0,
  PRIMARY KEY (id), KEY token (token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`
