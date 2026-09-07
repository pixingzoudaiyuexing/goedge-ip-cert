package rollback

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
)

const testOperationID = "0123456789abcdef0123456789abcdef"

func TestSnapshotPermissionsLoadAndCleanup(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rollback")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := testSnapshot()
	if err := store.Save(snapshot); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode=%v err=%v", dirInfo.Mode().Perm(), err)
	}
	path := filepath.Join(dir, testOperationID+".json")
	fileInfo, err := os.Stat(path)
	if err != nil || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%v err=%v", fileInfo.Mode().Perm(), err)
	}
	loaded, err := store.Load(testOperationID)
	if err != nil || loaded.Old.ID != 77 || string(loaded.Old.KeyData) != "old-private-key" {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	items, err := store.List()
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%d err=%v", len(items), err)
	}
	if err := store.Delete(testOperationID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("rollback snapshot not deleted: %v", err)
	}
	if err := store.Delete(testOperationID); err != nil {
		t.Fatalf("cleanup is not idempotent: %v", err)
	}
}

func TestLoadRejectsInsecureSnapshotPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rollback")
	store, _ := NewStore(dir)
	if err := store.Save(testSnapshot()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, testOperationID+".json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(testOperationID); err == nil {
		t.Fatal("insecure rollback snapshot accepted")
	}
}

func TestNewStoreRejectsSymlinkDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "rollback")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(link); err == nil {
		t.Fatal("symlink rollback directory accepted")
	}
}

func TestNewStoreRemovesOnlyStaleRollbackTempFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rollback")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".rollback-stale")
	if err := os.WriteFile(stale, []byte("old-private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewStore(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale temp file not removed: %v", err)
	}
}

func testSnapshot() Snapshot {
	old := goedge.CertificateInput{ID: 77, IsOn: true, Name: "old", CertData: []byte("old-cert"),
		KeyData: []byte("old-private-key"), TimeBeginAt: 1, TimeEndAt: 2, DNSNames: []string{"8.8.8.8"}}
	return NewSnapshot(testOperationID, "8.8.8.8", "new-fingerprint", "old-fingerprint", old)
}
