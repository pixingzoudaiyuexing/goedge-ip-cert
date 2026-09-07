package rollback

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
)

const snapshotVersion = 1

var operationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type Snapshot struct {
	Version        int                     `json:"version"`
	OperationID    string                  `json:"operationId"`
	IPv4           string                  `json:"ipv4"`
	CertID         int64                   `json:"certId"`
	NewFingerprint string                  `json:"newFingerprint"`
	OldFingerprint string                  `json:"oldFingerprint"`
	Old            goedge.CertificateInput `json:"old"`
}

type Store struct {
	dir string
}

func NewStore(dir string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, errors.New("rollback 目录必须是绝对路径")
	}
	if info, err := os.Lstat(dir); err == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("rollback 路径必须是真实目录，不能是 symlink")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 rollback 目录: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("设置 rollback 目录权限: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	removedTemp := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".rollback-") {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return nil, fmt.Errorf("清理遗留 rollback 临时文件: %w", err)
			}
			removedTemp = true
		}
	}
	if removedTemp {
		if err := syncDir(dir); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Save(snapshot Snapshot) error {
	if err := validate(snapshot); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".rollback-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path(snapshot.OperationID)); err != nil {
		return err
	}
	return syncDir(s.dir)
}

func (s *Store) Load(operationID string) (Snapshot, error) {
	if !operationIDPattern.MatchString(operationID) {
		return Snapshot{}, errors.New("rollback operation ID 无效")
	}
	path := s.path(operationID)
	info, err := os.Lstat(path)
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return Snapshot{}, errors.New("rollback snapshot 必须是 0600 普通文件")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return Snapshot{}, errors.New("rollback snapshot JSON 无效")
	}
	if err := validate(snapshot); err != nil {
		return Snapshot{}, err
	}
	if snapshot.OperationID != operationID {
		return Snapshot{}, errors.New("rollback filename 与 operation ID 不一致")
	}
	return snapshot, nil
}

func (s *Store) List() ([]Snapshot, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			return nil, fmt.Errorf("rollback 目录存在未知条目 %q", entry.Name())
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		if !operationIDPattern.MatchString(id) {
			return nil, fmt.Errorf("rollback 文件名 %q 无效", entry.Name())
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]Snapshot, 0, len(ids))
	for _, id := range ids {
		snapshot, err := s.Load(id)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, nil
}

func (s *Store) Delete(operationID string) error {
	if !operationIDPattern.MatchString(operationID) {
		return errors.New("rollback operation ID 无效")
	}
	err := os.Remove(s.path(operationID))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return syncDir(s.dir)
}

func (s *Store) path(operationID string) string {
	return filepath.Join(s.dir, operationID+".json")
}

func validate(snapshot Snapshot) error {
	if snapshot.Version != snapshotVersion || !operationIDPattern.MatchString(snapshot.OperationID) ||
		snapshot.IPv4 == "" || snapshot.CertID <= 0 || snapshot.NewFingerprint == "" || snapshot.OldFingerprint == "" ||
		snapshot.Old.ID != snapshot.CertID || len(snapshot.Old.CertData) == 0 || len(snapshot.Old.KeyData) == 0 {
		return errors.New("rollback snapshot 字段不完整")
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func NewSnapshot(operationID, ip, newFingerprint, oldFingerprint string, old goedge.CertificateInput) Snapshot {
	return Snapshot{Version: snapshotVersion, OperationID: operationID, IPv4: ip, CertID: old.ID,
		NewFingerprint: newFingerprint, OldFingerprint: oldFingerprint, Old: old}
}
