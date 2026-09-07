package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-acme/lego/v4/registration"
)

type Account struct {
	Email        string                 `json:"email"`
	DirectoryURL string                 `json:"directoryUrl"`
	Registration *registration.Resource `json:"registration,omitempty"`
	privateKey   crypto.PrivateKey
}

func (a *Account) GetEmail() string                        { return a.Email }
func (a *Account) GetRegistration() *registration.Resource { return a.Registration }
func (a *Account) GetPrivateKey() crypto.PrivateKey        { return a.privateKey }

type AccountStore struct {
	dir string
}

func NewAccountStore(dir string) (*AccountStore, error) {
	if dir == "" {
		return nil, errors.New("ACME account 目录不能为空")
	}
	return &AccountStore{dir: dir}, nil
}

func (s *AccountStore) LoadOrCreate(email, directoryURL string) (*Account, error) {
	if email == "" || directoryURL == "" {
		return nil, errors.New("ACME email/directory 不能为空")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建 ACME account 目录: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(s.dir, 0o700); err != nil {
			return nil, err
		}
	}
	keyPath := filepath.Join(s.dir, "account.key")
	metaPath := filepath.Join(s.dir, "account.json")
	keyData, keyErr := readPrivateFile(keyPath)
	metaData, metaErr := readPrivateFile(metaPath)
	if keyErr == nil && metaErr == nil {
		return loadAccount(keyData, metaData, email, directoryURL)
	}
	if !errors.Is(keyErr, os.ErrNotExist) || !errors.Is(metaErr, os.ErrNotExist) {
		return nil, errors.New("ACME account key/meta 必须同时存在或同时不存在")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ACME account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	account := &Account{Email: email, DirectoryURL: directoryURL, privateKey: key}
	meta, _ := json.MarshalIndent(account, "", "  ")
	if err := writeAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(metaPath, meta, 0o600); err != nil {
		return nil, err
	}
	return account, nil
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("ACME account 路径不是普通文件")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("ACME account 文件权限必须为 0600 或更严格")
	}
	return os.ReadFile(path)
}

func (s *AccountStore) Save(account *Account) error {
	if account == nil || account.privateKey == nil || account.Email == "" || account.DirectoryURL == "" {
		return errors.New("ACME account 不完整")
	}
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.dir, "account.json"), data, 0o600)
}

func (s *AccountStore) Reference(account *Account) (string, error) {
	if account == nil || account.GetPrivateKey() == nil || account.DirectoryURL == "" {
		return "", errors.New("ACME account 不完整")
	}
	signer, ok := account.GetPrivateKey().(crypto.Signer)
	if !ok {
		return "", errors.New("ACME account key 不支持签名")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}
	digest := sha256Sum(publicDER)
	return account.DirectoryURL + "#" + digest[:16], nil
}

func loadAccount(keyPEM, meta []byte, email, directoryURL string) (*Account, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("ACME account key PEM 无效")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("ACME account key 无效")
	}
	if _, ok := key.(crypto.Signer); !ok {
		return nil, errors.New("ACME account key 不支持签名")
	}
	var account Account
	if err := json.Unmarshal(meta, &account); err != nil {
		return nil, errors.New("ACME account metadata 无效")
	}
	if account.Email != email || account.DirectoryURL != directoryURL {
		return nil, errors.New("ACME account metadata 与配置不一致")
	}
	account.privateKey = key
	return &account, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".account-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
