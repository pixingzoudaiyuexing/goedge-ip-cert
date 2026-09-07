package bootstrap

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
)

const RuntimeDBUser = "goedge_ip_cert"
const ChallengeTable = "edgeACMEAuthentications"

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

type GoEdgeDBConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Database string `yaml:"database"`
}

func LoadGoEdgeDBConfig(path string) (GoEdgeDBConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return GoEdgeDBConfig{}, fmt.Errorf("读取 GoEdge DB 配置: %w", err)
	}
	var cfg GoEdgeDBConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return GoEdgeDBConfig{}, fmt.Errorf("解析 GoEdge DB 配置: %w", err)
	}
	if cfg.User == "" || cfg.Password == "" || cfg.Host == "" || !identifierPattern.MatchString(cfg.Database) {
		return GoEdgeDBConfig{}, errors.New("GoEdge DB 配置不完整或数据库名不安全")
	}
	host, _, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		return GoEdgeDBConfig{}, errors.New("GoEdge DB host 必须包含端口")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return GoEdgeDBConfig{}, errors.New("GoEdge DB 必须使用 loopback")
		}
	}
	return cfg, nil
}

func InitializeDatabase(ctx context.Context, configPath, outputPath, databaseOutputPath string) error {
	if _, err := os.Stat(outputPath); err == nil {
		if err := verifyExistingRuntimeDSN(ctx, outputPath); err != nil {
			return err
		}
		if databaseOutputPath != "" {
			data, err := os.ReadFile(outputPath)
			if err != nil {
				return err
			}
			parsed, err := mysql.ParseDSN(strings.TrimSpace(string(data)))
			if err != nil {
				return err
			}
			return writePublicAtomic(databaseOutputPath, []byte(parsed.DBName+"\n"))
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cfg, err := LoadGoEdgeDBConfig(configPath)
	if err != nil {
		return err
	}
	adminConfig := mysql.Config{User: cfg.User, Passwd: cfg.Password, Net: "tcp", Addr: cfg.Host,
		DBName: cfg.Database, ParseTime: true, AllowNativePasswords: true, Params: map[string]string{"charset": "utf8mb4"}}
	adminDSN := adminConfig.FormatDSN()
	db, err := sql.Open("mysql", adminDSN)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("AUTO_DB_INITIALIZATION_FAILED: 无法使用 GoEdge DB 管理连接")
	}
	var tableCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?`,
		cfg.Database, ChallengeTable).Scan(&tableCount); err != nil || tableCount != 1 {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: challenge 表不存在或不可确认")
	}
	var userCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mysql.user WHERE User=? AND Host='127.0.0.1'`, RuntimeDBUser).Scan(&userCount); err != nil {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 无法确认专用 DB 用户")
	}
	if userCount != 0 {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 专用 DB 用户已存在但本地 credential 不存在，拒绝重置")
	}
	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		return err
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	createSQL, grantSQL, err := LeastPrivilegeSQL(cfg.Database, password)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, createSQL); err != nil {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: CREATE USER 失败")
	}
	created := true
	defer func() {
		if created {
			_, _ = db.ExecContext(context.Background(), "DROP USER '"+RuntimeDBUser+"'@'127.0.0.1'")
		}
	}()
	if _, err := db.ExecContext(ctx, grantSQL); err != nil {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 最小权限 GRANT 失败")
	}
	runtimeConfig := mysql.Config{User: RuntimeDBUser, Passwd: password, Net: "tcp", Addr: cfg.Host,
		DBName: cfg.Database, ParseTime: true, AllowNativePasswords: true, Params: map[string]string{"charset": "utf8mb4"}}
	runtimeDSN := runtimeConfig.FormatDSN()
	if err := writePrivateAtomic(outputPath, []byte(runtimeDSN+"\n")); err != nil {
		return err
	}
	if err := verifyRuntimeDSN(ctx, runtimeDSN); err != nil {
		_ = os.Remove(outputPath)
		return err
	}
	if databaseOutputPath != "" {
		if err := writePublicAtomic(databaseOutputPath, []byte(cfg.Database+"\n")); err != nil {
			_ = os.Remove(outputPath)
			return err
		}
	}
	created = false
	return nil
}

func LeastPrivilegeSQL(database, password string) (string, string, error) {
	if !identifierPattern.MatchString(database) || password == "" || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(password) {
		return "", "", errors.New("数据库名或随机密码不安全")
	}
	account := "'" + RuntimeDBUser + "'@'127.0.0.1'"
	return "CREATE USER " + account + " IDENTIFIED BY '" + password + "'",
		"GRANT SELECT, INSERT, DELETE ON `" + database + "`.`" + ChallengeTable + "` TO " + account, nil
}

func verifyExistingRuntimeDSN(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 现有 DB credential 权限不安全")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return verifyRuntimeDSN(ctx, strings.TrimSpace(string(data)))
}

func verifyRuntimeDSN(ctx context.Context, dsn string) error {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 专用 DB credential 无法登录")
	}
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR '"+RuntimeDBUser+"'@'127.0.0.1'")
	if err != nil {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: SHOW GRANTS 失败")
	}
	defer rows.Close()
	var grants []string
	for rows.Next() {
		var grant string
		if err := rows.Scan(&grant); err != nil {
			return err
		}
		grants = append(grants, grant)
	}
	parsed, err := mysql.ParseDSN(dsn)
	if err != nil || !ExactLeastPrivilegeGrants(grants, parsed.DBName) {
		return errors.New("AUTO_DB_INITIALIZATION_FAILED: 专用 DB 用户权限不是最小权限")
	}
	return nil
}

func ExactLeastPrivilegeGrants(grants []string, database string) bool {
	want := "GRANT SELECT, INSERT, DELETE ON `" + database + "`.`" + ChallengeTable + "` TO '" + RuntimeDBUser + "'@'127.0.0.1'"
	passwordSuffix := regexp.MustCompile(` IDENTIFIED BY PASSWORD '[*A-Fa-f0-9]+'$`)
	found := false
	for _, grant := range grants {
		grant = passwordSuffix.ReplaceAllString(strings.TrimSpace(grant), "")
		upper := strings.ToUpper(strings.TrimSpace(grant))
		if strings.HasPrefix(upper, "GRANT USAGE ON *.* TO ") {
			continue
		}
		if grant == want {
			found = true
			continue
		}
		return false
	}
	return found
}

func writePrivateAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credential-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func writePublicAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".metadata-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
