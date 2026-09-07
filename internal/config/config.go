package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/ipv4"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/security"
	"gopkg.in/yaml.v3"
)

const (
	LetsEncryptProduction = "https://acme-v02.api.letsencrypt.org/directory"
	LetsEncryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Config struct {
	Version  int      `yaml:"version"`
	Target   Target   `yaml:"target"`
	GoEdge   GoEdge   `yaml:"goedge"`
	Database Database `yaml:"database"`
	ACME     ACME     `yaml:"acme"`
	State    State    `yaml:"state"`
	Schedule Schedule `yaml:"schedule"`
}

type Target struct {
	IPv4 string `yaml:"ipv4"`
}

type GoEdge struct {
	Endpoint       string             `yaml:"endpoint"`
	IdentityType   string             `yaml:"identity_type"`
	AccessKeyID    security.SecretRef `yaml:"access_key_id"`
	AccessKey      security.SecretRef `yaml:"access_key"`
	RequestTimeout Duration           `yaml:"request_timeout"`
}

type Database struct {
	Name string             `yaml:"name"`
	DSN  security.SecretRef `yaml:"dsn"`
}

type ACME struct {
	DirectoryURL string `yaml:"directory_url"`
	Email        string `yaml:"email"`
	AccountDir   string `yaml:"account_dir"`
}

type State struct {
	Path string `yaml:"path"`
}

type Schedule struct {
	RenewBefore Duration `yaml:"renew_before"`
	RetryMin    Duration `yaml:"retry_min"`
	RetryMax    Duration `yaml:"retry_max"`
	JitterMax   Duration `yaml:"jitter_max"`
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("无效时长 %q: %w", node.Value, err)
	}
	*d = Duration(value)
	return nil
}

func (d Duration) Value() time.Duration { return time.Duration(d) }

func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开配置: %w", err)
	}
	defer file.Close()

	var cfg Config
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("解析配置: %w", err)
	}
	cfg.setDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) setDefaults() {
	if c.GoEdge.RequestTimeout == 0 {
		c.GoEdge.RequestTimeout = Duration(15 * time.Second)
	}
	if c.Schedule.RenewBefore == 0 {
		c.Schedule.RenewBefore = Duration(72 * time.Hour)
	}
	if c.Schedule.RetryMin == 0 {
		c.Schedule.RetryMin = Duration(15 * time.Minute)
	}
	if c.Schedule.RetryMax == 0 {
		c.Schedule.RetryMax = Duration(6 * time.Hour)
	}
	if c.Schedule.JitterMax == 0 {
		c.Schedule.JitterMax = Duration(10 * time.Minute)
	}
}

func (c *Config) Validate() error {
	if c.Version != 1 {
		return fmt.Errorf("不支持的配置版本 %d", c.Version)
	}
	if _, err := ipv4.ParsePublic(c.Target.IPv4); err != nil {
		return err
	}
	endpoint, err := url.Parse(c.GoEdge.Endpoint)
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" {
		return errors.New("goedge.endpoint 必须是完整 URL")
	}
	if endpoint.Scheme != "http" && endpoint.Scheme != "https" {
		return errors.New("goedge.endpoint 只允许 http 或 https")
	}
	if endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return errors.New("goedge.endpoint 不允许 userinfo、query 或 fragment")
	}
	host := endpoint.Hostname()
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("Stage 2 V1 要求 goedge.endpoint 仅使用 loopback")
		}
	}
	if c.GoEdge.IdentityType != "admin" && c.GoEdge.IdentityType != "user" {
		return errors.New("goedge.identity_type 只允许 admin 或 user")
	}
	if c.GoEdge.AccessKeyID == (security.SecretRef{}) || c.GoEdge.AccessKey == (security.SecretRef{}) {
		return errors.New("必须配置 GoEdge Access Key 引用")
	}
	if c.Database.Name == "" || c.Database.DSN == (security.SecretRef{}) {
		return errors.New("必须配置数据库名称和 DSN 引用")
	}
	if c.ACME.DirectoryURL != LetsEncryptProduction && c.ACME.DirectoryURL != LetsEncryptStaging {
		return errors.New("V1 只允许 Let's Encrypt production 或 staging directory")
	}
	if c.ACME.Email == "" || c.ACME.AccountDir == "" || c.State.Path == "" {
		return errors.New("ACME email/account_dir 和 state.path 不能为空")
	}
	if !filepath.IsAbs(c.ACME.AccountDir) || !filepath.IsAbs(c.State.Path) {
		return errors.New("ACME account_dir 和 state.path 必须是绝对路径")
	}
	if c.Schedule.RenewBefore.Value() < 48*time.Hour || c.Schedule.RenewBefore.Value() > 96*time.Hour {
		return errors.New("renew_before 必须在 48h 到 96h 之间")
	}
	if c.Schedule.RetryMin.Value() <= 0 || c.Schedule.RetryMax.Value() < c.Schedule.RetryMin.Value() || c.Schedule.JitterMax.Value() < 0 {
		return errors.New("retry/jitter 配置无效")
	}
	return nil
}
