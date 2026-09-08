package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-sql-driver/mysql"
	acmeclient "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/acme"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/bootstrap"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/config"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/lifecycle"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/lock"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/rollback"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/scheduler"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/security"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/tlsverify"
)

const defaultConfigPath = "/etc/goedge-ip-cert/config.yaml"
const version = "v0.1.0-preview.5"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误:", security.NewRedactor().Redact(err.Error()))
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("用法: goedge-ip-cert <version|validate-config|status|discover-websites|target-status|bootstrap-db|run-once> [参数]")
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(os.Stdout, version)
		return nil
	case "bootstrap-db":
		flags := flag.NewFlagSet("bootstrap-db", flag.ContinueOnError)
		path := flags.String("goedge-db-config", "", "GoEdge db.yaml")
		output := flags.String("output", "/etc/goedge-ip-cert/credentials/mysql-dsn", "专用 DSN 文件")
		databaseOutput := flags.String("database-output", "", "非敏感数据库名文件")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *path == "" {
			return errors.New("必须指定 --goedge-db-config")
		}
		return bootstrap.InitializeDatabase(context.Background(), *path, *output, *databaseOutput)
	case "discover-websites":
		return discoverWebsites(args[1:])
	case "target-status":
		return targetStatus(args[1:])
	case "validate-config":
		flags := flag.NewFlagSet("validate-config", flag.ContinueOnError)
		path := flags.String("config", defaultConfigPath, "配置文件")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		if _, err := (config.GoEdgeCredentials{Config: cfg.GoEdge}).Credentials(); err != nil {
			return err
		}
		dsn, err := cfg.Database.DSN.Load()
		if err != nil {
			return err
		}
		return validateDSN(dsn, cfg.Database.Name)
	case "status":
		flags := flag.NewFlagSet("status", flag.ContinueOnError)
		path := flags.String("config", defaultConfigPath, "配置文件")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*path)
		if err != nil {
			return err
		}
		store, err := state.Open(cfg.State.Path)
		if err != nil {
			return err
		}
		defer store.Close()
		items, err := store.ListManaged(context.Background())
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, items)
	case "run-once":
		flags := flag.NewFlagSet("run-once", flag.ContinueOnError)
		path := flags.String("config", defaultConfigPath, "配置文件")
		apply := flags.Bool("apply", false, "执行签发/续期；默认只 dry-run")
		timer := flags.Bool("timer", false, "Timer 自动运行；跳过首次签发和 NEEDS_ATTENTION")
		manualRetry := flags.Bool("manual-first-issue-retry", false, "用户确认后手工重试首次签发")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if (*timer || *manualRetry) && !*apply {
			return errors.New("--timer/--manual-first-issue-retry 仅可与 --apply 一起使用")
		}
		if *timer && *manualRetry {
			return errors.New("--timer 与 --manual-first-issue-retry 不能同时使用")
		}
		mode := lifecycle.RunModeInteractive
		if *timer {
			mode = lifecycle.RunModeTimer
		} else if *manualRetry {
			mode = lifecycle.RunModeManualFirstIssueRetry
		}
		return runOnce(context.Background(), *path, *apply, mode)
	default:
		return fmt.Errorf("未知命令 %q", args[0])
	}
}

func runOnce(ctx context.Context, configPath string, apply bool, mode lifecycle.RunMode) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	runLock, err := lock.Acquire(cfg.State.Path + ".lock")
	if err != nil {
		return err
	}
	defer runLock.Close()

	stateStore, err := state.Open(cfg.State.Path)
	if err != nil {
		return err
	}
	defer stateStore.Close()
	dsn, err := cfg.Database.DSN.Load()
	if err != nil {
		return err
	}
	if err := validateDSN(dsn, cfg.Database.Name); err != nil {
		return err
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	challengeStore, err := challenge.NewMySQLStore(db, cfg.Database.Name)
	if err != nil {
		return err
	}
	httpClient := &http.Client{Timeout: cfg.GoEdge.RequestTimeout.Value()}
	edgeClient, err := goedge.NewClient(cfg.GoEdge.Endpoint, httpClient, config.GoEdgeCredentials{Config: cfg.GoEdge})
	if err != nil {
		return err
	}
	policy := scheduler.Policy{
		RenewBefore: cfg.Schedule.RenewBefore.Value(), RetryMin: cfg.Schedule.RetryMin.Value(),
		RetryMax: cfg.Schedule.RetryMax.Value(), JitterMax: cfg.Schedule.JitterMax.Value(),
	}
	runner := &lifecycle.Runner{State: stateStore, Challenges: challengeStore, Edge: edgeClient, Schedule: policy, Now: time.Now, Mode: mode}
	if !apply {
		result, err := runner.DryRun(ctx, cfg.Target.IPv4)
		if err != nil {
			return err
		}
		return writeJSON(os.Stdout, result)
	}
	accountStore, err := acmeclient.NewAccountStore(cfg.ACME.AccountDir)
	if err != nil {
		return err
	}
	account, err := accountStore.LoadOrCreate(cfg.ACME.Email, cfg.ACME.DirectoryURL)
	if err != nil {
		return err
	}
	issuer, err := acmeclient.NewIssuer(cfg.ACME.DirectoryURL, account, accountStore, challengeStore, stateStore)
	if err != nil {
		return err
	}
	reference, err := accountStore.Reference(account)
	if err != nil {
		return err
	}
	runner.Issuer = issuer
	runner.AccountReference = reference
	rollbackStore, err := rollback.NewStore(filepath.Join(filepath.Dir(cfg.State.Path), "rollback"))
	if err != nil {
		return err
	}
	runner.Rollbacks = rollbackStore
	runner.TLS = &tlsverify.NetworkVerifier{Timeout: 90 * time.Second, PollInterval: 2 * time.Second}
	return runner.RunOnce(ctx, cfg.Target.IPv4)
}

func validateDSN(value, databaseName string) error {
	parsed, err := mysql.ParseDSN(value)
	if err != nil {
		return errors.New("MySQL DSN 无效")
	}
	if parsed.DBName != databaseName {
		return fmt.Errorf("MySQL DSN 数据库 %q 与配置 %q 不一致", parsed.DBName, databaseName)
	}
	if parsed.DBName == "" {
		return errors.New("MySQL DSN 必须指定数据库")
	}
	if parsed.MultiStatements || parsed.AllowAllFiles || parsed.AllowCleartextPasswords {
		return errors.New("MySQL DSN 禁止 multiStatements、allowAllFiles 和 cleartext password")
	}
	switch parsed.Net {
	case "unix":
		if parsed.Addr == "" {
			return errors.New("MySQL unix DSN 必须指定 socket")
		}
	case "tcp", "tcp4", "tcp6":
		host, _, err := net.SplitHostPort(parsed.Addr)
		if err != nil {
			return errors.New("MySQL TCP DSN 地址无效")
		}
		if host != "localhost" {
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return errors.New("Stage 2 V1 要求 MySQL 仅使用 loopback 或 Unix socket")
			}
		}
	default:
		return fmt.Errorf("不支持的 MySQL network %q", parsed.Net)
	}
	return nil
}

func writeJSON(file *os.File, value any) error {
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
