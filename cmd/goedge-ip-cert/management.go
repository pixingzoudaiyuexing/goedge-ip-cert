package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"net/http"
	"os"
	"time"

	certcheck "github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/certificate"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/config"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/goedge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/security"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/state"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/tlsverify"
)

func discoverWebsites(args []string) error {
	flags := flag.NewFlagSet("discover-websites", flag.ContinueOnError)
	endpoint := flags.String("endpoint", "http://127.0.0.1:8002", "GoEdge REST endpoint")
	identity := flags.String("identity-type", "admin", "GoEdge identity type")
	idFile := flags.String("access-key-id-file", "/etc/goedge-ip-cert/credentials/goedge-access-key-id", "Access Key ID 文件")
	keyFile := flags.String("access-key-file", "/etc/goedge-ip-cert/credentials/goedge-access-key", "Access Key secret 文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	client, err := managementClient(*endpoint, *identity, *idFile, *keyFile)
	if err != nil {
		return err
	}
	websites, err := client.ListEligibleWebsites(context.Background())
	if err != nil {
		return err
	}
	return writeJSON(os.Stdout, websites)
}

type targetStatusResult struct {
	IPv4          string `json:"ipv4"`
	Website       string `json:"website"`
	Cluster       string `json:"cluster"`
	ServerID      int64  `json:"serverId"`
	PolicyID      int64  `json:"policyId"`
	CertID        int64  `json:"certId"`
	State         string `json:"state"`
	Bound         bool   `json:"bound"`
	NodeOnline    bool   `json:"nodeOnline"`
	Issuer        string `json:"issuer"`
	Environment   string `json:"environment"`
	IPSAN         bool   `json:"ipSan"`
	NotBefore     int64  `json:"notBefore"`
	NotAfter      int64  `json:"notAfter"`
	Remaining     string `json:"remaining"`
	AutoRenew     bool   `json:"autoRenew"`
	RenewBefore   string `json:"renewBefore"`
	NextRenewalAt int64  `json:"nextRenewalAt"`
	LastSuccessAt int64  `json:"lastSuccessAt"`
	LastFailureAt int64  `json:"lastFailureAt"`
	LastError     string `json:"lastError"`
	SystemTrust   bool   `json:"systemTrust"`
	HTTPSStatus   string `json:"httpsStatus"`
}

func targetStatus(args []string) error {
	flags := flag.NewFlagSet("target-status", flag.ContinueOnError)
	path := flags.String("config", defaultConfigPath, "配置文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	client, err := managementClientFromConfig(cfg)
	if err != nil {
		return err
	}
	result := targetStatusResult{IPv4: cfg.Target.IPv4, RenewBefore: cfg.Schedule.RenewBefore.Value().String(),
		Environment: "Production", HTTPSStatus: "未验证"}
	if cfg.ACME.DirectoryURL == config.LetsEncryptStaging {
		result.Environment = "Staging"
	}
	websites, err := client.ListEligibleWebsites(context.Background())
	if err != nil {
		return err
	}
	for _, website := range websites {
		if website.IPv4 == cfg.Target.IPv4 {
			result.Website, result.Cluster = website.Name, website.Cluster
			result.ServerID, result.PolicyID, result.NodeOnline = website.ServerID, website.PolicyID, website.NodeOnline
			break
		}
	}
	store, err := state.Open(cfg.State.Path)
	if err != nil {
		return err
	}
	defer store.Close()
	managed, managedErr := store.Managed(context.Background(), cfg.Target.IPv4)
	if managedErr == nil {
		result.CertID, result.State = managed.CertID, string(managed.State)
		if result.ServerID == 0 {
			result.ServerID, result.PolicyID = managed.ServerID, managed.PolicyID
		}
		result.NextRenewalAt, result.LastSuccessAt = managed.NextRenewalAt, managed.LastSuccessAt
		result.LastError, result.AutoRenew = managed.LastError, true
	} else if !errors.Is(managedErr, state.ErrNotFound) {
		return managedErr
	} else if operation, opErr := store.LatestOperation(context.Background(), cfg.Target.IPv4); opErr == nil {
		result.CertID, result.State, result.LastError = operation.CertID, string(operation.Stage), operation.ErrorMessage
		result.LastFailureAt = operation.UpdatedAt / int64(time.Second)
		if state.IsFirstIssueFailure(operation) {
			result.State = string(state.StateNeedsAttention)
		}
		if result.ServerID == 0 {
			result.ServerID, result.PolicyID = operation.ServerID, operation.PolicyID
		}
	} else if !errors.Is(opErr, state.ErrNotFound) {
		return opErr
	} else {
		result.State = "未申请"
	}
	if result.CertID > 0 {
		cert, err := client.Certificate(context.Background(), result.CertID)
		if err != nil {
			result.HTTPSStatus = "证书读取失败"
			return writeJSON(os.Stdout, result)
		}
		leaf, err := certcheck.ParseFirstCertificate(cert.CertData)
		if err == nil {
			result.Issuer = leaf.Issuer.String()
			result.NotBefore, result.NotAfter = leaf.NotBefore.Unix(), leaf.NotAfter.Unix()
			result.Remaining = time.Until(leaf.NotAfter).Round(time.Minute).String()
			for _, ip := range leaf.IPAddresses {
				if ip.String() == cfg.Target.IPv4 {
					result.IPSAN = true
				}
			}
		}
		result.Bound = client.VerifyCertificateBound(context.Background(), result.PolicyID, result.CertID) == nil
		if result.Bound && leaf != nil {
			digest := sha256.Sum256(leaf.Raw)
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			if err := (&tlsverify.NetworkVerifier{Timeout: 10 * time.Second, PollInterval: time.Second}).Verify(ctx,
				cfg.Target.IPv4, hex.EncodeToString(digest[:])); err == nil {
				result.SystemTrust, result.HTTPSStatus = true, "正常"
			} else {
				result.HTTPSStatus = "HTTPS异常"
			}
		}
	}
	return writeJSON(os.Stdout, result)
}

func managementClientFromConfig(cfg *config.Config) (*goedge.Client, error) {
	return goedge.NewClient(cfg.GoEdge.Endpoint, &http.Client{Timeout: cfg.GoEdge.RequestTimeout.Value()},
		config.GoEdgeCredentials{Config: cfg.GoEdge})
}

func managementClient(endpoint, identity, idFile, keyFile string) (*goedge.Client, error) {
	cfg := config.GoEdge{Endpoint: endpoint, IdentityType: identity,
		AccessKeyID: security.SecretRef{File: idFile}, AccessKey: security.SecretRef{File: keyFile},
		RequestTimeout: config.Duration(15 * time.Second)}
	return goedge.NewClient(endpoint, &http.Client{Timeout: 15 * time.Second}, config.GoEdgeCredentials{Config: cfg})
}
