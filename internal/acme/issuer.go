package acme

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	legoclient "github.com/go-acme/lego/v4/lego"
	acmelog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/challenge"
	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/ipv4"
)

const ShortLivedProfile = "shortlived"

type IssuedCertificate struct {
	Certificate []byte
	PrivateKey  []byte
}

type Issuer struct {
	directoryURL string
	account      *Account
	accountStore *AccountStore
	store        challenge.Store
	journal      challenge.Journal
}

func NewIssuer(directoryURL string, account *Account, accountStore *AccountStore, store challenge.Store, journal challenge.Journal) (*Issuer, error) {
	if directoryURL == "" || account == nil || accountStore == nil || store == nil || journal == nil {
		return nil, errors.New("ACME issuer 参数不完整")
	}
	// lego 的默认 logger 是全局 stdout；服务不允许把 challenge 细节写入日志。
	acmelog.Logger = log.New(io.Discard, "", 0)
	return &Issuer{directoryURL: directoryURL, account: account, accountStore: accountStore, store: store, journal: journal}, nil
}

func (i *Issuer) Obtain(ctx context.Context, operationID, requestedIPv4 string) (IssuedCertificate, error) {
	if _, err := ipv4.ParsePublic(requestedIPv4); err != nil {
		return IssuedCertificate{}, err
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	config := legoclient.NewConfig(i.account)
	config.CADirURL = i.directoryURL
	config.Certificate.KeyType = certcrypto.RSA2048
	client, err := legoclient.NewClient(config)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("创建 ACME client: %w", err)
	}
	if i.account.Registration == nil {
		resource, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return IssuedCertificate{}, fmt.Errorf("注册 ACME account: %w", err)
		}
		i.account.Registration = resource
		if err := i.accountStore.Save(i.account); err != nil {
			return IssuedCertificate{}, fmt.Errorf("保存 ACME account registration: %w", err)
		}
	} else if _, err := client.Registration.QueryRegistration(); err != nil {
		return IssuedCertificate{}, fmt.Errorf("查询 ACME account: %w", err)
	}
	provider, err := challenge.NewProvider(ctx, operationID, i.store, i.journal)
	if err != nil {
		return IssuedCertificate{}, err
	}
	if err := client.Challenge.SetHTTP01Provider(provider); err != nil {
		return IssuedCertificate{}, err
	}
	request, err := obtainRequest(requestedIPv4)
	if err != nil {
		return IssuedCertificate{}, err
	}
	resource, err := client.Certificate.ObtainForCSR(request)
	if err != nil {
		return IssuedCertificate{}, fmt.Errorf("ACME obtain: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return IssuedCertificate{}, err
	}
	return IssuedCertificate{Certificate: resource.Certificate, PrivateKey: resource.PrivateKey}, nil
}

func obtainRequest(requestedIPv4 string) (certificate.ObtainForCSRRequest, error) {
	if _, err := ipv4.ParsePublic(requestedIPv4); err != nil {
		return certificate.ObtainForCSRRequest{}, err
	}
	privateKey, err := certcrypto.GeneratePrivateKey(certcrypto.RSA2048)
	if err != nil {
		return certificate.ObtainForCSRRequest{}, fmt.Errorf("生成 certificate private key: %w", err)
	}
	der, err := createIPv4CSRDER(requestedIPv4, privateKey)
	if err != nil {
		return certificate.ObtainForCSRRequest{}, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return certificate.ObtainForCSRRequest{}, fmt.Errorf("解析 IPv4 CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return certificate.ObtainForCSRRequest{}, fmt.Errorf("校验 IPv4 CSR 签名: %w", err)
	}
	return certificate.ObtainForCSRRequest{
		CSR: csr, PrivateKey: privateKey, Bundle: true, Profile: ShortLivedProfile,
	}, nil
}

func createIPv4CSRDER(requestedIPv4 string, privateKey crypto.PrivateKey) ([]byte, error) {
	addr, err := ipv4.ParsePublic(requestedIPv4)
	if err != nil {
		return nil, err
	}
	if privateKey == nil {
		return nil, errors.New("certificate private key 不能为空")
	}
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		IPAddresses: []net.IP{net.IP(addr.AsSlice())},
	}, privateKey)
}
