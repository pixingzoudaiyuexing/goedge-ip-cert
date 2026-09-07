package certificate

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/ipv4"
)

type Verified struct {
	CertPEM     []byte
	KeyPEM      []byte
	NotBefore   time.Time
	NotAfter    time.Time
	DNSNames    []string
	CommonNames []string
	Fingerprint string
}

func Verify(certPEM, keyPEM []byte, requestedIPv4 string, now time.Time) (*Verified, error) {
	requested, err := ipv4.ParsePublic(requestedIPv4)
	if err != nil {
		return nil, err
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, errors.New("证书或私钥为空")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	certs := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("解析证书链: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) < 2 {
		return nil, errors.New("证书链不完整：至少需要 leaf 和 issuer")
	}
	leaf := certs[0]
	if leaf.IsCA {
		return nil, errors.New("leaf 证书不能是 CA")
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("证书尚未生效或已经过期")
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 1 || len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0 {
		return nil, errors.New("V1 证书 SAN 必须且只能包含一个 IPv4")
	}
	leafIP, err := ipv4.ParsePublic(leaf.IPAddresses[0].String())
	if err != nil || leafIP != requested {
		return nil, errors.New("证书 IP SAN 与请求 IPv4 不一致")
	}
	for index := 0; index < len(certs)-1; index++ {
		if !certs[index+1].IsCA {
			return nil, errors.New("证书链中的 issuer 不是 CA")
		}
		if err := certs[index].CheckSignatureFrom(certs[index+1]); err != nil {
			return nil, fmt.Errorf("证书链签名无效: %w", err)
		}
	}
	commonNames := make([]string, 0, len(certs))
	for _, cert := range certs {
		if cert.Issuer.CommonName != "" {
			commonNames = append(commonNames, cert.Issuer.CommonName)
		}
	}
	digest := sha256.Sum256(leaf.Raw)
	return &Verified{
		CertPEM:     append([]byte(nil), certPEM...),
		KeyPEM:      append([]byte(nil), keyPEM...),
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
		DNSNames:    []string{requested.String()},
		CommonNames: commonNames,
		Fingerprint: hex.EncodeToString(digest[:]),
	}, nil
}

func ParseFirstCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("找不到 PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}
