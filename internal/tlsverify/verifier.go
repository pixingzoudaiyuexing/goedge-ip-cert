package tlsverify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

type NetworkVerifier struct {
	Timeout      time.Duration
	PollInterval time.Duration
	RootCAs      *x509.CertPool
	Address      func(string) string
}

func (v *NetworkVerifier) Verify(ctx context.Context, ipv4, expectedFingerprint string) error {
	if v.Timeout <= 0 || v.PollInterval <= 0 || expectedFingerprint == "" {
		return errors.New("TLS verifier 配置不完整")
	}
	address := net.JoinHostPort(ipv4, "443")
	if v.Address != nil {
		address = v.Address(ipv4)
	}
	verifyCtx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	var lastErr error
	for {
		lastErr = v.verifyOnce(verifyCtx, address, ipv4, expectedFingerprint)
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(v.PollInterval)
		select {
		case <-verifyCtx.Done():
			timer.Stop()
			return fmt.Errorf("TLS verification timeout: %w", lastErr)
		case <-timer.C:
		}
	}
}

func (v *NetworkVerifier) verifyOnce(ctx context.Context, address, ipv4, expectedFingerprint string) error {
	dialer := &tls.Dialer{Config: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: ipv4,
		RootCAs:    v.RootCAs,
	}}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return errors.New("TLS dialer 未返回 TLS connection")
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("TLS peer 未返回证书")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	actual := hex.EncodeToString(digest[:])
	if actual != expectedFingerprint {
		return fmt.Errorf("TLS leaf fingerprint mismatch: got %s", actual)
	}
	return nil
}
