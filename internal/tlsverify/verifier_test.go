package tlsverify

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/testutil"
)

func TestNetworkVerifierChecksChainIPSANAndFingerprint(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, err := testutil.Certificate(testutil.CertOptions{IP: "127.0.0.1", NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(digest[:])
	pool := x509.NewCertPool()
	block, rest := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("missing leaf PEM")
	}
	root, _ := pem.Decode(rest)
	if root == nil {
		t.Fatal("missing root PEM")
	}
	pool.AddCert(mustParseCertificate(t, root.Bytes))

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serveTLSConnections(listener, 2)
	verifier := &NetworkVerifier{Timeout: time.Second, PollInterval: 10 * time.Millisecond, RootCAs: pool,
		Address: func(string) string { return listener.Addr().String() }}
	if err := verifier.Verify(context.Background(), "127.0.0.1", fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), "127.0.0.1", "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
}

func serveTLSConnections(listener net.Listener, count int) {
	go func() {
		for i := 0; i < count; i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			_ = conn.Close()
		}
	}()
}

func mustParseCertificate(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
