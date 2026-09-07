package certificate

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/pixingzoudaiyuexing/goedge-ip-cert/internal/testutil"
)

func TestVerifyAcceptsExactIPv4Chain(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	certPEM, keyPEM, err := testutil.Certificate(testutil.CertOptions{IP: "8.8.8.8", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(160 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(certPEM, keyPEM, "8.8.8.8", now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.DNSNames[0] != "8.8.8.8" || verified.NotAfter.Sub(now) != 160*time.Hour || len(verified.Fingerprint) != 64 {
		t.Fatalf("unexpected verified result: %+v", verified)
	}
}

func TestVerifyRejectsUnsafeCertificateInputs(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	uri, err := url.Parse("spiffe://example/service")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		options testutil.CertOptions
		request string
	}{
		{"expired", testutil.CertOptions{IP: "8.8.8.8", NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour)}, "8.8.8.8"},
		{"wrong IP", testutil.CertOptions{IP: "1.1.1.1", NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"multiple IP SAN", testutil.CertOptions{IP: "8.8.8.8", ExtraIPs: []net.IP{net.ParseIP("1.1.1.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"DNS SAN", testutil.CertOptions{IP: "8.8.8.8", DNSNames: []string{"example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"email SAN", testutil.CertOptions{IP: "8.8.8.8", Emails: []string{"ops@example.com"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"URI SAN", testutil.CertOptions{IP: "8.8.8.8", URIs: []*url.URL{uri}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"mismatch key", testutil.CertOptions{IP: "8.8.8.8", MismatchKey: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
		{"leaf only", testutil.CertOptions{IP: "8.8.8.8", LeafOnly: true, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}, "8.8.8.8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			certPEM, keyPEM, err := testutil.Certificate(test.options)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(certPEM, keyPEM, test.request, now); err == nil {
				t.Fatal("unsafe certificate unexpectedly accepted")
			}
		})
	}
}
