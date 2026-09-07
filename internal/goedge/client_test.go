package goedge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticCredentials struct{ value Credentials }

func (s staticCredentials) Credentials() (Credentials, error) { return s.value, nil }

func redirectSameHost(t *testing.T, status int) (string, *http.Client, *int, *string) {
	t.Helper()
	hits := 0
	leaked := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/APIAccessTokenService/getAPIAccessToken" {
			writeEnvelope(t, w, 200, "ok", map[string]any{"token": "redirect-secret-token", "expiresAt": time.Now().Add(time.Hour).Unix()})
			return
		}
		if r.URL.Path == "/redirect-target" {
			hits++
			leaked = r.Header.Get("X-Edge-Access-Token")
			writePolicyResponse(t, w)
			return
		}
		http.Redirect(w, r, "/redirect-target", status)
	}))
	t.Cleanup(server.Close)
	return server.URL, server.Client(), &hits, &leaked
}

func redirectCrossHost(t *testing.T, status int) (string, *http.Client, *int, *string) {
	t.Helper()
	hits := 0
	leaked := ""
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		leaked = r.Header.Get("X-Edge-Access-Token")
		writePolicyResponse(t, w)
	}))
	t.Cleanup(target.Close)
	source := redirectSource(t, status, target.URL+"/redirect-target", false)
	return source.URL, source.Client(), &hits, &leaked
}

func redirectHTTPToHTTPS(t *testing.T, status int) (string, *http.Client, *int, *string) {
	t.Helper()
	hits := 0
	leaked := ""
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		leaked = r.Header.Get("X-Edge-Access-Token")
		writePolicyResponse(t, w)
	}))
	t.Cleanup(target.Close)
	source := redirectSource(t, status, target.URL+"/redirect-target", false)
	return source.URL, target.Client(), &hits, &leaked
}

func redirectHTTPSToHTTP(t *testing.T, status int) (string, *http.Client, *int, *string) {
	t.Helper()
	hits := 0
	leaked := ""
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		leaked = r.Header.Get("X-Edge-Access-Token")
		writePolicyResponse(t, w)
	}))
	t.Cleanup(target.Close)
	source := redirectSource(t, status, target.URL+"/redirect-target", true)
	return source.URL, source.Client(), &hits, &leaked
}

func redirectSource(t *testing.T, status int, location string, tls bool) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/APIAccessTokenService/getAPIAccessToken" {
			writeEnvelope(t, w, 200, "ok", map[string]any{"token": "redirect-secret-token", "expiresAt": time.Now().Add(time.Hour).Unix()})
			return
		}
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	})
	var server *httptest.Server
	if tls {
		server = httptest.NewTLSServer(handler)
	} else {
		server = httptest.NewServer(handler)
	}
	t.Cleanup(server.Close)
	return server
}

func writePolicyResponse(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	data, _ := json.Marshal(SSLPolicy{ID: 9, IsOn: true})
	writeEnvelope(t, w, 200, "ok", map[string]any{"sslPolicyJSON": data})
}

type fakeAPI struct {
	t                *testing.T
	server           *httptest.Server
	mu               sync.Mutex
	authCalls        int
	createCalls      int
	updateCalls      int
	policyReads      int
	policyWrites     int
	nextCertID       int64
	certs            map[int64]CertificateConfig
	servers          []serverResponse
	policy           SSLPolicy
	authFailure      bool
	authErrorMessage string
	httpFailure      string
	invalidBody      string
	delay            time.Duration
	mutateOnRead     int
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{t: t, nextCertID: 40, certs: map[int64]CertificateConfig{}, policy: SSLPolicy{
		ID: 9, IsOn: true, CertRefs: []SSLCertRef{{IsOn: true, CertID: 7}}, ClientAuthType: 4,
		ClientCARefs: []SSLCertRef{{IsOn: true, CertID: 8}}, MinVersion: "TLS 1.2",
		CipherSuitesIsOn: true, CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		HSTS: json.RawMessage(`{"isOn":true,"maxAge":31536000}`), HTTP2Enabled: true, HTTP3Enabled: true, OCSPIsOn: false,
	}}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAPI) client(timeout time.Duration) *Client {
	client, err := NewClient(f.server.URL, &http.Client{Timeout: timeout}, staticCredentials{Credentials{IdentityType: "admin", AccessKeyID: "test-id", AccessKey: "test-secret"}})
	if err != nil {
		f.t.Fatal(err)
	}
	return client
}

func (f *fakeAPI) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.httpFailure == r.URL.Path {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	if f.invalidBody == r.URL.Path {
		_, _ = w.Write([]byte("not-json"))
		return
	}
	if r.URL.Path == "/APIAccessTokenService/getAPIAccessToken" {
		f.authCalls++
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			f.t.Error(err)
		}
		if request["accessKeyId"] != "test-id" || request["accessKey"] != "test-secret" || r.Header.Get("X-Edge-Access-Token") != "" {
			f.t.Errorf("bad auth request: %#v", request)
		}
		if f.authFailure {
			message := f.authErrorMessage
			if message == "" {
				message = "access key not found"
			}
			writeEnvelope(f.t, w, 400, message, map[string]any{})
			return
		}
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"token": "short-lived-token", "expiresAt": time.Now().Add(2 * time.Hour).Unix()})
		return
	}
	if r.Header.Get("X-Edge-Access-Token") != "short-lived-token" {
		writeEnvelope(f.t, w, 400, "invalid access token", map[string]any{})
		return
	}
	switch r.URL.Path {
	case "/SSLCertService/createSSLCert":
		var input CertificateInput
		decodeBody(f.t, r, &input)
		f.nextCertID++
		input.ID = f.nextCertID
		f.certs[input.ID] = inputConfig(input)
		f.createCalls++
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"sslCertId": input.ID})
	case "/SSLCertService/updateSSLCert":
		var input struct {
			SSLCertID   int64    `json:"sslCertId"`
			IsOn        bool     `json:"isOn"`
			Name        string   `json:"name"`
			Description string   `json:"description"`
			ServerName  string   `json:"serverName"`
			IsCA        bool     `json:"isCA"`
			CertData    []byte   `json:"certData"`
			KeyData     []byte   `json:"keyData"`
			TimeBeginAt int64    `json:"timeBeginAt"`
			TimeEndAt   int64    `json:"timeEndAt"`
			DNSNames    []string `json:"dnsNames"`
			CommonNames []string `json:"commonNames"`
		}
		decodeBody(f.t, r, &input)
		flat := CertificateInput{ID: input.SSLCertID, IsOn: input.IsOn, Name: input.Name, Description: input.Description,
			ServerName: input.ServerName, IsCA: input.IsCA, CertData: input.CertData, KeyData: input.KeyData,
			TimeBeginAt: input.TimeBeginAt, TimeEndAt: input.TimeEndAt, DNSNames: input.DNSNames, CommonNames: input.CommonNames}
		f.certs[flat.ID] = inputConfig(flat)
		f.updateCalls++
		writeEnvelope(f.t, w, 200, "ok", map[string]any{})
	case "/SSLCertService/findEnabledSSLCertConfig":
		var request struct {
			SSLCertID int64 `json:"sslCertId"`
		}
		decodeBody(f.t, r, &request)
		cert, ok := f.certs[request.SSLCertID]
		if !ok {
			writeEnvelope(f.t, w, 200, "ok", map[string]any{"sslCertJSON": []byte("null")})
			return
		}
		data, _ := json.Marshal(cert)
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"sslCertJSON": data})
	case "/SSLCertService/listSSLCerts":
		var request struct {
			Keyword string `json:"keyword"`
		}
		decodeBody(f.t, r, &request)
		var certs []CertificateConfig
		for _, cert := range f.certs {
			if cert.Name == request.Keyword {
				copy := cert
				copy.CertData, copy.KeyData = nil, nil
				certs = append(certs, copy)
			}
		}
		data, _ := json.Marshal(certs)
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"sslCertsJSON": data})
	case "/ServerService/listEnabledServersMatch":
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"servers": f.servers})
	case "/ServerService/countAllEnabledServersMatch":
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"count": len(f.servers)})
	case "/SSLPolicyService/findEnabledSSLPolicyConfig":
		f.policyReads++
		if f.mutateOnRead == f.policyReads {
			f.policy.MinVersion = "TLS 1.3"
		}
		data, _ := json.Marshal(f.policy)
		writeEnvelope(f.t, w, 200, "ok", map[string]any{"sslPolicyJSON": data})
	case "/SSLPolicyService/updateSSLPolicy":
		f.policyWrites++
		writeEnvelope(f.t, w, 500, "Policy writes are forbidden", map[string]any{})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestClientAuthenticationAndCertificateCreate(t *testing.T) {
	f := newFakeAPI(t)
	client := f.client(time.Second)
	id, err := client.CreateCertificate(context.Background(), CertificateInput{IsOn: true, Name: "marker", CertData: []byte("cert"), KeyData: []byte("key"), TimeEndAt: 123, DNSNames: []string{"8.8.8.8"}})
	if err != nil || id != 41 || f.authCalls != 1 || f.createCalls != 1 {
		t.Fatalf("id=%d err=%v auth=%d create=%d", id, err, f.authCalls, f.createCalls)
	}
	if _, err := client.FindCertificateByMarker(context.Background(), "marker", 0); err != nil {
		t.Fatal(err)
	}
	if f.authCalls != 1 {
		t.Fatalf("token cache missed: auth calls=%d", f.authCalls)
	}
}

func TestUpdateCertificateKeepsSameID(t *testing.T) {
	f := newFakeAPI(t)
	f.certs[77] = CertificateConfig{ID: 77, IsOn: true, Name: "managed", CertData: []byte("old"), KeyData: []byte("old-key")}
	client := f.client(time.Second)
	err := client.UpdateCertificate(context.Background(), CertificateInput{ID: 77, IsOn: true, Name: "managed", CertData: []byte("new"), KeyData: []byte("new-key"), TimeEndAt: 456, DNSNames: []string{"8.8.8.8"}})
	if err != nil || f.updateCalls != 1 || string(f.certs[77].CertData) != "new" || len(f.certs) != 1 {
		t.Fatalf("err=%v updates=%d cert=%+v count=%d", err, f.updateCalls, f.certs[77], len(f.certs))
	}
}

func TestDiscoverServerFiltersBroadSearchAndFailsClosed(t *testing.T) {
	f := newFakeAPI(t)
	f.servers = []serverResponse{
		serverFixture(t, 1, []ServerName{{Name: "not-8.8.8.8.example"}}, 9),
		serverFixture(t, 4, []ServerName{{Name: "8.8.8.8", Type: "match"}}, 9),
		serverFixture(t, 2, []ServerName{{Name: "8.8.8.8"}}, 9),
	}
	target, err := f.client(time.Second).DiscoverServer(context.Background(), "8.8.8.8")
	if err != nil || target.ID != 2 || target.PolicyID != 9 {
		t.Fatalf("target=%+v err=%v", target, err)
	}
	f.servers = append(f.servers, serverFixture(t, 3, []ServerName{{SubNames: []string{"8.8.8.8"}}}, 10))
	_, err = f.client(time.Second).DiscoverServer(context.Background(), "8.8.8.8")
	if !errors.Is(err, ErrMultipleServers) {
		t.Fatalf("multiple match error=%v", err)
	}
}

func TestVerifyCertificateBoundIsReadOnly(t *testing.T) {
	f := newFakeAPI(t)
	f.policy.CertRefs = append(f.policy.CertRefs, SSLCertRef{IsOn: true, CertID: 11})
	if err := f.client(time.Second).VerifyCertificateBound(context.Background(), 9, 11); err != nil {
		t.Fatal(err)
	}
	if f.policyWrites != 0 {
		t.Fatalf("verification wrote Policy %d time(s)", f.policyWrites)
	}

	fMissing := newFakeAPI(t)
	err := fMissing.client(time.Second).VerifyCertificateBound(context.Background(), 9, 11)
	if !errors.Is(err, ErrCertificateNotBound) || !strings.Contains(err.Error(), "certificate ID 11") || !strings.Contains(err.Error(), "policy ID 9") {
		t.Fatalf("missing binding err=%v", err)
	}
	if fMissing.policyWrites != 0 {
		t.Fatalf("missing binding wrote Policy %d time(s)", fMissing.policyWrites)
	}

	fConcurrent := newFakeAPI(t)
	fConcurrent.mutateOnRead = 1
	err = fConcurrent.client(time.Second).VerifyCertificateBound(context.Background(), 9, 11)
	if !errors.Is(err, ErrCertificateNotBound) {
		t.Fatalf("concurrent mutation err=%v", err)
	}
	if fConcurrent.policyWrites != 0 {
		t.Fatalf("concurrent admin mutation caused %d Policy write(s)", fConcurrent.policyWrites)
	}
}

func TestRESTClientRejectsRedirectsWithoutLeakingToken(t *testing.T) {
	statuses := []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}
	tests := []struct {
		name    string
		servers func(*testing.T, int) (string, *http.Client, *int, *string)
	}{
		{"same-host", redirectSameHost},
		{"cross-host", redirectCrossHost},
		{"http-to-https", redirectHTTPToHTTPS},
		{"https-to-http", redirectHTTPSToHTTP},
	}
	for _, test := range tests {
		for _, status := range statuses {
			t.Run(fmt.Sprintf("%s/%d", test.name, status), func(t *testing.T) {
				endpoint, httpClient, hits, leaked := test.servers(t, status)
				client, err := NewClient(endpoint, httpClient, staticCredentials{Credentials{IdentityType: "admin", AccessKeyID: "test-id", AccessKey: "test-secret"}})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Policy(context.Background(), 9); err == nil {
					t.Fatal("redirect unexpectedly accepted")
				}
				if *hits != 0 || *leaked != "" {
					t.Fatalf("redirect target hits=%d leaked token=%q", *hits, *leaked)
				}
			})
		}
	}
}

func TestRESTClientRejectsAuthenticationRedirectWithoutLeakingAccessKey(t *testing.T) {
	var hits int
	var leakedBody string
	target := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hits++
		data, _ := io.ReadAll(r.Body)
		leakedBody = string(data)
	}))
	t.Cleanup(target.Close)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(source.Close)
	client, err := NewClient(source.URL, source.Client(), staticCredentials{Credentials{IdentityType: "admin", AccessKeyID: "test-id", AccessKey: "test-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Policy(context.Background(), 9); err == nil {
		t.Fatal("authentication redirect unexpectedly accepted")
	}
	if hits != 0 || leakedBody != "" {
		t.Fatalf("redirect target hits=%d leaked body=%q", hits, leakedBody)
	}
}

func TestClientErrorSurfaces(t *testing.T) {
	t.Run("auth failure", func(t *testing.T) {
		f := newFakeAPI(t)
		f.authFailure = true
		_, err := f.client(time.Second).Policy(context.Background(), 9)
		if !errors.Is(err, ErrAuthentication) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("HTTP error", func(t *testing.T) {
		f := newFakeAPI(t)
		f.httpFailure = "/SSLPolicyService/findEnabledSSLPolicyConfig"
		_, err := f.client(time.Second).Policy(context.Background(), 9)
		if err == nil {
			t.Fatal("HTTP error was ignored")
		}
	})
	t.Run("unexpected response", func(t *testing.T) {
		f := newFakeAPI(t)
		f.invalidBody = "/SSLPolicyService/findEnabledSSLPolicyConfig"
		_, err := f.client(time.Second).Policy(context.Background(), 9)
		if !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFakeAPI(t)
		f.delay = 100 * time.Millisecond
		_, err := f.client(10*time.Millisecond).Policy(context.Background(), 9)
		if err == nil {
			t.Fatal("timeout was ignored")
		}
	})
}

func TestClientRedactsSecretsFromAPIErrors(t *testing.T) {
	f := newFakeAPI(t)
	f.authFailure = true
	// 模拟不可信 API 把请求中的凭据回显到错误消息。
	f.authErrorMessage = "access key test-secret was rejected"
	_, err := f.client(time.Second).Policy(context.Background(), 9)
	if err == nil || strings.Contains(err.Error(), "test-secret") {
		t.Fatalf("error was not redacted: %v", err)
	}
}

func serverFixture(t *testing.T, id int64, names []ServerName, policyID int64) serverResponse {
	t.Helper()
	namesJSON, _ := json.Marshal(names)
	httpsJSON, _ := json.Marshal(httpsConfig{IsOn: true, SSLPolicyRef: &SSLPolicyRef{IsOn: true, SSLPolicyID: policyID}})
	return serverResponse{ID: id, ServerNamesJSON: namesJSON, HTTPSJSON: httpsJSON}
}

func inputConfig(input CertificateInput) CertificateConfig {
	return CertificateConfig{ID: input.ID, IsOn: input.IsOn, Name: input.Name, Description: input.Description,
		CertData: input.CertData, KeyData: input.KeyData, ServerName: input.ServerName, IsCA: input.IsCA,
		TimeBeginAt: input.TimeBeginAt, TimeEndAt: input.TimeEndAt, DNSNames: input.DNSNames, CommonNames: input.CommonNames}
}

func decodeBody(t *testing.T, r *http.Request, value any) {
	t.Helper()
	if err := json.NewDecoder(r.Body).Decode(value); err != nil {
		t.Error(err)
	}
}

func writeEnvelope(t *testing.T, w http.ResponseWriter, code int, message string, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "data": data}); err != nil {
		t.Error(err)
	}
}
