package goedge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type staticCredentials struct{ value Credentials }

func (s staticCredentials) Credentials() (Credentials, error) { return s.value, nil }

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
		var request struct {
			SSLPolicyID       int64    `json:"sslPolicyId"`
			HTTP2Enabled      bool     `json:"http2Enabled"`
			HTTP3Enabled      bool     `json:"http3Enabled"`
			MinVersion        string   `json:"minVersion"`
			SSLCertsJSON      []byte   `json:"sslCertsJSON"`
			HSTSJSON          []byte   `json:"hstsJSON"`
			ClientAuthType    int32    `json:"clientAuthType"`
			ClientCACertsJSON []byte   `json:"clientCACertsJSON"`
			CipherSuites      []string `json:"cipherSuites"`
			CipherSuitesIsOn  bool     `json:"cipherSuitesIsOn"`
			OCSPIsOn          bool     `json:"ocspIsOn"`
		}
		decodeBody(f.t, r, &request)
		var refs, caRefs []SSLCertRef
		_ = json.Unmarshal(request.SSLCertsJSON, &refs)
		_ = json.Unmarshal(request.ClientCACertsJSON, &caRefs)
		f.policy = SSLPolicy{ID: request.SSLPolicyID, IsOn: true, CertRefs: refs, ClientAuthType: request.ClientAuthType,
			ClientCARefs: caRefs, MinVersion: request.MinVersion, CipherSuitesIsOn: request.CipherSuitesIsOn,
			CipherSuites: request.CipherSuites, HSTS: request.HSTSJSON, HTTP2Enabled: request.HTTP2Enabled,
			HTTP3Enabled: request.HTTP3Enabled, OCSPIsOn: request.OCSPIsOn}
		f.policyWrites++
		writeEnvelope(f.t, w, 200, "ok", map[string]any{})
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

func TestBindCertificatePreservesPolicyAndDetectsRace(t *testing.T) {
	f := newFakeAPI(t)
	original := f.policy
	already, err := f.client(time.Second).BindCertificate(context.Background(), 9, 11)
	if err != nil || already || f.policyWrites != 1 || !f.policy.ContainsCert(11) {
		t.Fatalf("already=%v err=%v writes=%d policy=%+v", already, err, f.policyWrites, f.policy)
	}
	if f.policy.MinVersion != original.MinVersion || !reflect.DeepEqual(f.policy.ClientCARefs, original.ClientCARefs) || !reflect.DeepEqual(f.policy.HSTS, original.HSTS) {
		t.Fatal("policy fields were overwritten")
	}
	f2 := newFakeAPI(t)
	f2.mutateOnRead = 2
	_, err = f2.client(time.Second).BindCertificate(context.Background(), 9, 11)
	if !errors.Is(err, ErrPolicyDrift) || f2.policyWrites != 0 {
		t.Fatalf("race err=%v writes=%d", err, f2.policyWrites)
	}
	f3 := newFakeAPI(t)
	f3.policy.CertRefs = append(f3.policy.CertRefs, SSLCertRef{IsOn: false, CertID: 11})
	if _, err := f3.client(time.Second).BindCertificate(context.Background(), 9, 11); err == nil || f3.policyWrites != 0 {
		t.Fatalf("disabled target ref was overwritten: err=%v writes=%d", err, f3.policyWrites)
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
