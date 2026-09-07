package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	legoacme "github.com/go-acme/lego/v4/acme"
	"github.com/go-acme/lego/v4/certificate"
	legoclient "github.com/go-acme/lego/v4/lego"
)

func TestIPv4NewOrderContainsIPIdentifierAndShortLivedProfile(t *testing.T) {
	request, err := obtainRequest("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"issue", "renew"} {
		t.Run(phase, func(t *testing.T) {
			captured := captureNewOrder(t, request)
			if len(captured.Identifiers) != 1 || captured.Identifiers[0].Type != "ip" || captured.Identifiers[0].Value != "8.8.8.8" {
				t.Fatalf("unexpected identifiers: %+v", captured.Identifiers)
			}
			if captured.Profile != "shortlived" {
				t.Fatalf("profile=%q, want shortlived", captured.Profile)
			}
		})
	}
}

func TestObtainRequestRejectsNonPublicIPv4(t *testing.T) {
	for _, value := range []string{"10.0.0.1", "2001:db8::1", "example.com", "::ffff:8.8.8.8"} {
		if _, err := obtainRequest(value); err == nil {
			t.Fatalf("%q unexpectedly accepted", value)
		}
	}
}

func captureNewOrder(t *testing.T, request certificate.ObtainRequest) legoacme.Order {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{Email: "test@example.com", privateKey: key}
	var captured legoacme.Order
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/directory", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(t, w, http.StatusOK, legoacme.Directory{NewNonceURL: server.URL + "/nonce", NewAccountURL: server.URL + "/account", NewOrderURL: server.URL + "/new-order"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Replay-Nonce", "stage2-nonce")
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, r *http.Request) {
		var envelope struct {
			Payload string `json:"payload"`
		}
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Error(err)
			return
		}
		payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil || json.Unmarshal(payload, &captured) != nil {
			t.Errorf("decode JWS payload: %v", err)
			return
		}
		writeTestJSON(t, w, http.StatusBadRequest, legoacme.ProblemDetails{Type: "urn:ietf:params:acme:error:malformed", Detail: "capture complete", HTTPStatus: http.StatusBadRequest})
	})
	config := legoclient.NewConfig(account)
	config.CADirURL = server.URL + "/directory"
	client, err := legoclient.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Certificate.Obtain(request); err == nil {
		t.Fatal("fixture should stop after new-order")
	}
	return captured
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}
