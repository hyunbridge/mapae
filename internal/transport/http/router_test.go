package httpapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"mapae/internal/auth"
	"mapae/internal/config"
	"mapae/internal/logging"
	"mapae/internal/storage/memory"
)

func makeHTTPServer(t *testing.T, withSigner bool) (*Server, *auth.Service) {
	t.Helper()

	settings := &config.Settings{
		CORSAllowOrigins:   []string{"https://allowed.example"},
		AuthTTLSeconds:     60,
		VerifiedTTLSeconds: 30,
		SMSInboundAddress:  "verify@example.com",
		JWTIssuer:          "https://issuer.example",
		JWTTTLSeconds:      120,
	}
	if withSigner {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey() error = %v", err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
		}
		settings.JWTPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	}

	store, err := memory.New()
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	authSvc, err := auth.New(store, settings)
	if err != nil {
		t.Fatalf("auth.New() error = %v", err)
	}
	logger := logging.New("test: ", false)
	return NewServer(settings, authSvc, logger), authSvc
}

func request(t *testing.T, h http.Handler, method, path, origin string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestHealthAndCORS(t *testing.T) {
	s, _ := makeHTTPServer(t, false)
	h := s.Handler()

	opt := request(t, h, http.MethodOptions, "/auth/init", "https://allowed.example")
	if opt.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS status = %d, want 204", opt.Code)
	}
	if got := opt.Header().Get("Access-Control-Allow-Origin"); got != "https://allowed.example" {
		t.Fatalf("allowed origin header = %q", got)
	}

	health := request(t, h, http.MethodGet, "/health", "https://blocked.example")
	if health.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", health.Code)
	}
	if got := health.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("disallowed origin should not be echoed, got %q", got)
	}

	var body HealthResponse
	if err := json.Unmarshal(health.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if body.Status != "ok" || body.Storage != "up" {
		t.Fatalf("unexpected health response: %#v", body)
	}
}

func TestAuthEndpointsWithoutSigner(t *testing.T) {
	s, authSvc := makeHTTPServer(t, false)
	h := s.Handler()

	initResp := request(t, h, http.MethodPost, "/auth/init", "")
	if initResp.Code != http.StatusOK {
		t.Fatalf("POST /auth/init status = %d, want 200", initResp.Code)
	}

	var initBody auth.AuthInitResponse
	if err := json.Unmarshal(initResp.Body.Bytes(), &initBody); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if ok, _ := regexp.MatchString(`^[0-9a-f]{32}$`, initBody.AuthID); !ok {
		t.Fatalf("unexpected auth id: %q", initBody.AuthID)
	}

	waiting := request(t, h, http.MethodGet, "/auth/check/"+initBody.AuthID, "")
	if waiting.Code != http.StatusOK {
		t.Fatalf("GET /auth/check status = %d, want 200", waiting.Code)
	}

	var waitingBody auth.AuthCheckResponse
	if err := json.Unmarshal(waiting.Body.Bytes(), &waitingBody); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if waitingBody.Status != "waiting" {
		t.Fatalf("status = %q, want waiting", waitingBody.Status)
	}

	nonceRe := regexp.MustCompile(`\[MAPAE:([0-9a-fA-F]{64})\]`)
	match := nonceRe.FindStringSubmatch(initBody.SMSBody)
	if len(match) < 2 {
		t.Fatalf("failed to parse nonce from %q", initBody.SMSBody)
	}
	consumedAuthID, ok, err := authSvc.ConsumeAuthIDByNonce(context.Background(), match[1])
	if err != nil {
		t.Fatalf("ConsumeAuthIDByNonce() error = %v", err)
	}
	if !ok || consumedAuthID != initBody.AuthID {
		t.Fatalf("consume mismatch: authID=%q ok=%t", consumedAuthID, ok)
	}
	phone := "01012345678"
	carrier := "KT"
	if err := authSvc.StoreVerified(context.Background(), initBody.AuthID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	verified := request(t, h, http.MethodGet, "/auth/check/"+initBody.AuthID, "")
	if verified.Code != http.StatusOK {
		t.Fatalf("GET /auth/check (verified) status = %d, want 200", verified.Code)
	}

	signed := request(t, h, http.MethodGet, "/auth/check-signed/"+initBody.AuthID, "")
	if signed.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /auth/check-signed status = %d, want 503", signed.Code)
	}

	jwks := request(t, h, http.MethodGet, "/.well-known/jwks.json", "")
	if jwks.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /.well-known/jwks.json status = %d, want 503", jwks.Code)
	}

	badID := request(t, h, http.MethodGet, "/auth/check/not-valid", "")
	if badID.Code != http.StatusBadRequest {
		t.Fatalf("GET /auth/check/not-valid status = %d, want 400", badID.Code)
	}
}

func TestSignedEndpointAndJWKSWithSigner(t *testing.T) {
	s, authSvc := makeHTTPServer(t, true)
	h := s.Handler()

	initResp := request(t, h, http.MethodPost, "/auth/init", "")
	if initResp.Code != http.StatusOK {
		t.Fatalf("POST /auth/init status = %d, want 200", initResp.Code)
	}
	var initBody auth.AuthInitResponse
	if err := json.Unmarshal(initResp.Body.Bytes(), &initBody); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	nonceRe := regexp.MustCompile(`\[MAPAE:([0-9a-fA-F]{64})\]`)
	match := nonceRe.FindStringSubmatch(initBody.SMSBody)
	if len(match) < 2 {
		t.Fatalf("failed to parse nonce from %q", initBody.SMSBody)
	}
	_, _, _ = authSvc.ConsumeAuthIDByNonce(context.Background(), match[1])
	phone := "01088887777"
	carrier := "LGU+"
	if err := authSvc.StoreVerified(context.Background(), initBody.AuthID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	signed := request(t, h, http.MethodGet, "/auth/check-signed/"+initBody.AuthID, "")
	if signed.Code != http.StatusOK {
		t.Fatalf("GET /auth/check-signed status = %d, want 200", signed.Code)
	}
	var signedBody auth.AuthCheckResponse
	if err := json.Unmarshal(signed.Body.Bytes(), &signedBody); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if signedBody.Token == "" || signedBody.Status != "verified" {
		t.Fatalf("unexpected signed response: %#v", signedBody)
	}

	jwks := request(t, h, http.MethodGet, "/.well-known/jwks.json", "")
	if jwks.Code != http.StatusOK {
		t.Fatalf("GET /.well-known/jwks.json status = %d, want 200", jwks.Code)
	}
	if ct := jwks.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("jwks content-type = %q", ct)
	}
	if !strings.Contains(jwks.Body.String(), "Ed25519") {
		t.Fatalf("unexpected jwks response: %s", jwks.Body.String())
	}
}
