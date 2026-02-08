package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"mapae/internal/config"
	"mapae/internal/storage/memory"
)

func makeSettings(t *testing.T, withSigner bool) (*config.Settings, ed25519.PublicKey) {
	t.Helper()

	settings := &config.Settings{
		AuthTTLSeconds:     60,
		VerifiedTTLSeconds: 30,
		SMSInboundAddress:  "verify@example.com",
		JWTIssuer:          "https://issuer.example",
		JWTTTLSeconds:      120,
	}
	if !withSigner {
		return settings, nil
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	settings.JWTPrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
	return settings, pub
}

func newService(t *testing.T, withSigner bool) (*Service, *memory.Client, ed25519.PublicKey) {
	t.Helper()
	settings, pub := makeSettings(t, withSigner)
	store, err := memory.New()
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}
	svc, err := New(store, settings)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return svc, store, pub
}

func TestRandomHex(t *testing.T) {
	value, err := randomHex(16)
	if err != nil {
		t.Fatalf("randomHex() error = %v", err)
	}
	if len(value) != 32 {
		t.Fatalf("len(randomHex(16)) = %d, want 32", len(value))
	}
	if ok, _ := regexp.MatchString(`^[0-9a-f]+$`, value); !ok {
		t.Fatalf("randomHex produced non-hex value: %q", value)
	}

	if _, err := randomHex(0); err == nil {
		t.Fatalf("randomHex(0) should fail")
	}
}

func TestNewReturnsErrorForInvalidPEM(t *testing.T) {
	store, err := memory.New()
	if err != nil {
		t.Fatalf("memory.New() error = %v", err)
	}

	_, err = New(store, &config.Settings{JWTPrivateKeyPEM: "not-a-pem"})
	if err == nil {
		t.Fatalf("expected error for invalid pem")
	}
}

func TestInitAuthAndVerifyFlow(t *testing.T) {
	svc, _, _ := newService(t, false)
	ctx := context.Background()

	initResp, err := svc.InitAuth(ctx)
	if err != nil {
		t.Fatalf("InitAuth() error = %v", err)
	}

	if ok, _ := regexp.MatchString(`^[0-9a-f]{32}$`, initResp.AuthID); !ok {
		t.Fatalf("AuthID has unexpected format: %q", initResp.AuthID)
	}
	if !strings.HasPrefix(initResp.SMSBody, "[MAPAE:") {
		t.Fatalf("unexpected SMS body: %q", initResp.SMSBody)
	}
	if initResp.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds = %d, want 60", initResp.TTLSeconds)
	}

	check, err := svc.CheckAuth(ctx, initResp.AuthID)
	if err != nil {
		t.Fatalf("CheckAuth() error = %v", err)
	}
	if check.Status != "waiting" {
		t.Fatalf("CheckAuth status = %q, want waiting", check.Status)
	}

	nonceRe := regexp.MustCompile(`\[MAPAE:([0-9a-fA-F]{64})\]`)
	match := nonceRe.FindStringSubmatch(initResp.SMSBody)
	if len(match) < 2 {
		t.Fatalf("failed to parse nonce from SMS body: %q", initResp.SMSBody)
	}

	authIDByNonce, ok, err := svc.ConsumeAuthIDByNonce(ctx, match[1])
	if err != nil {
		t.Fatalf("ConsumeAuthIDByNonce() error = %v", err)
	}
	if !ok || authIDByNonce != initResp.AuthID {
		t.Fatalf("ConsumeAuthIDByNonce() = (%q,%t), want (%q,true)", authIDByNonce, ok, initResp.AuthID)
	}

	_, ok, err = svc.ConsumeAuthIDByNonce(ctx, match[1])
	if err != nil {
		t.Fatalf("ConsumeAuthIDByNonce(second) error = %v", err)
	}
	if ok {
		t.Fatalf("nonce should be one-time consumable")
	}

	phone := "01012345678"
	carrier := "KT"
	if err := svc.StoreVerified(ctx, initResp.AuthID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	check, err = svc.CheckAuth(ctx, initResp.AuthID)
	if err != nil {
		t.Fatalf("CheckAuth() after verify error = %v", err)
	}
	if check.Status != "verified" || check.Phone != phone || check.Carrier != carrier || check.Timestamp == "" {
		t.Fatalf("unexpected verified response: %#v", check)
	}
}

func TestCheckAuthValidationAndFallbacks(t *testing.T) {
	svc, store, _ := newService(t, false)
	ctx := context.Background()

	if _, err := svc.CheckAuth(ctx, "bad-id"); err != ErrInvalidAuthID {
		t.Fatalf("CheckAuth invalid id error = %v, want ErrInvalidAuthID", err)
	}

	expiredID := strings.Repeat("a", 32)
	resp, err := svc.CheckAuth(ctx, expiredID)
	if err != nil {
		t.Fatalf("CheckAuth expired error = %v", err)
	}
	if resp.Status != "expired" {
		t.Fatalf("expired CheckAuth status = %q", resp.Status)
	}

	brokenID := strings.Repeat("b", 32)
	if err := store.SetEx(ctx, "auth:"+brokenID, "not-json", 60); err != nil {
		t.Fatalf("SetEx() error = %v", err)
	}
	resp, err = svc.CheckAuth(ctx, brokenID)
	if err != nil {
		t.Fatalf("CheckAuth broken payload error = %v", err)
	}
	if resp.Status != "waiting" {
		t.Fatalf("broken payload should map to waiting, got %q", resp.Status)
	}
}

func TestCheckSignedWithoutSignerAndJWKSUnavailable(t *testing.T) {
	svc, _, _ := newService(t, false)
	ctx := context.Background()
	authID := strings.Repeat("c", 32)
	phone := "01011112222"
	carrier := "SKT"
	if err := svc.StoreVerified(ctx, authID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	if _, err := svc.CheckSigned(ctx, authID); err != ErrJWKSUnavailable {
		t.Fatalf("CheckSigned() error = %v, want ErrJWKSUnavailable", err)
	}
	if _, err := svc.JWKS(); err != ErrJWKSUnavailable {
		t.Fatalf("JWKS() error = %v, want ErrJWKSUnavailable", err)
	}
}

func TestCheckSignedWithSignerIssuesTokenAndJWKS(t *testing.T) {
	svc, _, pub := newService(t, true)
	ctx := context.Background()
	authID := strings.Repeat("d", 32)
	phone := "01099998888"
	carrier := "LGU+"
	if err := svc.StoreVerified(ctx, authID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	resp, err := svc.CheckSigned(ctx, authID)
	if err != nil {
		t.Fatalf("CheckSigned() error = %v", err)
	}
	if resp.Token == "" || resp.Status != "verified" {
		t.Fatalf("unexpected signed response: %#v", resp)
	}

	parsed, err := jwt.Parse(resp.Token, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "EdDSA" {
			t.Fatalf("unexpected signing method: %s", token.Method.Alg())
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("signed jwt should be valid")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}
	if claims["auth_id"] != authID || claims["phone_number"] != phone || claims["carrier"] != carrier {
		t.Fatalf("unexpected claims: %#v", claims)
	}
	if claims["iss"] != "https://issuer.example" || claims["sub"] != phone {
		t.Fatalf("unexpected identity claims: %#v", claims)
	}

	jwtData, err := svc.JWKS()
	if err != nil {
		t.Fatalf("JWKS() error = %v", err)
	}
	if !strings.Contains(string(jwtData), "Ed25519") || !strings.Contains(string(jwtData), "EdDSA") {
		t.Fatalf("unexpected JWKS payload: %s", string(jwtData))
	}
}

func TestCheckSignedWaitingWhenPhoneMissing(t *testing.T) {
	svc, _, _ := newService(t, true)
	ctx := context.Background()
	authID := strings.Repeat("e", 32)

	if err := svc.StoreVerified(ctx, authID, nil, nil); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	resp, err := svc.CheckSigned(ctx, authID)
	if err != nil {
		t.Fatalf("CheckSigned() error = %v", err)
	}
	if resp.Status != "waiting" {
		t.Fatalf("CheckSigned status = %q, want waiting", resp.Status)
	}
}

func TestStoreVerifiedWritesRFC3339Timestamp(t *testing.T) {
	svc, _, _ := newService(t, false)
	ctx := context.Background()
	authID := strings.Repeat("f", 32)
	phone := "01012344321"
	carrier := "KT"

	if err := svc.StoreVerified(ctx, authID, &phone, &carrier); err != nil {
		t.Fatalf("StoreVerified() error = %v", err)
	}

	resp, err := svc.CheckAuth(ctx, authID)
	if err != nil {
		t.Fatalf("CheckAuth() error = %v", err)
	}
	if _, err := time.Parse(time.RFC3339, resp.Timestamp); err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", resp.Timestamp, err)
	}
}
