package auth

import (
	"strings"
	"testing"
	"time"

	"mapae/internal/config"
)

func TestNormalizePEMString(t *testing.T) {
	raw := "\"-----BEGIN PRIVATE KEY-----\\nabc\\r\\ndef\\n-----END PRIVATE KEY-----\""
	got := normalizePEMString(raw)

	if strings.Contains(got, "\\n") || strings.Contains(got, "\"") {
		t.Fatalf("normalizePEMString did not normalize escapes/quotes: %q", got)
	}
	if !strings.Contains(got, "-----BEGIN PRIVATE KEY-----") || !strings.Contains(got, "-----END PRIVATE KEY-----") {
		t.Fatalf("normalizePEMString removed pem boundaries: %q", got)
	}
}

func TestNewJWTSignerOptionalAndTTLFallback(t *testing.T) {
	signer, err := newJWTSigner(&config.Settings{})
	if err != nil {
		t.Fatalf("newJWTSigner() error = %v", err)
	}
	if signer != nil {
		t.Fatalf("newJWTSigner() without key should return nil signer")
	}

	settings, _ := makeSettings(t, true)
	settings.JWTTTLSeconds = 0
	signer, err = newJWTSigner(settings)
	if err != nil {
		t.Fatalf("newJWTSigner() error = %v", err)
	}
	if signer == nil {
		t.Fatalf("newJWTSigner() should return signer when key exists")
	}
	if signer.exp != time.Hour {
		t.Fatalf("ttl fallback = %s, want 1h", signer.exp)
	}
}
