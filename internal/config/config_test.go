package config

import (
	"reflect"
	"testing"
)

func TestEnvBool(t *testing.T) {
	t.Setenv("BOOL_VAL", "yes")
	if got := envBool("BOOL_VAL", false); !got {
		t.Fatalf("envBool yes = false, want true")
	}

	t.Setenv("BOOL_VAL", "off")
	if got := envBool("BOOL_VAL", true); got {
		t.Fatalf("envBool off = true, want false")
	}

	t.Setenv("BOOL_VAL", "unknown")
	if got := envBool("BOOL_VAL", true); !got {
		t.Fatalf("envBool unknown should fall back to default")
	}

	if got := envBool("BOOL_MISSING", true); !got {
		t.Fatalf("envBool missing should use default")
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("INT_VAL", " 42 ")
	if got := envInt("INT_VAL", 7); got != 42 {
		t.Fatalf("envInt parsed = %d, want 42", got)
	}

	t.Setenv("INT_VAL", "abc")
	if got := envInt("INT_VAL", 7); got != 7 {
		t.Fatalf("envInt invalid = %d, want default 7", got)
	}

	if got := envInt("INT_MISSING", 9); got != 9 {
		t.Fatalf("envInt missing = %d, want default 9", got)
	}
}

func TestEnvList(t *testing.T) {
	def := []string{"*"}

	t.Setenv("LIST_VAL", "a, b, ,c")
	if got := envList("LIST_VAL", def); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Fatalf("envList csv = %#v", got)
	}

	t.Setenv("LIST_VAL", `["https://a.example","https://b.example"]`)
	if got := envList("LIST_VAL", def); !reflect.DeepEqual(got, []string{"https://a.example", "https://b.example"}) {
		t.Fatalf("envList json = %#v", got)
	}

	t.Setenv("LIST_VAL", "[]")
	if got := envList("LIST_VAL", def); !reflect.DeepEqual(got, def) {
		t.Fatalf("envList empty json should use default, got %#v", got)
	}

	t.Setenv("LIST_VAL", "  ")
	if got := envList("LIST_VAL", def); !reflect.DeepEqual(got, def) {
		t.Fatalf("envList blank should use default, got %#v", got)
	}
}

func TestLoadWithDefaultsAndOverrides(t *testing.T) {
	t.Setenv("DEBUG", "true")
	t.Setenv("USE_IN_MEMORY_STORE", "1")
	t.Setenv("REDIS_URL", "redis://localhost:6379/0")
	t.Setenv("DUMP_INBOUND", "true")
	t.Setenv("SMS_INBOUND_ADDRESS", "verify@carrier.test")
	t.Setenv("SMTP_HOST", "127.0.0.1")
	t.Setenv("SMTP_PORT", "2526")
	t.Setenv("HTTP_HOST", "127.0.0.1")
	t.Setenv("HTTP_PORT", "8080")
	t.Setenv("CORS_ALLOW_ORIGINS", "https://a.example,https://b.example")
	t.Setenv("AUTH_TTL_SECONDS", "60")
	t.Setenv("VERIFIED_TTL_SECONDS", "30")
	t.Setenv("JWT_PRIVATE_KEY", "test-key")
	t.Setenv("JWT_ISSUER", "https://issuer.example")
	t.Setenv("JWT_TTL_SECONDS", "120")

	s := Load()
	if !s.Debug || !s.UseInMemoryStore || !s.DumpInbound {
		t.Fatalf("boolean settings were not loaded correctly: %#v", s)
	}
	if s.RedisURL != "redis://localhost:6379/0" || s.SMSInboundAddress != "verify@carrier.test" {
		t.Fatalf("string settings were not loaded correctly: %#v", s)
	}
	if s.SMTPHost != "127.0.0.1" || s.SMTPPort != 2526 || s.HTTPHost != "127.0.0.1" || s.HTTPPort != 8080 {
		t.Fatalf("network settings were not loaded correctly: %#v", s)
	}
	if !reflect.DeepEqual(s.CORSAllowOrigins, []string{"https://a.example", "https://b.example"}) {
		t.Fatalf("origins = %#v", s.CORSAllowOrigins)
	}
	if s.AuthTTLSeconds != 60 || s.VerifiedTTLSeconds != 30 || s.JWTTTLSeconds != 120 {
		t.Fatalf("ttl settings were not loaded correctly: %#v", s)
	}
	if s.JWTPrivateKeyPEM != "test-key" || s.JWTIssuer != "https://issuer.example" {
		t.Fatalf("jwt settings were not loaded correctly: %#v", s)
	}
	if s.DataSizeLimitBytes != 128*1024 {
		t.Fatalf("DataSizeLimitBytes = %d, want %d", s.DataSizeLimitBytes, 128*1024)
	}
}
