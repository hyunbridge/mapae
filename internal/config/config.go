package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

type Settings struct {
	Debug              bool
	UseInMemoryStore   bool
	RedisURL           string
	DumpInbound        bool
	SMSInboundAddress  string
	SMTPHost           string
	SMTPPort           int
	HTTPHost           string
	HTTPPort           int
	CORSAllowOrigins   []string
	AuthTTLSeconds     int
	VerifiedTTLSeconds int
	DataSizeLimitBytes int
	JWTPrivateKeyPEM   string
	JWTIssuer          string
	JWTTTLSeconds      int
}

func Load() *Settings {
	return &Settings{
		Debug:              envBool("DEBUG", false),
		UseInMemoryStore:   envBool("USE_IN_MEMORY_STORE", false),
		RedisURL:           envString("REDIS_URL", ""),
		DumpInbound:        envBool("DUMP_INBOUND", false),
		SMSInboundAddress:  envString("SMS_INBOUND_ADDRESS", "verify@example.com"),
		SMTPHost:           envString("SMTP_HOST", "0.0.0.0"),
		SMTPPort:           envInt("SMTP_PORT", 2525),
		HTTPHost:           envString("HTTP_HOST", "0.0.0.0"),
		HTTPPort:           envInt("HTTP_PORT", 8000),
		CORSAllowOrigins:   envList("CORS_ALLOW_ORIGINS", []string{"*"}),
		AuthTTLSeconds:     envInt("AUTH_TTL_SECONDS", 600),
		VerifiedTTLSeconds: envInt("VERIFIED_TTL_SECONDS", 300),
		DataSizeLimitBytes: 128 * 1024,
		JWTPrivateKeyPEM:   envString("JWT_PRIVATE_KEY", ""),
		JWTIssuer:          envString("JWT_ISSUER", "https://example.com"),
		JWTTTLSeconds:      envInt("JWT_TTL_SECONDS", 3600),
	}
}

func envString(key, def string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return def
}

func envBool(key string, def bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return def
	}
	return parsed
}

func envList(key string, def []string) []string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return def
	}
	if strings.HasPrefix(trimmed, "[") {
		var parsed []string
		if err := json.Unmarshal([]byte(trimmed), &parsed); err == nil && len(parsed) > 0 {
			return parsed
		}
		return def
	}
	parts := strings.Split(trimmed, ",")
	var out []string
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}
