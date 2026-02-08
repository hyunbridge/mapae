package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"mapae/internal/config"
)

type jwtSigner struct {
	priv ed25519.PrivateKey
	iss  string
	exp  time.Duration
}

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

func newJWTSigner(settings *config.Settings) (*jwtSigner, error) {
	var pemBytes []byte
	switch {
	case settings.JWTPrivateKeyPEM != "":
		pemBytes = []byte(normalizePEMString(settings.JWTPrivateKeyPEM))
	default:
		// 키 설정이 없을 때 기존 API 호환성을 위해 signer를 선택 사항으로 처리
		return nil, nil
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid pem for jwt private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ed25519 private key: %w", err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ed25519")
	}
	ttl := time.Duration(settings.JWTTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &jwtSigner{priv: key, iss: settings.JWTIssuer, exp: ttl}, nil
}

func normalizePEMString(raw string) string {
	value := strings.TrimSpace(raw)

	// 일부 환경 변수 로더가 따옴표를 리터럴 문자로 남겨두는 경우 처리
	for len(value) >= 2 {
		if value[0] == '"' && value[len(value)-1] == '"' {
			value = strings.TrimSpace(value[1 : len(value)-1])
			continue
		}
		if value[0] == '\'' && value[len(value)-1] == '\'' {
			value = strings.TrimSpace(value[1 : len(value)-1])
			continue
		}
		break
	}

	// 셸 스타일(\n) 및 도커 환경 파일 스타일(\\n)의 이스케이프된 줄바꿈 허용
	replacer := strings.NewReplacer(
		"\\\\r\\\\n", "\n",
		"\\\\n", "\n",
		"\\\\r", "\n",
		"\\r\\n", "\n",
		"\\n", "\n",
		"\\r", "\n",
		"\r\n", "\n",
		"\r", "\n",
	)
	return replacer.Replace(value)
}

func (s *jwtSigner) Sign(authID, phoneNumber, carrier, jti string) (string, error) {
	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":          s.iss,
		"sub":          phoneNumber,
		"auth_id":      authID,
		"iat":          now.Unix(),
		"exp":          now.Add(s.exp).Unix(),
		"phone_number": phoneNumber,
		"carrier":      carrier,
		"jti":          jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	return token.SignedString(s.priv)
}

func (s *jwtSigner) JWKS() ([]byte, error) {
	pub := s.priv.Public().(ed25519.PublicKey)
	key := jwkKey{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString([]byte(pub)),
		Use: "sig",
		Alg: "EdDSA",
	}
	resp := jwksResponse{Keys: []jwkKey{key}}
	return json.Marshal(resp)
}
