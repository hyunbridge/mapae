package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"mapae/internal/config"
	"mapae/internal/storage"
)

type Service struct {
	store    storage.Store
	settings *config.Settings
	signer   *jwtSigner
}

type AuthInitResponse struct {
	AuthID     string `json:"auth_id"`
	SMSBody    string `json:"sms_body"`
	Link       string `json:"link"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type AuthPayload struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

type VerifiedPayload struct {
	Status    string `json:"status"`
	Phone     string `json:"phone,omitempty"`
	Carrier   string `json:"carrier,omitempty"`
	Timestamp string `json:"timestamp"`
}

type AuthCheckResponse struct {
	Status    string `json:"status"`
	Phone     string `json:"phone,omitempty"`
	Carrier   string `json:"carrier,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Token     string `json:"token,omitempty"`
}

var authIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var ErrInvalidAuthID = errors.New("invalid_auth_id")
var ErrJWKSUnavailable = errors.New("jwks_unavailable")

func New(store storage.Store, settings *config.Settings) (*Service, error) {
	svc := &Service{store: store, settings: settings}
	signer, err := newJWTSigner(settings)
	if err != nil {
		return nil, err
	}
	svc.signer = signer
	return svc, nil
}

func (s *Service) InitAuth(ctx context.Context) (*AuthInitResponse, error) {
	nonce, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	authID, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	payload := AuthPayload{
		Status:    "pending",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	authKey := fmt.Sprintf("auth:%s", authID)
	nonceKey := fmt.Sprintf("nonce:%s", nonce)
	if err := s.store.SetEx(ctx, authKey, string(payloadJSON), s.settings.AuthTTLSeconds); err != nil {
		return nil, err
	}
	if err := s.store.SetEx(ctx, nonceKey, authID, s.settings.AuthTTLSeconds); err != nil {
		return nil, err
	}
	smsBody := fmt.Sprintf("[MAPAE:%s]", nonce)
	return &AuthInitResponse{
		AuthID:     authID,
		SMSBody:    smsBody,
		Link:       fmt.Sprintf("sms:%s?body=%s", s.settings.SMSInboundAddress, smsBody),
		TTLSeconds: s.settings.AuthTTLSeconds,
	}, nil
}

func (s *Service) CheckAuth(ctx context.Context, authID string) (*AuthCheckResponse, error) {
	if !authIDRe.MatchString(authID) {
		return nil, ErrInvalidAuthID
	}
	value, ok, err := s.store.Get(ctx, fmt.Sprintf("auth:%s", authID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return &AuthCheckResponse{Status: "expired"}, nil
	}
	var decoded AuthCheckResponse
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return &AuthCheckResponse{Status: "waiting"}, nil
	}
	if decoded.Status == "verified" {
		return &decoded, nil
	}
	return &AuthCheckResponse{Status: "waiting"}, nil
}

func (s *Service) ConsumeAuthIDByNonce(ctx context.Context, nonce string) (string, bool, error) {
	return s.store.Take(ctx, fmt.Sprintf("nonce:%s", nonce))
}

func (s *Service) Ping(ctx context.Context) error {
	return s.store.Ping(ctx)
}

func (s *Service) StoreVerified(ctx context.Context, authID string, phone, carrier *string) error {
	payload := VerifiedPayload{
		Status:    "verified",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	if phone != nil {
		payload.Phone = *phone
	}
	if carrier != nil {
		payload.Carrier = *carrier
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("auth:%s", authID)
	return s.store.SetEx(ctx, key, string(payloadJSON), s.settings.VerifiedTTLSeconds)
}

func (s *Service) CheckSigned(ctx context.Context, authID string) (*AuthCheckResponse, error) {
	if !authIDRe.MatchString(authID) {
		return nil, ErrInvalidAuthID
	}
	value, ok, err := s.store.Get(ctx, fmt.Sprintf("auth:%s", authID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return &AuthCheckResponse{Status: "expired"}, nil
	}
	var decoded AuthCheckResponse
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return &AuthCheckResponse{Status: "waiting"}, nil
	}
	if decoded.Status != "verified" {
		return &AuthCheckResponse{Status: "waiting"}, nil
	}
	if s.signer == nil {
		return nil, ErrJWKSUnavailable
	}
	if decoded.Phone == "" {
		return &AuthCheckResponse{Status: "waiting"}, nil
	}
	token, err := s.signer.Sign(authID, decoded.Phone, decoded.Carrier, authID)
	if err != nil {
		return nil, err
	}
	decoded.Token = token
	return &decoded, nil
}

func (s *Service) JWKS() ([]byte, error) {
	if s.signer == nil {
		return nil, ErrJWKSUnavailable
	}
	return s.signer.JWKS()
}

func randomHex(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		return "", errors.New("invalid length")
	}
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
