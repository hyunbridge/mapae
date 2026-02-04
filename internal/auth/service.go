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

var authIDRe = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var ErrInvalidAuthID = errors.New("invalid_auth_id")

func New(store storage.Store, settings *config.Settings) *Service {
	return &Service{store: store, settings: settings}
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

func (s *Service) CheckAuth(ctx context.Context, authID string) (map[string]any, error) {
	if !authIDRe.MatchString(authID) {
		return nil, ErrInvalidAuthID
	}
	value, ok, err := s.store.Get(ctx, fmt.Sprintf("auth:%s", authID))
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]any{"status": "expired"}, nil
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return map[string]any{"status": "waiting"}, nil
	}
	if status, _ := decoded["status"].(string); status == "verified" {
		return decoded, nil
	}
	return map[string]any{"status": "waiting"}, nil
}

func (s *Service) LookupAuthIDByNonce(ctx context.Context, nonce string) (string, bool, error) {
	return s.store.Get(ctx, fmt.Sprintf("nonce:%s", nonce))
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
