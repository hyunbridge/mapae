package parser

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStreamExtractHeaderFromAndNoncePlain(t *testing.T) {
	nonce := strings.Repeat("c", nonceHexLength)
	msg := fmt.Sprintf("From: 01012345678@mms.kt.co.kr\r\nContent-Type: text/plain\r\n\r\nhello [MAPAE:%s]", nonce)

	from, gotNonce, n, err := StreamExtractHeaderFromAndNonce(strings.NewReader(msg), 0)
	if err != nil {
		t.Fatalf("StreamExtractHeaderFromAndNonce() error = %v", err)
	}
	if from != "01012345678@mms.kt.co.kr" {
		t.Fatalf("from = %q", from)
	}
	if gotNonce != nonce {
		t.Fatalf("nonce = %q, want %q", gotNonce, nonce)
	}
	if n <= 0 {
		t.Fatalf("bytesRead = %d, want > 0", n)
	}
}

func TestStreamExtractHeaderFromAndNonceBase64(t *testing.T) {
	nonce := strings.Repeat("d", nonceHexLength)
	body := base64.StdEncoding.EncodeToString([]byte("[MAPAE:" + nonce + "]"))
	msg := "From: user@example.com\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		"  " + body + "\r\n"

	_, gotNonce, _, err := StreamExtractHeaderFromAndNonce(strings.NewReader(msg), 0)
	if err != nil {
		t.Fatalf("StreamExtractHeaderFromAndNonce() error = %v", err)
	}
	if gotNonce != nonce {
		t.Fatalf("nonce = %q, want %q", gotNonce, nonce)
	}
}

func TestStreamExtractHeaderFromAndNonceMessageTooLarge(t *testing.T) {
	nonce := strings.Repeat("e", nonceHexLength)
	msg := fmt.Sprintf("From: user@example.com\r\n\r\n[MAPAE:%s]", nonce)

	_, _, _, err := StreamExtractHeaderFromAndNonce(strings.NewReader(msg), 10)
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("error = %v, want ErrMessageTooLarge", err)
	}
}

func TestStreamExtractHeaderFromAndNonceNoNonce(t *testing.T) {
	msg := "From: user@example.com\r\n\r\nhello"
	from, nonce, _, err := StreamExtractHeaderFromAndNonce(strings.NewReader(msg), 0)
	if err != nil {
		t.Fatalf("StreamExtractHeaderFromAndNonce() error = %v", err)
	}
	if from != "user@example.com" {
		t.Fatalf("from = %q", from)
	}
	if nonce != "" {
		t.Fatalf("nonce should be empty, got %q", nonce)
	}
}
