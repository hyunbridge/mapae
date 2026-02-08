package parser

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestIsValidNonce(t *testing.T) {
	good := strings.Repeat("a", nonceHexLength)
	if !IsValidNonce(good) {
		t.Fatalf("expected valid nonce")
	}
	if IsValidNonce(good+"0") {
		t.Fatalf("nonce with invalid length should fail")
	}
	if IsValidNonce(good[:63] + "z") {
		t.Fatalf("nonce with non-hex char should fail")
	}
}

func TestExtractPhoneAndCarrier(t *testing.T) {
	phone, carrier := ExtractPhoneAndCarrier("010-1234-5678@mms.kt.co.kr")
	if phone == nil || *phone != "01012345678" {
		t.Fatalf("phone = %#v", phone)
	}
	if carrier == nil || *carrier != "KT" {
		t.Fatalf("carrier = %#v", carrier)
	}

	phone, carrier = ExtractPhoneAndCarrier("01011112222@example.com")
	if phone == nil || *phone != "01011112222" {
		t.Fatalf("phone for unknown carrier = %#v", phone)
	}
	if carrier != nil {
		t.Fatalf("carrier for unknown domain should be nil: %#v", carrier)
	}

	phone, carrier = ExtractPhoneAndCarrier("  ")
	if phone != nil || carrier != nil {
		t.Fatalf("blank sender should return nil,nil")
	}
}

func TestParseBodyMultipartBase64(t *testing.T) {
	nonce := strings.Repeat("a", nonceHexLength)
	text := "hello [MAPAE:" + nonce + "] world"
	enc := base64.StdEncoding.EncodeToString([]byte(text))
	raw := strings.Join([]string{
		"From: 010-1234-5678@mms.kt.co.kr",
		"Content-Type: multipart/mixed; boundary=abc",
		"",
		"--abc",
		"Content-Type: text/plain; charset=utf-8",
		"Content-Transfer-Encoding: base64",
		"",
		enc,
		"--abc--",
		"",
	}, "\r\n")

	body, headers := ParseBody([]byte(raw))
	if !strings.Contains(body, text) {
		t.Fatalf("decoded body = %q", body)
	}
	if headers["from"] != "010-1234-5678@mms.kt.co.kr" {
		t.Fatalf("from header = %q", headers["from"])
	}
}

func TestFindNonceWithFallback(t *testing.T) {
	nonce := strings.Repeat("b", nonceHexLength)
	encoded := base64.StdEncoding.EncodeToString([]byte("prefix [MAPAE:" + nonce + "] suffix"))

	got := FindNonceWithFallback("no nonce here", []byte(encoded))
	if got != nonce {
		t.Fatalf("FindNonceWithFallback = %q, want %q", got, nonce)
	}

	if got := FindNonceWithFallback("", []byte("nothing")); got != "" {
		t.Fatalf("FindNonceWithFallback should return empty when absent, got %q", got)
	}
}

func TestExtractHeaderFromRawAndSplitHeaderBody(t *testing.T) {
	raw := strings.Join([]string{
		"From: Sender",
		" \t<01012345678@mmsmail.uplus.co.kr>",
		"Subject: test",
		"",
		"body",
	}, "\n")

	gotFrom := ExtractHeaderFromRaw([]byte(raw))
	if !strings.Contains(gotFrom, "01012345678@mmsmail.uplus.co.kr") {
		t.Fatalf("ExtractHeaderFromRaw = %q", gotFrom)
	}

	header, body := SplitHeaderBody([]byte("A: b\r\n\r\nhello"))
	if string(header) != "A: b" || string(body) != "hello" {
		t.Fatalf("SplitHeaderBody unexpected result: header=%q body=%q", string(header), string(body))
	}
}
