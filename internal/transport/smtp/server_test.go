package smtp

import (
	"strings"
	"testing"

	smtpserver "github.com/emersion/go-smtp"

	"mapae/internal/config"
)

func TestReadData(t *testing.T) {
	payload := strings.Repeat("x", 20)

	data, over, err := readData(strings.NewReader(payload), 0)
	if err != nil {
		t.Fatalf("readData(limit=0) error = %v", err)
	}
	if over {
		t.Fatalf("readData(limit=0) should never mark over limit")
	}
	if string(data) != payload {
		t.Fatalf("readData(limit=0) = %q", string(data))
	}

	data, over, err = readData(strings.NewReader(payload), 10)
	if err != nil {
		t.Fatalf("readData(limit=10) error = %v", err)
	}
	if !over {
		t.Fatalf("readData(limit=10) should mark over-limit")
	}
	if len(data) != 10 {
		t.Fatalf("truncated length = %d, want 10", len(data))
	}
}

func TestSanitizeSender(t *testing.T) {
	if got := sanitizeSender("Display <user@example.com>"); got != "user@example.com" {
		t.Fatalf("sanitizeSender parsed = %q", got)
	}
	if got := sanitizeSender("<>"); got != "" {
		t.Fatalf("sanitizeSender null sender = %q", got)
	}
	if got := sanitizeSender(" raw@example.com "); got != "raw@example.com" {
		t.Fatalf("sanitizeSender trimmed = %q", got)
	}
}

func TestMaskEmailLocalPart(t *testing.T) {
	if got := maskEmailLocalPart("Display <user@example.com>"); got != "***@example.com" {
		t.Fatalf("maskEmailLocalPart parsed = %q", got)
	}
	if got := maskEmailLocalPart("no-at-symbol"); got != "no-at-symbol" {
		t.Fatalf("maskEmailLocalPart passthrough = %q", got)
	}
	if got := maskEmailLocalPart("user@"); got != "***" {
		t.Fatalf("maskEmailLocalPart empty domain = %q", got)
	}
}

func TestExtractDomain(t *testing.T) {
	if got := extractDomain("Display <USER@Example.COM>"); got != "example.com" {
		t.Fatalf("extractDomain parsed = %q", got)
	}
	if got := extractDomain("   "); got != "" {
		t.Fatalf("extractDomain blank = %q", got)
	}
	if got := extractDomain("invalid-address"); got != "" {
		t.Fatalf("extractDomain invalid = %q", got)
	}
}

func TestSessionRcpt(t *testing.T) {
	sess := &session{server: &Server{settings: &config.Settings{SMSInboundAddress: "verify@example.com"}}}

	if err := sess.Rcpt("verify@example.com", nil); err != nil {
		t.Fatalf("Rcpt() for inbound address error = %v", err)
	}
	if len(sess.rcptTos) != 1 || sess.rcptTos[0] != "verify@example.com" {
		t.Fatalf("rcptTos = %#v", sess.rcptTos)
	}

	err := sess.Rcpt("blocked@example.com", nil)
	if err == nil {
		t.Fatalf("Rcpt() should reject non-inbound address")
	}
	smtpErr, ok := err.(*smtpserver.SMTPError)
	if !ok {
		t.Fatalf("Rcpt() error type = %T, want *SMTPError", err)
	}
	if smtpErr.Code != 550 {
		t.Fatalf("SMTP error code = %d, want 550", smtpErr.Code)
	}
}
