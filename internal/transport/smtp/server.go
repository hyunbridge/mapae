package smtp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/mail"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	smtpserver "github.com/emersion/go-smtp"

	"mapae/internal/auth"
	"mapae/internal/config"
	"mapae/internal/logging"
	"mapae/internal/transport/smtp/parser"
)

type Server struct {
	settings *config.Settings
	auth     *auth.Service
	logger   *logging.Logger
	server   *smtpserver.Server
	baseCtx  context.Context
}

type backend struct {
	server *Server
}

type session struct {
	server    *Server
	mailFrom  string
	rcptTos   []string
	peerIP    net.IP
	connStart time.Time
	ctx       context.Context
}

func NewServer(settings *config.Settings, authService *auth.Service, logger *logging.Logger) *Server {
	return &Server{
		settings: settings,
		auth:     authService,
		logger:   logger,
	}
}

func (s *Server) Run(ctx context.Context) error {
	be := &backend{server: s}
	server := smtpserver.NewServer(be)
	server.Addr = fmt.Sprintf("%s:%d", s.settings.SMTPHost, s.settings.SMTPPort)
	server.Domain = "JOSEON DYNASTY MAPAE - Amhaeng-eosa Chuldo-ya!"
	server.ReadTimeout = 10 * time.Minute
	server.WriteTimeout = 10 * time.Minute
	server.MaxMessageBytes = int64(s.settings.DataSizeLimitBytes)
	server.MaxRecipients = 1
	server.AllowInsecureAuth = true
	s.server = server
	s.baseCtx = ctx
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	s.logger.Printf("SMTP server listening on %s", server.Addr)
	return server.ListenAndServe()
}

func (b *backend) NewSession(c *smtpserver.Conn) (smtpserver.Session, error) {
	var peerIP net.IP
	if c != nil {
		if nc := c.Conn(); nc != nil {
			if tcpAddr, ok := nc.RemoteAddr().(*net.TCPAddr); ok {
				peerIP = tcpAddr.IP
			}
		}
	}
	return &session{server: b.server, peerIP: peerIP, connStart: time.Now(), ctx: b.server.baseCtx}, nil
}

func (s *session) Mail(from string, _ *smtpserver.MailOptions) error {
	s.mailFrom = strings.TrimSpace(from)
	return nil
}

func (s *session) Rcpt(to string, _ *smtpserver.RcptOptions) error {
	inbound := strings.ToLower(strings.TrimSpace(s.server.settings.SMSInboundAddress))
	if inbound != "" && strings.ToLower(strings.TrimSpace(to)) != inbound {
		return &smtpserver.SMTPError{Code: 550, Message: "Not relaying to that address"}
	}
	s.rcptTos = append(s.rcptTos, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	data, overLimit, err := readData(r, s.server.settings.DataSizeLimitBytes)
	if err != nil {
		return err
	}
	if overLimit {
		s.server.logger.Printf("Message too large (limit=%d bytes)", s.server.settings.DataSizeLimitBytes)
		return &smtpserver.SMTPError{Code: 552, Message: "Message size exceeds limit"}
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// 연결이 끊겨도 Downstream(SPF/DB) 작업이 10초 후 종료되도록 제한
	opCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.server.handleData(opCtx, s, data)
}

func (s *session) Reset() {
	s.mailFrom = ""
	s.rcptTos = nil
}

func (s *session) Logout() error {
	return nil
}

func (s *session) AuthPlain(username, password string) error {
	return smtpserver.ErrAuthUnsupported
}

func (s *Server) handleData(ctx context.Context, sess *session, raw []byte) error {
	mailFrom := sess.mailFrom
	peerIP := sess.peerIP
	rcptList := strings.Join(sess.rcptTos, ",")
	maskedMailFrom := maskEmailLocalPart(mailFrom)
	result := "fail"
	authID := ""
	stored := false
	defer func() {
		ip := ""
		if peerIP != nil {
			ip = peerIP.String()
		}
		if authID == "" {
			authID = "-"
		}
		dur := time.Duration(0)
		if !sess.connStart.IsZero() {
			dur = time.Since(sess.connStart).Truncate(time.Millisecond)
		}
		if s.settings.Debug && mailFrom != "" {
			s.logger.Printf(`INFO:     smtp %s - "RCPT TO: %s" result=%s auth_id=%s stored=%t mail_from=%s dur=%s`, ip, rcptList, result, authID, stored, mailFrom, dur)
			return
		}
		s.logger.Printf(`INFO:     smtp %s - "RCPT TO: %s" result=%s stored=%t mail_from=%s dur=%s`, ip, rcptList, result, stored, maskedMailFrom, dur)
	}()

	bodyText, headers := parser.ParseBody(raw)
	headerFrom := headers["from"]
	_, bodyBytes := parser.SplitHeaderBody(raw)
	if headerFrom == "" {
		headerFrom = parser.ExtractHeaderFromRaw(raw)
	}

	envPhone, envCarrier := parser.ExtractPhoneAndCarrier(mailFrom)
	hdrPhone, hdrCarrier := parser.ExtractPhoneAndCarrier(headerFrom)

	envSPFOK := false
	hdrSPFOK := false
	var envResult spf.Result
	var hdrResult spf.Result
	var envErr error
	var hdrErr error
	if peerIP != nil {
		spfCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		opts := []spf.Option{spf.WithContext(spfCtx)}
		if mailFrom != "" {
			if sender := sanitizeSender(mailFrom); sender != "" {
				envResult, envErr = spf.CheckHostWithSender(peerIP, "", sender, opts...)
				envSPFOK = envResult == spf.Pass
				if envErr != nil && envResult != spf.Pass {
					s.logger.Printf("SPF env error: ip=%s sender=%s result=%s err=%v", peerIP.String(), sender, envResult, envErr)
				}
			}
		}
		if headerFrom != "" {
			if sender := sanitizeSender(headerFrom); sender != "" {
				hdrResult, hdrErr = spf.CheckHostWithSender(peerIP, "", sender, opts...)
				hdrSPFOK = hdrResult == spf.Pass
				if hdrErr != nil && hdrResult != spf.Pass {
					s.logger.Printf("SPF hdr error: ip=%s sender=%s result=%s err=%v", peerIP.String(), sender, hdrResult, hdrErr)
				}
			}
		}
		if !(envSPFOK || hdrSPFOK) {
			if envResult == spf.TempError || hdrResult == spf.TempError {
				s.logger.Printf("SPF temperror: ip=%s mail_from=%s header_from=%s", peerIP.String(), mailFrom, headerFrom)
				return &smtpserver.SMTPError{Code: 451, Message: "SPF temperror"}
			}
			s.logger.Printf("SPF fail: ip=%s mail_from=%s header_from=%s", peerIP.String(), mailFrom, headerFrom)
			return &smtpserver.SMTPError{Code: 550, Message: "SPF fail"}
		}
	}

	var phone *string
	var carrier *string
	if envCarrier != nil && (peerIP == nil || envSPFOK) {
		phone, carrier = envPhone, envCarrier
	} else if hdrCarrier != nil && (peerIP == nil || hdrSPFOK) {
		phone, carrier = hdrPhone, hdrCarrier
	}
	if carrier == nil {
		s.logger.Printf("Carrier domain not recognized")
		return &smtpserver.SMTPError{Code: 550, Message: "Invalid carrier domain"}
	}

	if s.settings.DumpInbound {
		s.logger.Printf("MAIL FROM: %s", mailFrom)
		if headerFrom != "" {
			s.logger.Printf("HEADER FROM: %s", headerFrom)
		}
		s.logger.Printf("RAW BYTES LEN: %d", len(raw))
		s.logger.Printf("BODY (decoded): %s", bodyText)
	}

	nonce := parser.FindNonceWithFallback(bodyText, bodyBytes)
	if nonce == "" {
		s.logger.Printf("Nonce not found in message body")
		return &smtpserver.SMTPError{Code: 550, Message: "Invalid nonce"}
	}

	authID, ok, err := s.auth.LookupAuthIDByNonce(ctx, nonce)
	if err != nil {
		s.logger.Printf("Store error while looking up nonce: %v", err)
		return &smtpserver.SMTPError{Code: 451, Message: "Temporary server error"}
	}
	if !ok {
		s.logger.Printf("Nonce not found or expired: %s", nonce)
		return &smtpserver.SMTPError{Code: 550, Message: "Invalid nonce"}
	}
	if err := s.auth.StoreVerified(ctx, authID, phone, carrier); err != nil {
		s.logger.Printf("Failed to store verification: %v", err)
		return &smtpserver.SMTPError{Code: 451, Message: "Temporary server error"}
	} else {
		s.logger.Printf("Stored verification for auth_id %s", authID)
		stored = true
		result = "pass"
	}

	return nil
}

func readData(r io.Reader, limit int) ([]byte, bool, error) {
	if limit <= 0 {
		data, err := io.ReadAll(r)
		return data, false, err
	}
	limited := io.LimitReader(r, int64(limit)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if len(data) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func sanitizeSender(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "<>" {
		return ""
	}
	if addr, err := mail.ParseAddress(trimmed); err == nil && addr.Address != "" {
		return addr.Address
	}
	return trimmed
}

func maskEmailLocalPart(value string) string {
	addr := value
	if parsed, err := mail.ParseAddress(value); err == nil && parsed.Address != "" {
		addr = parsed.Address
	}
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return addr
	}
	domain := addr[at+1:]
	if domain == "" {
		return "***"
	}
	return "***" + "@" + domain
}

func extractDomain(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || trimmed == "<>" {
		return ""
	}
	if addr, err := mail.ParseAddress(trimmed); err == nil {
		trimmed = addr.Address
	}
	at := strings.LastIndex(trimmed, "@")
	if at < 0 {
		return ""
	}
	domain := strings.TrimSpace(trimmed[at+1:])
	return strings.ToLower(domain)
}
