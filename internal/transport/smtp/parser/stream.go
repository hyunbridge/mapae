package parser

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

var ErrMessageTooLarge = errors.New("message_too_large")

type countingLimitReader struct {
	r     io.Reader
	limit int
	n     int
}

func (l *countingLimitReader) Read(p []byte) (int, error) {
	if l.limit > 0 {
		remain := (l.limit + 1) - l.n
		if remain <= 0 {
			return 0, ErrMessageTooLarge
		}
		if len(p) > remain {
			p = p[:remain]
		}
	}
	n, err := l.r.Read(p)
	l.n += n
	if l.limit > 0 && l.n > l.limit {
		return n, ErrMessageTooLarge
	}
	return n, err
}

type nonceScanner struct {
	state  int
	digits []byte
	found  string
}

func newNonceScanner() *nonceScanner {
	return &nonceScanner{digits: make([]byte, 0, nonceHexLength)}
}

func (s *nonceScanner) Found() bool { return s.found != "" }
func (s *nonceScanner) Nonce() string {
	return s.found
}

func (s *nonceScanner) reset() {
	s.state = 0
	s.digits = s.digits[:0]
}

func (s *nonceScanner) resetAndMaybeStart(b byte) {
	s.reset()
	// 현재 바이트가 '['이면 시작 상태로 재진입
	if b == '[' {
		s.state = 1
	}
}

func (s *nonceScanner) scanByte(b byte) {
	if s.found != "" {
		return
	}

	// 대소문자 구분 없이 "[MAPAE:" 패턴을 찾고, ']' 전까지 HEX 수집
	// 정확히 64자리 HEX일 때만 nonce로 인정
	switch s.state {
	case 0:
		if b == '[' {
			s.state = 1
		}
	case 1:
		if b == 'M' || b == 'm' {
			s.state = 2
		} else if b == '[' {
			s.state = 1
		} else {
			s.state = 0
		}
	case 2:
		if b == 'A' || b == 'a' {
			s.state = 3
		} else {
			s.resetAndMaybeStart(b)
		}
	case 3:
		if b == 'P' || b == 'p' {
			s.state = 4
		} else {
			s.resetAndMaybeStart(b)
		}
	case 4:
		if b == 'A' || b == 'a' {
			s.state = 5
		} else {
			s.resetAndMaybeStart(b)
		}
	case 5:
		if b == 'E' || b == 'e' {
			s.state = 6
		} else {
			s.resetAndMaybeStart(b)
		}
	case 6:
		if b == ':' {
			s.state = 7
			s.digits = s.digits[:0]
		} else {
			s.resetAndMaybeStart(b)
		}
	case 7:
		switch {
		case b == ']':
			if len(s.digits) == nonceHexLength {
				s.found = string(s.digits)
				return
			}
			s.reset()
		case b == ' ' || b == '\r' || b == '\n' || b == '\t':
			s.reset()
		case (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F'):
			if len(s.digits) >= nonceHexLength {
				s.reset()
				return
			}
			s.digits = append(s.digits, b)
		default:
			s.resetAndMaybeStart(b)
		}
	}
}

func (s *nonceScanner) Scan(p []byte) {
	for _, b := range p {
		s.scanByte(b)
		if s.found != "" {
			return
		}
	}
}

type whitespaceFilterReader struct {
	r       io.Reader
	scratch []byte
}

func newWhitespaceFilterReader(r io.Reader) *whitespaceFilterReader {
	return &whitespaceFilterReader{r: r, scratch: make([]byte, 4096)}
}

func (w *whitespaceFilterReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// 고정 크기 버퍼(재할당 오버헤드 방지)
	chunk := w.scratch
	if len(chunk) == 0 {
		chunk = make([]byte, 4096)
		w.scratch = chunk
	}
	if len(chunk) > len(p) {
		chunk = chunk[:len(p)]
	}

	for {
		n, err := w.r.Read(chunk)
		if n > 0 {
			j := 0
			for i := 0; i < n; i++ {
				b := chunk[i]
				if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
					continue
				}
				p[j] = b
				j++
			}

			// 공백만 들어온 경우에는 계속 읽음(단, 아래에서 에러가 올라오면 중단)
			if j == 0 && err == nil {
				continue
			}
			// 용량 제한 초과는 즉시 return
			if err != nil && errors.Is(err, ErrMessageTooLarge) {
				return j, err
			}
			// EOF/기타 에러는 데이터를 하나라도 만들었으면 우선 return
			if j > 0 {
				return j, nil
			}
			return 0, err
		}

		if err != nil {
			return 0, err
		}
	}
}

func scanDecoded(r io.Reader, sc *nonceScanner) error {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			sc.Scan(buf[:n])
			if sc.Found() {
				_, _ = io.Copy(io.Discard, r)
				return nil
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func scanLeafBody(raw io.Reader, cte string, sc *nonceScanner) error {
	if sc.Found() {
		_, _ = io.Copy(io.Discard, raw)
		return nil
	}

	cte = strings.ToLower(strings.TrimSpace(cte))
	switch cte {
	case "base64":
		dec := base64.NewDecoder(base64.StdEncoding, newWhitespaceFilterReader(raw))
		if err := scanDecoded(dec, sc); err != nil {
			if errors.Is(err, ErrMessageTooLarge) {
				return err
			}
			// 디코딩 실패 시에도 stream 끝까지 drain하여 multipart 파싱이 어긋나지 않게 함
			_, _ = io.Copy(io.Discard, raw)
			return nil
		}
		// nonce를 찾았더라도 stream은 끝까지 drain
		_, _ = io.Copy(io.Discard, raw)
		return nil
	case "quoted-printable":
		dec := quotedprintable.NewReader(raw)
		if err := scanDecoded(dec, sc); err != nil {
			if errors.Is(err, ErrMessageTooLarge) {
				return err
			}
			_, _ = io.Copy(io.Discard, raw)
			return nil
		}
		// nonce를 찾았더라도 stream은 끝까지 drain
		_, _ = io.Copy(io.Discard, raw)
		return nil
	default:
		return scanDecoded(raw, sc)
	}
}

func scanEntity(body io.Reader, header textproto.MIMEHeader, sc *nonceScanner, depth int) error {
	if depth > 5 {
		_, _ = io.Copy(io.Discard, body)
		return nil
	}

	ct := header.Get("Content-Type")
	cte := header.Get("Content-Transfer-Encoding")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}

	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") && params["boundary"] != "" {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			perr := scanEntity(part, part.Header, sc, depth+1)
			_ = part.Close()
			if perr != nil {
				return perr
			}
		}
	}

	return scanLeafBody(body, cte, sc)
}

// StreamExtractHeaderFromAndNonce는 MIME 헤더를 파싱하고, 메시지를 스트리밍으로 읽으며 MAPAE nonce(논스)를 찾음
// nonce(논스)를 찾았더라도 SMTP 세션이 꼬이지 않도록 본문은 끝까지 drain
//
// - limit > 0 이고 메시지가 이를 초과하면 ErrMessageTooLarge 반환
// - From 헤더가 없거나 파싱 불가하면 headerFrom은 빈 문자열일 수 있음
func StreamExtractHeaderFromAndNonce(r io.Reader, limit int) (headerFrom string, nonce string, bytesRead int, err error) {
	lr := &countingLimitReader{r: r, limit: limit}
	br := bufio.NewReader(lr)
	tr := textproto.NewReader(br)

	defer func() {
		// 제한 초과 이외의 케이스에서는 SMTP 세션을 계속 사용할 수 있도록 가능한 한 drain
		if err != nil && !errors.Is(err, ErrMessageTooLarge) {
			_, _ = io.Copy(io.Discard, br)
		}
	}()

	hdr, err := tr.ReadMIMEHeader()
	if err != nil {
		return "", "", lr.n, err
	}

	headerFrom = strings.TrimSpace(hdr.Get("From"))

	sc := newNonceScanner()
	// bufio.Reader를 그대로 본문 스트림으로 사용(이미 읽혀 버퍼에 남은 바이트 포함)
	if err := scanEntity(br, hdr, sc, 0); err != nil {
		return headerFrom, "", lr.n, err
	}

	return headerFrom, sc.Nonce(), lr.n, nil
}
