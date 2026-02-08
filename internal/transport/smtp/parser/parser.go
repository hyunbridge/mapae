package parser

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"regexp"
	"strings"
)

const nonceHexLength = 64

var (
	carrierDomains = map[string]string{
		"vmms.nate.com":       "SKT",
		"mmsmail.uplus.co.kr": "LGU+",
		"mms.kt.co.kr":        "KT",
	}
	nonceRe = regexp.MustCompile(fmt.Sprintf(`(?i)\[MAPAE:([0-9a-f]{%d})\]`, nonceHexLength))
	phoneRe = regexp.MustCompile(`([0-9-]{9,13})@([A-Za-z0-9.-]+)`)
)

func IsValidNonce(value string) bool {
	if len(value) != nonceHexLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F') {
			continue
		}
		return false
	}
	return true
}

func normalizeDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ExtractPhoneAndCarrier(fromAddress string) (*string, *string) {
	if strings.TrimSpace(fromAddress) == "" {
		return nil, nil
	}
	matches := phoneRe.FindStringSubmatch(fromAddress)
	if len(matches) < 3 {
		return nil, nil
	}
	phone := normalizeDigits(matches[1])
	domain := strings.ToLower(matches[2])
	carrier, ok := carrierDomains[domain]
	if !ok {
		return &phone, nil
	}
	return &phone, &carrier
}

func ParseBody(raw []byte) (string, map[string]string) {
	headerBytes, bodyBytes := SplitHeaderBody(raw)
	headers := parseHeaders(headerBytes)
	bodyText := extractTextFromBody(bodyBytes, headers, 0)
	if bodyText == "" {
		bodyText = decodeASCII(raw)
	}
	return bodyText, headers
}

func ExtractHeaderFromRaw(raw []byte) string {
	text := decodeASCII(raw)
	lines := strings.Split(text, "\n")
	var currentName string
	var currentValue strings.Builder
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if currentName != "" {
				currentValue.WriteString(" ")
				currentValue.WriteString(strings.TrimSpace(line))
			}
			continue
		}
		if strings.EqualFold(currentName, "from") {
			return strings.TrimSpace(currentValue.String())
		}
		currentName = ""
		currentValue.Reset()
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			currentName = strings.TrimSpace(parts[0])
			currentValue.WriteString(strings.TrimSpace(parts[1]))
		}
	}
	if strings.EqualFold(currentName, "from") {
		return strings.TrimSpace(currentValue.String())
	}
	return ""
}

func findNonce(text string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	match := nonceRe.FindStringSubmatch(text)
	if len(match) < 2 {
		return ""
	}
	if !IsValidNonce(match[1]) {
		return ""
	}
	return match[1]
}

func FindNonceWithFallback(bodyText string, body []byte) string {
	if nonce := findNonce(bodyText); nonce != "" {
		return nonce
	}
	if nonce := findNonce(decodeASCII(body)); nonce != "" {
		return nonce
	}
	if decoded := decodeQuotedPrintable(body); len(decoded) > 0 {
		if nonce := findNonce(decodeASCII(decoded)); nonce != "" {
			return nonce
		}
	}
	if decoded := decodeBase64(body); len(decoded) > 0 {
		if nonce := findNonce(decodeASCII(decoded)); nonce != "" {
			return nonce
		}
	}
	return ""
}

func SplitHeaderBody(raw []byte) ([]byte, []byte) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, nil
}

func parseHeaders(raw []byte) map[string]string {
	headers := make(map[string]string)
	lines := strings.Split(string(raw), "\n")
	var lastKey string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			break
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if lastKey != "" {
				headers[lastKey] = strings.TrimSpace(headers[lastKey] + " " + strings.TrimSpace(line))
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		if existing, ok := headers[key]; ok {
			headers[key] = existing + ", " + value
		} else {
			headers[key] = value
		}
		lastKey = key
	}
	return headers
}

func extractTextFromBody(body []byte, headers map[string]string, depth int) string {
	if depth > 5 {
		return decodeASCII(body)
	}
	ctype, params := parseContentType(headers["content-type"])
	if strings.HasPrefix(ctype, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return ""
		}
		parts := splitMultipart(body, boundary)
		var texts []string
		for _, part := range parts {
			h, b := SplitHeaderBody(part)
			partHeaders := parseHeaders(h)
			text := extractTextFromBody(b, partHeaders, depth+1)
			if strings.TrimSpace(text) != "" {
				texts = append(texts, text)
			}
		}
		return strings.Join(texts, "\n")
	}
	decoded := decodeTransfer(body, headers["content-transfer-encoding"])
	if strings.HasPrefix(ctype, "text/") || ctype == "" {
		return decodeASCII(decoded)
	}
	return ""
}

func parseContentType(value string) (string, map[string]string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", map[string]string{}
	}
	parts := strings.Split(value, ";")
	mimeType := strings.ToLower(strings.TrimSpace(parts[0]))
	params := map[string]string{}
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			val := strings.TrimSpace(kv[1])
			val = strings.Trim(val, "\"")
			params[key] = val
		}
	}
	return mimeType, params
}

func splitMultipart(body []byte, boundary string) [][]byte {
	delim := []byte("--" + boundary)
	var parts [][]byte
	var current bytes.Buffer
	inPart := false
	reader := bytes.NewReader(body)
	buf := make([]byte, 0, 4096)
	for {
		line, err := readLineBytes(reader, &buf)
		if err != nil && err != io.EOF {
			break
		}
		if len(line) == 0 && err == io.EOF {
			break
		}
		trimmed := bytes.TrimRight(line, "\r\n")
		if bytes.HasPrefix(trimmed, delim) {
			if inPart && current.Len() > 0 {
				parts = append(parts, append([]byte(nil), current.Bytes()...))
				current.Reset()
			}
			if bytes.HasPrefix(trimmed, append(delim, []byte("--")...)) {
				break
			}
			inPart = true
			if err == io.EOF {
				break
			}
			continue
		}
		if inPart {
			current.Write(line)
		}
		if err == io.EOF {
			break
		}
	}
	if inPart && current.Len() > 0 {
		parts = append(parts, append([]byte(nil), current.Bytes()...))
	}
	return parts
}

func readLineBytes(r io.Reader, buf *[]byte) ([]byte, error) {
	*buf = (*buf)[:0]
	var tmp [1]byte
	for {
		n, err := r.Read(tmp[:])
		if n > 0 {
			*buf = append(*buf, tmp[0])
			if tmp[0] == '\n' {
				return *buf, err
			}
		}
		if err != nil {
			return *buf, err
		}
	}
}

func decodeTransfer(body []byte, encoding string) []byte {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "base64":
		if decoded := decodeBase64(body); len(decoded) > 0 {
			return decoded
		}
		return body
	case "quoted-printable":
		if decoded := decodeQuotedPrintable(body); len(decoded) > 0 {
			return decoded
		}
		return body
	default:
		return body
	}
}

func decodeASCII(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(data))
	for _, ch := range data {
		if ch < 0x80 {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func decodeBase64(body []byte) []byte {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, string(body))
	if cleaned == "" {
		return nil
	}
	if decoded, err := base64.StdEncoding.DecodeString(cleaned); err == nil {
		return decoded
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(cleaned); err == nil {
		return decoded
	}
	return nil
}

func decodeQuotedPrintable(body []byte) []byte {
	reader := quotedprintable.NewReader(bytes.NewReader(body))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return nil
	}
	return decoded
}
