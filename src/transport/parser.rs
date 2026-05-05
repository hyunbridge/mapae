use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};

use base64::{engine::general_purpose::STANDARD, read::DecoderReader};

const NONCE_HEX_LENGTH: usize = 64;
const MAX_MIME_DEPTH: usize = 5;
const READ_BUFFER_SIZE: usize = 4096;

#[derive(Debug)]
struct MessageTooLarge;

impl fmt::Display for MessageTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("message too large")
    }
}

impl Error for MessageTooLarge {}

/// I/O 오류가 메시지 크기 제한 초과를 의미하는지 확인합니다.
pub fn is_message_too_large(err: &io::Error) -> bool {
    err.kind() == ErrorKind::Other
        && err
            .get_ref()
            .is_some_and(|cause| cause.is::<MessageTooLarge>())
}

struct CountingLimitReader<R> {
    inner: R,
    limit: usize,
    bytes_read: usize,
}

impl<R> CountingLimitReader<R> {
    fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
        }
    }

    fn bytes_read(&self) -> usize {
        self.bytes_read
    }
}

impl<R: Read> Read for CountingLimitReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.limit == 0 {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "byte limit must be greater than zero",
            ));
        }

        let mut max_len = buf.len();
        let remaining = self.limit.saturating_add(1).saturating_sub(self.bytes_read);
        if remaining == 0 {
            return Err(io::Error::other(MessageTooLarge));
        }
        max_len = max_len.min(remaining);

        let n = self.inner.read(&mut buf[..max_len])?;
        self.bytes_read += n;
        if self.bytes_read > self.limit {
            return Err(io::Error::other(MessageTooLarge));
        }

        Ok(n)
    }
}

#[derive(Debug, Default)]
struct MimeHeaders {
    fields: Vec<(String, String)>,
}

impl MimeHeaders {
    fn get(&self, key: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Default)]
struct ContentTypeHeader {
    media_type: String,
    params: BTreeMap<String, String>,
}

struct NonceScanner {
    state: u8,
    digits: Vec<u8>,
    found: Option<String>,
}

impl NonceScanner {
    fn new() -> Self {
        Self {
            state: 0,
            digits: Vec::with_capacity(NONCE_HEX_LENGTH),
            found: None,
        }
    }

    fn found(&self) -> bool {
        self.found.is_some()
    }

    fn nonce(&self) -> String {
        self.found.clone().unwrap_or_default()
    }

    fn reset(&mut self) {
        self.state = 0;
        self.digits.clear();
    }

    fn reset_and_maybe_start(&mut self, b: u8) {
        self.reset();
        if b == b'[' {
            self.state = 1;
        }
    }

    fn scan_byte(&mut self, b: u8) {
        if self.found.is_some() {
            return;
        }

        match self.state {
            0 => {
                if b == b'[' {
                    self.state = 1;
                }
            }
            1 => {
                if b.eq_ignore_ascii_case(&b'M') {
                    self.state = 2;
                } else if b == b'[' {
                    self.state = 1;
                } else {
                    self.state = 0;
                }
            }
            2 => {
                if b.eq_ignore_ascii_case(&b'A') {
                    self.state = 3;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            3 => {
                if b.eq_ignore_ascii_case(&b'P') {
                    self.state = 4;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            4 => {
                if b.eq_ignore_ascii_case(&b'A') {
                    self.state = 5;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            5 => {
                if b.eq_ignore_ascii_case(&b'E') {
                    self.state = 6;
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            6 => {
                if b == b':' {
                    self.state = 7;
                    self.digits.clear();
                } else {
                    self.reset_and_maybe_start(b);
                }
            }
            7 => match b {
                b']' => {
                    if self.digits.len() == NONCE_HEX_LENGTH {
                        self.found = Some(String::from_utf8_lossy(&self.digits).into_owned());
                    }
                    self.reset();
                }
                b' ' | b'\r' | b'\n' | b'\t' => self.reset(),
                b if b.is_ascii_hexdigit() => {
                    if self.digits.len() >= NONCE_HEX_LENGTH {
                        self.reset();
                        return;
                    }
                    self.digits.push(b);
                }
                _ => self.reset_and_maybe_start(b),
            },
            _ => self.reset(),
        }
    }

    fn scan(&mut self, data: &[u8]) {
        for &b in data {
            self.scan_byte(b);
            if self.found() {
                return;
            }
        }
    }
}

struct WhitespaceFilterReader<R> {
    inner: R,
    scratch: [u8; READ_BUFFER_SIZE],
}

impl<R> WhitespaceFilterReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            scratch: [0; READ_BUFFER_SIZE],
        }
    }
}

impl<R: Read> Read for WhitespaceFilterReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            let max_len = self.scratch.len().min(out.len());
            let n = self.inner.read(&mut self.scratch[..max_len])?;
            if n == 0 {
                return Ok(0);
            }

            let mut written = 0;
            for &b in &self.scratch[..n] {
                if matches!(b, b' ' | b'\t' | b'\r' | b'\n') {
                    continue;
                }
                out[written] = b;
                written += 1;
            }

            if written > 0 {
                return Ok(written);
            }
        }
    }
}

/// 값이 64자 hexadecimal Nonce인지 확인합니다.
pub fn is_valid_nonce(value: &str) -> bool {
    value.len() == NONCE_HEX_LENGTH && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// 발신자 이메일 주소에서 전화번호를 추출하고 통신사를 판별합니다.
///
/// `010-1234-5678@mms.kt.co.kr` 형태의 주소를 파싱하여
/// 정규화된 전화번호(`01012345678`)와 통신사(`KT`, `SKT`, `LGU+`)로 매핑합니다.
pub fn extract_phone_and_carrier(from_address: &str) -> (Option<String>, Option<String>) {
    let trimmed = from_address.trim();
    if trimmed.is_empty() {
        return (None, None);
    }

    let addr = match mailparse::addrparse(trimmed) {
        Ok(addrs) if !addrs.is_empty() => match &addrs[0] {
            mailparse::MailAddr::Single(s) => s.addr.clone(),
            mailparse::MailAddr::Group(g) => g
                .addrs
                .first()
                .map_or_else(|| trimmed.to_string(), |a| a.addr.clone()),
        },
        _ => trimmed.to_string(),
    };

    let addr = addr.trim();
    let (local, domain) = match addr.split_once('@') {
        Some(parts) => parts,
        None => return (None, None),
    };

    if !(9..=13).contains(&local.len())
        || !local.chars().all(|c| c.is_ascii_digit() || c == '-')
        || domain.is_empty()
        || !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
    {
        return (None, None);
    }

    let phone = normalize_digits(local);
    if !(9..=11).contains(&phone.len()) {
        return (None, None);
    }

    let carrier = carrier_for_domain(domain).map(str::to_string);
    (Some(phone), carrier)
}

fn normalize_digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

fn carrier_for_domain(domain: &str) -> Option<&'static str> {
    match domain.to_ascii_lowercase().as_str() {
        "vmms.nate.com" => Some("SKT"),
        "mmsmail.uplus.co.kr" => Some("LGU+"),
        "mms.kt.co.kr" => Some("KT"),
        _ => None,
    }
}

/// 이메일 파싱 결과물
#[derive(Debug)]
pub struct ExtractResult {
    /// 원본 `From` 헤더 값.
    pub header_from: String,
    /// 추출된 Nonce. 찾지 못하면 빈 문자열입니다.
    pub nonce: String,
    /// 입력 스트림에서 소비한 바이트 수.
    pub bytes_read: usize,
}

/// SMTP 데몬으로 수신된 원시 데이터에서 `From` 헤더와 `Nonce`를 추출합니다.
///
/// Base64, Quoted-Printable, Multipart 등 복잡한 MIME 구조를 재귀적으로 탐색하며,
/// 자원 고갈(DoS) 방지를 위해 최대 깊이(`MAX_MIME_DEPTH`) 및 용량(`limit`)을 제한합니다.
pub fn extract_header_from_and_nonce(data: &[u8], limit: usize) -> io::Result<ExtractResult> {
    extract_header_from_and_nonce_stream(data, limit)
}

/// `extract_header_from_and_nonce`의 스트리밍 버전.
///
/// 크기 제한 오류는 fatal I/O 오류로 반환합니다. leaf MIME body의 decode 오류는
/// best-effort miss로 처리하여 깨진 optional part만으로 전체 메시지를 거부하지 않습니다.
pub fn extract_header_from_and_nonce_stream<R: Read>(
    reader: R,
    limit: usize,
) -> io::Result<ExtractResult> {
    if limit == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "byte limit must be greater than zero",
        ));
    }

    let mut reader = BufReader::new(CountingLimitReader::new(reader, limit));

    let result = (|| {
        let headers = read_mime_headers(&mut reader)?;
        let header_from = headers
            .get("from")
            .map(str::trim)
            .unwrap_or_default()
            .to_string();

        let mut scanner = NonceScanner::new();
        scan_entity(&mut reader, &headers, &mut scanner, 0)?;

        Ok(ExtractResult {
            header_from,
            nonce: scanner.nonce(),
            bytes_read: reader.get_ref().bytes_read(),
        })
    })();

    if let Err(err) = &result {
        if !is_message_too_large(err) {
            let _ = drain_to_end(&mut reader);
        }
    }

    result
}

fn read_mime_headers<R: BufRead + ?Sized>(reader: &mut R) -> io::Result<MimeHeaders> {
    let mut headers = MimeHeaders::default();
    let mut last_index: Option<usize> = None;
    let mut line = Vec::new();

    loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "missing MIME header terminator",
            ));
        }

        let trimmed_line = trim_crlf(&line);
        if trimmed_line.is_empty() {
            return Ok(headers);
        }

        if matches!(trimmed_line.first(), Some(b' ' | b'\t')) {
            if let Some(idx) = last_index {
                headers.fields[idx].1.push(' ');
                headers.fields[idx]
                    .1
                    .push_str(bytes_to_trimmed_string(trimmed_line).as_str());
            }
            continue;
        }

        let Some(colon) = trimmed_line.iter().position(|&b| b == b':') else {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "malformed MIME header",
            ));
        };

        let name = bytes_to_trimmed_string(&trimmed_line[..colon]);
        if name.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "empty MIME header name",
            ));
        }
        let value = bytes_to_trimmed_string(&trimmed_line[colon + 1..]);
        headers.fields.push((name, value));
        last_index = Some(headers.fields.len() - 1);
    }
}

fn parse_content_type_header(value: &str) -> ContentTypeHeader {
    let segments = split_semicolon_quoted(value);
    let media_type = segments
        .first()
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let mut params = BTreeMap::new();
    for segment in segments.iter().skip(1) {
        let Some((key, raw_value)) = segment.split_once('=') else {
            continue;
        };

        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            continue;
        }
        params.insert(key, unquote_param(raw_value.trim()));
    }

    ContentTypeHeader { media_type, params }
}

fn split_semicolon_quoted(value: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    let mut escaped = false;

    for (idx, ch) in value.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' if in_quote => escaped = true,
            '"' => in_quote = !in_quote,
            ';' if !in_quote => {
                segments.push(&value[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }

    segments.push(&value[start..]);
    segments
}

fn unquote_param(value: &str) -> String {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return value.to_string();
    }

    let inner = &value[1..value.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else {
            out.push(ch);
        }
    }
    if escaped {
        out.push('\\');
    }
    out
}

fn scan_entity(
    body: &mut dyn Read,
    headers: &MimeHeaders,
    scanner: &mut NonceScanner,
    depth: usize,
) -> io::Result<()> {
    if depth > MAX_MIME_DEPTH {
        return drain_to_end(body);
    }

    let parsed_type = parse_content_type_header(headers.get("content-type").unwrap_or_default());

    if parsed_type.media_type.starts_with("multipart/") {
        if let Some(boundary) = parsed_type.params.get("boundary").filter(|b| !b.is_empty()) {
            let mut buffered_body = BufReader::new(body);
            scan_multipart(&mut buffered_body, boundary, scanner, depth)?;
            return drain_to_end(&mut buffered_body);
        }
    }

    let cte = headers.get("content-transfer-encoding").unwrap_or_default();
    scan_leaf_body(body, cte, scanner)
}

fn scan_multipart(
    reader: &mut dyn BufRead,
    boundary: &str,
    scanner: &mut NonceScanner,
    depth: usize,
) -> io::Result<()> {
    let marker = format!("--{boundary}").into_bytes();
    let mut line = Vec::new();

    let first_is_final = loop {
        line.clear();
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(());
        }

        if let Some(final_boundary) = boundary_line_kind(&line, &marker) {
            break final_boundary;
        }
    };

    if first_is_final {
        return drain_to_end(reader);
    }

    loop {
        let part_headers = match read_mime_headers(reader) {
            Ok(headers) => headers,
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(()),
            Err(err) => return Err(err),
        };

        let mut part_body = PartBody::new(reader, marker.clone());
        let scan_result = scan_entity(&mut part_body, &part_headers, scanner, depth + 1);
        if let Err(err) = scan_result {
            if !is_message_too_large(&err) {
                let _ = drain_to_end(&mut part_body);
            }
            return Err(err);
        }

        drain_to_end(&mut part_body)?;
        let stop = part_body.final_boundary || part_body.stream_eof;
        drop(part_body);

        if stop {
            return drain_to_end(reader);
        }
    }
}

struct PartBody<'a> {
    source: &'a mut dyn BufRead,
    marker: Vec<u8>,
    pending: Vec<u8>,
    offset: usize,
    done: bool,
    final_boundary: bool,
    stream_eof: bool,
}

impl<'a> PartBody<'a> {
    fn new(source: &'a mut dyn BufRead, marker: Vec<u8>) -> Self {
        Self {
            source,
            marker,
            pending: Vec::new(),
            offset: 0,
            done: false,
            final_boundary: false,
            stream_eof: false,
        }
    }
}

impl Read for PartBody<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        loop {
            if self.offset < self.pending.len() {
                let available = self.pending.len() - self.offset;
                let to_copy = available.min(out.len());
                out[..to_copy].copy_from_slice(&self.pending[self.offset..self.offset + to_copy]);
                self.offset += to_copy;
                if self.offset == self.pending.len() {
                    self.pending.clear();
                    self.offset = 0;
                }
                return Ok(to_copy);
            }

            if self.done {
                return Ok(0);
            }

            self.pending.clear();
            let n = self.source.read_until(b'\n', &mut self.pending)?;
            if n == 0 {
                self.done = true;
                self.stream_eof = true;
                return Ok(0);
            }

            if let Some(final_boundary) = boundary_line_kind(&self.pending, &self.marker) {
                self.done = true;
                self.final_boundary = final_boundary;
                self.pending.clear();
                return Ok(0);
            }
        }
    }
}

fn scan_leaf_body<R: Read + ?Sized>(
    raw: &mut R,
    cte: &str,
    scanner: &mut NonceScanner,
) -> io::Result<()> {
    if scanner.found() {
        return drain_to_end(raw);
    }

    match cte.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            let result = {
                let filtered = WhitespaceFilterReader::new(&mut *raw);
                let mut decoder = DecoderReader::new(filtered, &STANDARD);
                scan_decoded(&mut decoder, scanner)
            };

            match result {
                Ok(()) => drain_to_end(raw),
                Err(err) if is_message_too_large(&err) => Err(err),
                // 통신사 MMS에는 깨진 optional part가 섞일 수 있어, 크기 제한만 전파하고
                // decode 실패는 Nonce 미발견으로 취급합니다.
                Err(_) => drain_to_end(raw),
            }
        }
        "quoted-printable" => scan_quoted_printable(raw, scanner),
        _ => scan_decoded(raw, scanner),
    }
}

fn scan_decoded<R: Read + ?Sized>(reader: &mut R, scanner: &mut NonceScanner) -> io::Result<()> {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }

        scanner.scan(&buf[..n]);
        if scanner.found() {
            return drain_to_end(reader);
        }
    }
}

fn scan_quoted_printable<R: Read + ?Sized>(
    raw: &mut R,
    scanner: &mut NonceScanner,
) -> io::Result<()> {
    enum State {
        Normal,
        AfterEquals,
        Hex1(u8),
        SoftCr,
    }

    fn scan_literal(scanner: &mut NonceScanner, byte: u8) {
        scanner.scan(&[byte]);
    }

    let mut state = State::Normal;
    let mut buf = [0u8; READ_BUFFER_SIZE];

    loop {
        let n = raw.read(&mut buf)?;
        if n == 0 {
            match state {
                State::AfterEquals => scan_literal(scanner, b'='),
                State::Hex1(first) => {
                    scan_literal(scanner, b'=');
                    scan_literal(scanner, first);
                }
                State::SoftCr => {}
                State::Normal => {}
            }
            return Ok(());
        }

        for &b in &buf[..n] {
            match state {
                State::Normal => {
                    if b == b'=' {
                        state = State::AfterEquals;
                    } else {
                        scan_literal(scanner, b);
                    }
                }
                State::AfterEquals => {
                    if b == b'\r' {
                        state = State::SoftCr;
                    } else if b == b'\n' {
                        state = State::Normal;
                    } else if b.is_ascii_hexdigit() {
                        state = State::Hex1(b);
                    } else {
                        scan_literal(scanner, b'=');
                        scan_literal(scanner, b);
                        state = State::Normal;
                    }
                }
                State::Hex1(first) => {
                    if b.is_ascii_hexdigit() {
                        let decoded = (hex_value(first) << 4) | hex_value(b);
                        scan_literal(scanner, decoded);
                    } else {
                        scan_literal(scanner, b'=');
                        scan_literal(scanner, first);
                        scan_literal(scanner, b);
                    }
                    state = State::Normal;
                }
                State::SoftCr => {
                    if b != b'\n' {
                        scan_literal(scanner, b);
                    }
                    state = State::Normal;
                }
            }

            if scanner.found() {
                return drain_to_end(raw);
            }
        }
    }
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn drain_to_end<R: Read + ?Sized>(reader: &mut R) -> io::Result<()> {
    let mut buf = [0u8; READ_BUFFER_SIZE];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(err) => return Err(err),
        }
    }
}

fn boundary_line_kind(line: &[u8], marker: &[u8]) -> Option<bool> {
    let trimmed = trim_crlf(line);
    if !trimmed.starts_with(marker) {
        return None;
    }

    let rest = trim_ascii_space(&trimmed[marker.len()..]);
    if rest.is_empty() {
        return Some(false);
    }
    if rest == b"--" {
        return Some(true);
    }
    None
}

pub(crate) fn trim_crlf(mut value: &[u8]) -> &[u8] {
    while matches!(value.last(), Some(b'\r' | b'\n')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_ascii_space(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn bytes_to_trimmed_string(value: &[u8]) -> String {
    String::from_utf8_lossy(trim_ascii_space(value)).into_owned()
}

#[cfg(test)]
fn extract_nonce_from_body(body: &str) -> Option<String> {
    let mut scanner = NonceScanner::new();
    scanner.scan(body.as_bytes());
    scanner.found
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Read;

    struct OneByteReader<'a> {
        data: &'a [u8],
    }

    impl<'a> OneByteReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data }
        }
    }

    impl Read for OneByteReader<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                return Ok(0);
            }

            out[0] = self.data[0];
            self.data = &self.data[1..];
            Ok(1)
        }
    }

    #[test]
    fn test_is_valid_nonce() {
        let good = "a".repeat(NONCE_HEX_LENGTH);
        assert!(is_valid_nonce(&good));
        assert!(!is_valid_nonce(&format!("{good}0")));
        assert!(!is_valid_nonce(&format!("{}z", &good[..63])));
    }

    #[test]
    fn test_extract_phone_and_carrier() {
        let (phone, carrier) = extract_phone_and_carrier("010-1234-5678@mms.kt.co.kr");
        assert_eq!(phone, Some("01012345678".to_string()));
        assert_eq!(carrier, Some("KT".to_string()));

        let (phone, carrier) = extract_phone_and_carrier("01011112222@example.com");
        assert_eq!(phone, Some("01011112222".to_string()));
        assert_eq!(carrier, None);

        let (phone, carrier) =
            extract_phone_and_carrier("010-1234-5678@mms.kt.co.kr <attacker@attacker-domain.com>");
        assert_eq!(phone, None);
        assert_eq!(carrier, None);

        let (phone, carrier) = extract_phone_and_carrier(
            "\"010-1234-5678@mms.kt.co.kr\" <attacker@attacker-domain.com>",
        );
        assert_eq!(phone, None);
        assert_eq!(carrier, None);

        let (phone, carrier) = extract_phone_and_carrier("0---------@mms.kt.co.kr");
        assert_eq!(phone, None);
        assert_eq!(carrier, None);

        let (phone, carrier) = extract_phone_and_carrier("  ");
        assert_eq!(phone, None);
        assert_eq!(carrier, None);
    }

    #[test]
    fn test_extract_header_from_and_nonce_plain() {
        let nonce = "a".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: Sender\n \t<01012345678@mmsmail.uplus.co.kr>\nSubject: test\n\nbody [MAPAE:{nonce}]"
        );

        let got = extract_header_from_and_nonce(raw.as_bytes(), raw.len()).unwrap();
        assert!(got.header_from.contains("01012345678@mmsmail.uplus.co.kr"));
        assert_eq!(got.nonce, nonce);
        assert_eq!(got.bytes_read, raw.len());
    }

    #[test]
    fn test_extract_header_from_and_nonce_base64() {
        let nonce = "b".repeat(NONCE_HEX_LENGTH);
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("[MAPAE:{nonce}]"));
        let raw = format!(
            "From: 01012345678@mms.kt.co.kr\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        );

        let got = extract_header_from_and_nonce(raw.as_bytes(), raw.len()).unwrap();
        assert_eq!(got.nonce, nonce);
    }

    #[test]
    fn test_extract_header_from_and_nonce_quoted_printable() {
        let nonce = "c".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: 01012345678@mms.kt.co.kr\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=5BMAPAE:{nonce}=5D"
        );

        let got = extract_header_from_and_nonce(raw.as_bytes(), raw.len()).unwrap();
        assert_eq!(got.nonce, nonce);
    }

    #[test]
    fn test_extract_header_from_and_nonce_multipart() {
        let nonce = "d".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: 01012345678@mms.kt.co.kr\r\n\
             Content-Type: multipart/alternative; boundary=\"abc;123\"\r\n\
             \r\n\
             --abc;123\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             no nonce\r\n\
             --abc;123\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             \r\n\
             <p>[MAPAE:{nonce}]</p>\r\n\
             --abc;123--\r\n"
        );

        let got = extract_header_from_and_nonce(raw.as_bytes(), raw.len()).unwrap();
        assert_eq!(got.nonce, nonce);
    }

    #[test]
    fn test_stream_extract_handles_one_byte_reads() {
        let nonce = "a".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: 01012345678@mms.kt.co.kr\r\nContent-Type: text/plain\r\n\r\nprefix [mapae:{nonce}] suffix"
        );

        let got =
            extract_header_from_and_nonce_stream(OneByteReader::new(raw.as_bytes()), raw.len())
                .unwrap();
        assert_eq!(got.header_from, "01012345678@mms.kt.co.kr");
        assert_eq!(got.nonce, nonce);
        assert_eq!(got.bytes_read, raw.len());
    }

    #[test]
    fn test_stream_extract_rejects_oversize_after_nonce() {
        let nonce = "b".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: user@example.com\r\n\r\n[MAPAE:{nonce}]{}",
            "x".repeat(128)
        );

        let err = extract_header_from_and_nonce_stream(raw.as_bytes(), raw.len() - 1).unwrap_err();
        assert!(is_message_too_large(&err));
    }

    #[test]
    fn test_extract_header_from_and_nonce_rejects_oversize_input() {
        let raw = b"From: user@example.com\r\n\r\nhello";
        let err = extract_header_from_and_nonce(raw, raw.len() - 1).unwrap_err();
        assert!(is_message_too_large(&err));
    }

    #[test]
    fn test_extract_header_from_and_nonce_rejects_zero_limit() {
        let raw = b"From: user@example.com\r\n\r\nhello";
        let err = extract_header_from_and_nonce(raw, 0).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn test_extract_nonce_requires_exact_hex_payload() {
        let good = "f".repeat(NONCE_HEX_LENGTH);
        assert_eq!(
            extract_nonce_from_body(&format!("[MAPAE:{good}extra]")),
            None
        );
        assert_eq!(
            extract_nonce_from_body(&format!("[MAPAE:not-hex][MAPAE:{good}]")),
            Some(good)
        );
    }

    #[test]
    fn test_extract_nonce_continues_after_malformed_prefix() {
        let good = "e".repeat(NONCE_HEX_LENGTH);
        assert_eq!(
            extract_nonce_from_body(&format!("[MAPAE:not-hex [MAPAE:{good}]")),
            Some(good)
        );
    }
}
