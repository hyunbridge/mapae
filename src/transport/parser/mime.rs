use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, ErrorKind, Read};

use base64::{engine::general_purpose::STANDARD, read::DecoderReader};
use mail_parser::decoders::quoted_printable::quoted_printable_decode;

use super::nonce::NonceScanner;
use super::{
    is_message_too_large_io, trim_crlf, MessageTooLarge, MAX_MIME_DEPTH, READ_BUFFER_SIZE,
};

pub(super) struct CountingLimitReader<R> {
    inner: R,
    limit: usize,
    bytes_read: usize,
}

impl<R> CountingLimitReader<R> {
    pub(super) fn new(inner: R, limit: usize) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
        }
    }

    pub(super) fn bytes_read(&self) -> usize {
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
pub(super) struct MimeHeaders {
    fields: Vec<(String, String)>,
}

impl MimeHeaders {
    pub(super) fn get(&self, key: &str) -> Option<&str> {
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

pub(super) fn read_mime_headers<R: BufRead + ?Sized>(reader: &mut R) -> io::Result<MimeHeaders> {
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

pub(super) fn scan_entity(
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
            if !is_message_too_large_io(&err) {
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
                Err(err) if is_message_too_large_io(&err) => Err(err),
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
    let mut encoded = Vec::new();
    raw.read_to_end(&mut encoded)?;
    if let Some(decoded) = quoted_printable_decode(&encoded) {
        scanner.scan(&decoded);
    }

    Ok(())
}

pub(super) fn drain_to_end<R: Read + ?Sized>(reader: &mut R) -> io::Result<()> {
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
