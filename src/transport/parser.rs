use std::io::{self, BufReader, ErrorKind, Read};

use thiserror::Error;

mod mime;
mod nonce;

use mime::{drain_to_end, read_mime_headers, scan_entity, CountingLimitReader};
use nonce::NonceScanner;

const NONCE_HEX_LENGTH: usize = 64;
const MAX_MIME_DEPTH: usize = 5;
const READ_BUFFER_SIZE: usize = 4096;

#[derive(Debug, Error)]
#[error("message too large")]
struct MessageTooLarge;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("message too large")]
    MessageTooLarge,
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl ParseError {
    fn from_io(err: io::Error) -> Self {
        if is_message_too_large_io(&err) {
            return Self::MessageTooLarge;
        }

        match err.kind() {
            ErrorKind::InvalidInput => Self::InvalidInput(err.to_string()),
            ErrorKind::InvalidData | ErrorKind::UnexpectedEof => {
                Self::InvalidMessage(err.to_string())
            }
            _ => Self::Io(err),
        }
    }

    /// 오류가 메시지 크기 제한 초과를 의미하는지 확인합니다.
    pub fn is_message_too_large(&self) -> bool {
        matches!(self, Self::MessageTooLarge)
    }
}

fn is_message_too_large_io(err: &io::Error) -> bool {
    err.kind() == ErrorKind::Other
        && err
            .get_ref()
            .is_some_and(|cause| cause.is::<MessageTooLarge>())
}

/// 값이 64자 hexadecimal Nonce인지 확인합니다.
pub fn is_valid_nonce(value: &str) -> bool {
    nonce::is_valid_nonce(value)
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
pub fn extract_header_from_and_nonce(
    data: &[u8],
    limit: usize,
) -> Result<ExtractResult, ParseError> {
    extract_header_from_and_nonce_stream(data, limit)
}

/// `extract_header_from_and_nonce`의 스트리밍 버전.
///
/// 크기 제한 오류는 fatal I/O 오류로 반환합니다. leaf MIME body의 decode 오류는
/// best-effort miss로 처리하여 깨진 optional part만으로 전체 메시지를 거부하지 않습니다.
pub fn extract_header_from_and_nonce_stream<R: Read>(
    reader: R,
    limit: usize,
) -> Result<ExtractResult, ParseError> {
    if limit == 0 {
        return Err(ParseError::InvalidInput(
            "byte limit must be greater than zero".to_string(),
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
        if !is_message_too_large_io(err) {
            let _ = drain_to_end(&mut reader);
        }
    }

    result.map_err(ParseError::from_io)
}

pub(crate) fn trim_crlf(mut value: &[u8]) -> &[u8] {
    while matches!(value.last(), Some(b'\r' | b'\n')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
fn extract_nonce_from_body(body: &str) -> Option<String> {
    let mut scanner = NonceScanner::new();
    scanner.scan(body.as_bytes());
    scanner.found_nonce()
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
    fn test_extract_header_from_and_nonce_quoted_printable_soft_break() {
        let nonce = "c".repeat(NONCE_HEX_LENGTH);
        let raw = format!(
            "From: 01012345678@mms.kt.co.kr\r\n\
             Content-Transfer-Encoding: quoted-printable\r\n\
             \r\n\
             =5BMAPAE:{}=\r\n{}=5D",
            &nonce[..32],
            &nonce[32..]
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
        assert!(err.is_message_too_large());
    }

    #[test]
    fn test_extract_header_from_and_nonce_rejects_oversize_input() {
        let raw = b"From: user@example.com\r\n\r\nhello";
        let err = extract_header_from_and_nonce(raw, raw.len() - 1).unwrap_err();
        assert!(err.is_message_too_large());
    }

    #[test]
    fn test_extract_header_from_and_nonce_rejects_zero_limit() {
        let raw = b"From: user@example.com\r\n\r\nhello";
        let err = extract_header_from_and_nonce(raw, 0).unwrap_err();
        assert!(matches!(err, ParseError::InvalidInput(_)));
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
