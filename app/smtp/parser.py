import re
from email import policy
from email.parser import BytesParser

CARRIER_DOMAINS = {
    "vmms.nate.com": "SKT",
    "mmsmail.uplus.co.kr": "LGU+",
    "mms.kt.co.kr": "KT",
}

NONCE_RE = re.compile(r"\[MAPAE:([0-9a-fA-F]{64,})\]", re.IGNORECASE | re.DOTALL)


def normalize_digits(value: str) -> str:
    return re.sub(r"[^0-9]", "", value)


def extract_phone_and_carrier(from_address: str) -> tuple[str | None, str | None]:
    if not from_address:
        return None, None
    # 01012345678@domain 형태에서 주소 부분 추출 (로컬 파트에 하이픈 허용)
    m = re.search(r"([0-9-]{9,13})@([A-Za-z0-9.-]+)", from_address)
    if not m:
        return None, None
    phone = normalize_digits(m.group(1))
    domain = m.group(2).lower()
    carrier = CARRIER_DOMAINS.get(domain)
    return phone, carrier


def decode_bytes(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        # Nonce와 Delimiter는 ASCII이므로 다른 인코딩을 고려할 필요 없음
        return data.decode("ascii", errors="ignore")


def extract_text_from_message(msg) -> str:
    if msg.is_multipart():
        parts = []
        for part in msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get_content_type().startswith("text/"):
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                parts.append(decode_bytes(payload))
        return "\n".join(parts)

    payload = msg.get_payload(decode=True)
    if payload is None:
        return ""
    return decode_bytes(payload)


def parse_body(raw: bytes) -> tuple[str, object | None]:
    parsed = None
    try:
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        body_text = extract_text_from_message(parsed)
    except Exception:
        body_text = decode_bytes(raw)
    return body_text, parsed


def find_nonce(text: str) -> str | None:
    if not text:
        return None
    m = NONCE_RE.search(text)
    if not m:
        return None
    raw = m.group(1)
    # 통신사가 긴 토큰 내부에 삽입할 수 있는 공백/개행 문자 방지
    clean = re.sub(r"\s+", "", raw)
    return clean
