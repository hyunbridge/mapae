import asyncio
from datetime import datetime, timezone

from aiosmtpd.smtp import Envelope
import redis.asyncio as redis

from app.config import get_settings
from app.schemas.auth import AuthRecord, VerifiedPayload
from app.smtp.parser import extract_phone_and_carrier, find_nonce, parse_body
from app.smtp.spf_check import spf_pass
from app.utils.logging import get_logger

settings = get_settings()
logger = get_logger("smtp")


class PermissiveHandler:
    def __init__(self, redis_url: str):
        self._redis_url = redis_url
        self._redis: redis.Redis | None = None
        self._redis_lock = asyncio.Lock()

    async def _get_redis(self) -> redis.Redis:
        if self._redis is None:
            async with self._redis_lock:
                if self._redis is None:
                    self._redis = redis.from_url(self._redis_url, decode_responses=True)
        return self._redis

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if settings.ALLOWED_RCPT_SUFFIXES:
            addr = (address or "").lower()
            if not any(addr.endswith(suffix) for suffix in settings.ALLOWED_RCPT_SUFFIXES):
                return "550 Not relaying to that address"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope: Envelope):
        mail_from = envelope.mail_from
        raw = envelope.content
        peer_ip = session.peer[0] if session and session.peer else None
        helo = getattr(session, "host_name", None)

        body_text, parsed = parse_body(raw)

        header_from = str(parsed.get("From", "")) if parsed else ""
        env_phone, env_carrier = extract_phone_and_carrier(mail_from)
        hdr_phone, hdr_carrier = extract_phone_and_carrier(header_from)

        # SPF: peer IP가 있을 때, 최소한 신뢰할 수 있는 발신자(mail_from 또는 header From) 중 하나는 pass여야 함.
        # (통신사에 따라 envelope MAIL FROM이 generic일 수 있어 header From도 함께 검증)
        env_spf_ok = False
        hdr_spf_ok = False
        if peer_ip:
            if mail_from:
                env_spf_ok = await spf_pass(peer_ip, mail_from, helo)
            if header_from:
                hdr_spf_ok = await spf_pass(peer_ip, header_from, helo)
            if not (env_spf_ok or hdr_spf_ok):
                logger.info(
                    "SPF fail: ip=%s mail_from=%s header_from=%s", peer_ip, mail_from, header_from
                )
                return "550 SPF fail"

        phone = None
        carrier = None
        if env_carrier and (not peer_ip or env_spf_ok):
            phone, carrier = env_phone, env_carrier
        elif hdr_carrier and (not peer_ip or hdr_spf_ok):
            phone, carrier = hdr_phone, hdr_carrier

        if settings.DUMP_INBOUND:
            logger.info("MAIL FROM: %s", mail_from)
            if header_from:
                logger.info("HEADER FROM: %s", header_from)
            logger.info("RAW BYTES LEN: %s", len(raw) if raw else 0)
            logger.info("BODY (decoded): %s", body_text)

        nonce = find_nonce(body_text)

        if nonce and phone and carrier:
            redis_client = await self._get_redis()
            auth_id = await redis_client.get(f"nonce:{nonce}")
            if auth_id:
                payload = VerifiedPayload(
                    status="verified",
                    phone=phone,
                    carrier=carrier,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                record = AuthRecord(key=f"auth:{auth_id}", payload=payload)
                await redis_client.set(
                    record.key, payload.model_dump_json(), ex=settings.VERIFIED_TTL_SECONDS
                )
                logger.info("Stored verification for %s (%s)", phone, carrier)
            else:
                logger.info("Nonce not found or expired: %s", nonce)
        else:
            logger.info("No valid code/carrier/phone parsed")

        return "250 OK"
