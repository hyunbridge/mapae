from __future__ import annotations

import json
import re
import secrets
from datetime import datetime, timezone

import redis.asyncio as redis

from ..config import get_settings
from ..exceptions import MapaeException
from ..schemas.auth import AuthPayload, AuthRecord, NonceRecord, VerifiedPayload

settings = get_settings()


class AuthService:
    _auth_id_re = re.compile(r"^[0-9a-fA-F]{32}$")

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def _generate_nonce(self) -> str:
        return secrets.token_hex(32)

    def _generate_auth_id(self) -> str:
        return secrets.token_hex(16)

    async def init_auth(self) -> dict:
        nonce = self._generate_nonce()
        auth_id = self._generate_auth_id()
        payload = AuthPayload(
            status="pending",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        auth_record = AuthRecord(key=f"auth:{auth_id}", payload=payload)
        nonce_record = NonceRecord(key=f"nonce:{nonce}", auth_id=auth_id)
        pipe = self.redis.pipeline()
        pipe.set(
            auth_record.key,
            payload.model_dump_json(),
            ex=settings.AUTH_TTL_SECONDS,
        )
        pipe.set(nonce_record.key, nonce_record.auth_id, ex=settings.AUTH_TTL_SECONDS)
        await pipe.execute()
        sms_body = f"[MAPAE:{nonce}]"
        return {
            "auth_id": auth_id,
            "sms_body": sms_body,
            "link": f"sms:{settings.SMS_INBOUND_ADDRESS}?body={sms_body}",
            "ttl_seconds": settings.AUTH_TTL_SECONDS,
        }

    async def check_auth(self, auth_id: str) -> dict:
        if not self._auth_id_re.fullmatch(auth_id or ""):
            raise MapaeException("유효하지 않은 auth_id 입니다", status_code=400)
        raw = await self.redis.get(f"auth:{auth_id}")
        if raw is None:
            return {"status": "expired"}

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return {"status": "waiting"}

        if data.get("status") == "verified":
            verified = VerifiedPayload.model_validate(data)
            return verified.model_dump()

        return {"status": "waiting"}
