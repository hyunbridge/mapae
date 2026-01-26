from __future__ import annotations

from typing import AsyncGenerator

import redis.asyncio as redis

from ..config import get_settings

_settings = get_settings()
_client: redis.Redis | None = None


def get_client() -> redis.Redis:
    global _client
    if _client is None:
        _client = redis.from_url(_settings.REDIS_URL, decode_responses=True)
    return _client


async def get_redis() -> AsyncGenerator[redis.Redis, None]:
    yield get_client()


async def close_client() -> None:
    global _client
    if _client is None:
        return
    await _client.close()
    _client = None
