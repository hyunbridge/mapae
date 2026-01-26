from fastapi import Depends

from .db import get_redis
from .services.auth_service import AuthService


async def get_auth_service(redis=Depends(get_redis)) -> AuthService:
    return AuthService(redis)
