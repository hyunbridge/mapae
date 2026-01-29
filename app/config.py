from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DEBUG: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"
    DUMP_INBOUND: bool = False
    SMS_INBOUND_ADDRESS: str = "verify@yourdomain.com"

    SMTP_HOST: str = "0.0.0.0"
    SMTP_PORT: int = 25

    CORS_ALLOW_ORIGINS: list[str] = ["*"]

    AUTH_TTL_SECONDS: int = 600
    VERIFIED_TTL_SECONDS: int = 300


@lru_cache
def get_settings() -> Settings:
    return Settings()
