import asyncio
from aiosmtpd.controller import Controller
import redis.asyncio as redis

from app.config import get_settings
from app.smtp.handler import PermissiveHandler
from app.utils.logging import get_logger

settings = get_settings()
logger = get_logger("smtp")


def create_controller(redis_client: redis.Redis) -> Controller:
    handler = PermissiveHandler(redis_client)
    return Controller(handler, hostname=settings.SMTP_HOST, port=settings.SMTP_PORT)


async def run_forever() -> None:
    redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    controller = create_controller(redis_client)
    controller.start()
    logger.info("SMTP server listening on %s:%s", settings.SMTP_HOST, settings.SMTP_PORT)
    try:
        await asyncio.Event().wait()
    finally:
        controller.stop()
        await redis_client.close()


if __name__ == "__main__":
    from app.utils.logging import setup_logging

    setup_logging()
    asyncio.run(run_forever())
