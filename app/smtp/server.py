import asyncio
from aiosmtpd.controller import Controller
from app.config import get_settings
from app.smtp.handler import PermissiveHandler
from app.utils.logging import get_logger

settings = get_settings()
logger = get_logger("smtp")
DATA_SIZE_LIMIT_BYTES = 500 * 1024


def create_controller(redis_url: str) -> Controller:
    handler = PermissiveHandler(redis_url)
    return Controller(
        handler,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        data_size_limit=DATA_SIZE_LIMIT_BYTES,
    )


async def run_forever() -> None:
    controller = create_controller(settings.REDIS_URL)
    controller.start()
    logger.info("SMTP server listening on %s:%s", settings.SMTP_HOST, settings.SMTP_PORT)
    try:
        await asyncio.Event().wait()
    finally:
        controller.stop()


if __name__ == "__main__":
    from app.utils.logging import setup_logging

    setup_logging()
    asyncio.run(run_forever())
