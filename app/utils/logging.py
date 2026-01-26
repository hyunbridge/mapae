from __future__ import annotations

import logging
import sys

from ..config import get_settings

settings = get_settings()


def setup_logging() -> None:
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("aiosmtpd").setLevel(logging.INFO)
    logging.getLogger("redis").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"mapae.{name}")
