from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import close_client, get_client
from app.exceptions import MapaeException
from app.routers.auth import router as auth_router
from app.routers.health import router as health_router
from app.smtp.server import create_controller
from app.utils.logging import get_logger, setup_logging

setup_logging()
settings = get_settings()
logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.redis = get_client()
    controller = create_controller(settings.REDIS_URL)
    controller.start()
    app.state.smtp_controller = controller
    try:
        yield
    finally:
        controller.stop()
        await close_client()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_credentials=False,
)
app.include_router(auth_router)
app.include_router(health_router)


@app.exception_handler(MapaeException)
async def mapae_exception_handler(request, exc: MapaeException):
    logger.error("Mapae exception: %s", exc.message)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    logger.exception("Unexpected error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"detail": "서버 오류가 발생했습니다"},
    )
