from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["헬스체크"])


@router.get(
    "/health",
    summary="서비스 상태 확인",
    description="애플리케이션과 Redis 연결 상태를 확인합니다.",
)
async def health(request: Request) -> JSONResponse:
    redis_client = request.app.state.redis
    try:
        await redis_client.ping()
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "unhealthy", "redis": "down"},
        )

    return JSONResponse(
        status_code=200,
        content={"status": "ok", "redis": "up"},
    )
