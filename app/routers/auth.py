from fastapi import APIRouter, Depends, Path

from app.config import get_settings
from app.dependencies import get_auth_service
from app.schemas.auth import AuthCheckResponse, AuthInitResponse
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["인증"])
settings = get_settings()


@router.post(
    "/init",
    response_model=AuthInitResponse,
    summary="인증 세션 생성",
    description="""
새로운 휴대폰 인증 세션을 생성하고 Nonce를 발급합니다.

반환된 `link`를 모바일에서 클릭하면 문자 앱이 실행되며,
사용자가 문자를 전송하면 인증이 완료됩니다.

`auth_id`는 프론트엔드에서 결과를 조회할 때 사용합니다.
    """,
    responses={
        200: {
            "description": "인증 세션 생성 성공",
            "content": {
                "application/json": {
                    "example": {
                        "auth_id": "ab12cd34ef56gh78ij90kl12mn34op56",
                        "sms_body": "[MAPAE:f8a1b2c3d4e5f6...]",
                        "link": f"sms:{settings.SMS_INBOUND_ADDRESS}?body=[MAPAE:f8a1b2c3d4e5f6...]",
                        "ttl_seconds": 600
                    }
                }
            },
        }
    },
)
async def auth_init(
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthInitResponse:
    """인증을 위한 세션과 Nonce를 생성합니다."""
    return await auth_service.init_auth()


@router.get(
    "/check/{auth_id}",
    response_model=AuthCheckResponse,
    summary="인증 결과 조회",
    description="""
프론트엔드에서 폴링(Polling) 방식으로 호출하여 인증 상태를 확인합니다.

### 응답 상태
- `waiting`: 사용자가 아직 문자를 보내지 않음
- `verified`: 인증 성공 (휴대폰 번호, 통신사 정보 포함)
- `expired`: 인증 세션 만료됨
    """,
    responses={
        200: {
            "description": "인증 상태 조회 성공",
            "content": {
                "application/json": {
                    "examples": {
                        "waiting": {
                            "summary": "대기 중",
                            "value": {"status": "waiting"}
                        },
                        "verified": {
                            "summary": "인증 성공",
                            "value": {
                                "status": "verified",
                                "phone": "01012345678",
                                "carrier": "SKT",
                                "timestamp": "2026-01-25T14:00:00+09:00"
                            }
                        },
                        "expired": {
                            "summary": "만료됨",
                            "value": {"status": "expired"}
                        }
                    }
                }
            },
        },
        400: {
            "description": "유효하지 않은 auth_id",
            "content": {
                "application/json": {
                    "example": {"detail": "유효하지 않은 auth_id 입니다"}
                }
            },
        },
    },
)
async def auth_check(
    auth_id: str = Path(
        ...,
        description="인증 세션 생성 시 발급받은 auth_id (32자리 16진수)",
        example="ab12cd34ef56gh78ij90kl12mn34op56",
        min_length=32,
        max_length=32,
    ),
    auth_service: AuthService = Depends(get_auth_service),
) -> AuthCheckResponse:
    """auth_id로 인증 상태를 조회합니다."""
    return await auth_service.check_auth(auth_id)
