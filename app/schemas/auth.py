from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class AuthInitResponse(BaseModel):
    """인증 세션 생성 응답"""

    auth_id: str = Field(
        ...,
        description="인증 결과 조회에 사용할 고유 식별자 (32자리 16진수)",
        json_schema_extra={"example": "ab12cd34ef56gh78ij90kl12mn34op56"},
    )
    sms_body: str = Field(
        ...,
        description="사용자가 전송할 문자 본문 (Nonce 포함)",
        json_schema_extra={"example": "[MAPAE:f8a1b2c3d4e5f6...]"},
    )
    link: str = Field(
        ...,
        description="모바일에서 클릭 시 문자 앱을 실행하는 sms: URI 스키마",
        json_schema_extra={"example": "sms:verify@yourdomain.com?body=[MAPAE:f8a1b2c3d4e5f6...]"},
    )
    ttl_seconds: int = Field(
        ...,
        description="인증 세션 유효 시간 (초)",
        json_schema_extra={"example": 600},
    )


class AuthPayload(BaseModel):
    """내부용: 대기 중인 인증 세션 페이로드"""

    status: Literal["pending"]
    timestamp: str


class VerifiedPayload(BaseModel):
    """내부용: 인증 완료된 페이로드"""

    status: Literal["verified"]
    phone: str | None = None
    carrier: str | None = None
    timestamp: str


class AuthRecord(BaseModel):
    """내부용: Redis에 저장되는 인증 레코드"""

    key: str
    payload: AuthPayload | VerifiedPayload


class NonceRecord(BaseModel):
    """내부용: Redis에 저장되는 Nonce 레코드"""

    key: str
    auth_id: str


class AuthCheckExpired(BaseModel):
    """인증 세션 만료 응답"""

    status: Literal["expired"] = Field(
        ...,
        description="인증 상태 (만료됨)",
        json_schema_extra={"example": "expired"},
    )


class AuthCheckWaiting(BaseModel):
    """인증 대기 중 응답"""

    status: Literal["waiting"] = Field(
        ...,
        description="인증 상태 (대기 중)",
        json_schema_extra={"example": "waiting"},
    )


class AuthCheckVerified(BaseModel):
    """인증 성공 응답"""

    status: Literal["verified"] = Field(
        ...,
        description="인증 상태 (성공)",
        json_schema_extra={"example": "verified"},
    )
    phone: str | None = Field(
        None,
        description="인증된 휴대폰 번호 (하이픈 제외)",
        json_schema_extra={"example": "01012345678"},
    )
    carrier: str | None = Field(
        None,
        description="통신사 (SKT, KT, LGU+ 중 하나)",
        json_schema_extra={"example": "SKT"},
    )
    timestamp: str | None = Field(
        None,
        description="인증 완료 시각 (ISO 8601 형식)",
        json_schema_extra={"example": "2026-01-25T14:00:00+00:00"},
    )


AuthCheckResponse = AuthCheckExpired | AuthCheckWaiting | AuthCheckVerified
