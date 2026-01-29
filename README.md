# MAPAE (Mobile Authentication Platform via Automated Email)

SMS API 비용 없이, 통신사의 MMS-to-Email 게이트웨이를 활용하여 휴대폰 인증을 구현합니다.

## 프로젝트 소개

MAPAE는 한국 이동통신 3사의 MMS-to-Email 게이트웨이 특성을 이용하여 구축한 휴대폰 인증 시스템입니다.

기존의 MO(Mobile Originated) 인증 방식은 사용자가 특정 번호(예: #1234)로 문자를 보내 인증하는 방식으로, 수신 번호 임대료와 건당 비용이 발생합니다.

MAPAE는 문자 메시지(MMS)를 이메일 주소로 발송할 수 있는 기능을 활용합니다. 사용자가 설정된 수신 주소로 인증 문자를 보내면, 통신사가 이를 이메일로 변환하여 MAPAE 서버로 전달하고, 서버가 이를 실시간으로 파싱하여 인증을 완료합니다.

### 핵심 기능
- 비용 절감: 별도의 SMS/MO 계약 없이, 도메인과 서버만으로 인증 시스템 구축 가능
- 관대한(Permissive) SMTP 리스너: 표준을 준수하지 않는 통신사의 깨진 헤더를 처리하고, Nonce를 추출
- 고성능 비동기 아키텍처: FastAPI와 aiosmtpd를 단일 비동기 루프(Asyncio) 위에서 통합 실행, 블로킹 작업을 별도 스레드로 격리하여 처리량 극대화
- 보안 설계: SPF을 통한 발신 서버 검증으로 이메일 변조 방지

## 아키텍처 및 동작 원리

MAPAE는 SMTP 서버(25/tcp)와 HTTP API(8000/tcp)를 동시에 제공합니다.

1. 클라이언트가 API로 인증을 요청하면, 서버는 고유한 Nonce를 발급합니다.
2. 사용자는 화면의 링크(`sms:verify@...`)를 통해 Nonce가 포함된 문자를 전송합니다.
3. SMTP 서버는 이메일 본문의 Nonce를 추출하고, 발신자 헤더를 분석하여 휴대폰 번호와 통신사를 식별합니다.
4. 클라이언트는 폴링을 통해 성공 여부를 확인합니다.

## 요구사항
- Python: 3.10 이상
- Database: Redis 6.x 이상
- Network: TCP Inbound 25번 포트 개방 필요(SMTP)

## 설정 가이드 (.env)

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| DEBUG | false | 디버그 로깅 활성화 |
| REDIS_URL | redis://localhost:6379/0 | Redis 연결 주소 |
| SMTP_HOST | 0.0.0.0 | SMTP 바인딩 호스트 |
| SMTP_PORT | 25 | SMTP 바인딩 포트 |
| ALLOWED_RCPT_SUFFIXES | [] | 허용할 수신 이메일 주소 목록 (예: ["verify@mydomain.com"]). 비워두면 모든 수신 허용. |
| SMS_INBOUND_ADDRESS | verify@yourdomain.com | 인바운드 수신 주소 |
| DUMP_INBOUND | false | 수신된 이메일의 헤더/본문을 로그에 출력 |
| CORS_ALLOW_ORIGINS | ["*"] | CORS 허용 Origin 목록 |
| AUTH_TTL_SECONDS | 600 | 인증 시도(Nonce) 유효 시간 (초) |
| VERIFIED_TTL_SECONDS | 300 | 인증 완료 후 결과 보관 시간 (초) |

## 개발

의존성 관리는 `pyproject.toml` 기반입니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 배포

### Docker로 실행

1) 이미지 빌드
```bash
docker build -t mapae:latest .
```

2) 컨테이너 실행
```bash
docker run --rm --name mapae \
  --env-file .env \
  -p 8000:8000 \
  -p 25:25 \
  mapae:latest
```

## API 명세

서버 실행 후 Swagger UI를 확인할 수 있습니다.

- **Swagger UI**: http://localhost:8000/docs

## 통신사 호환성

| 통신사 | 발신 도메인 | 특이사항 대응 |
| :--- | :--- | :--- |
| SKT | vmms.nate.com | - |
| KT | mms.kt.co.kr | Broken Header 처리 (Message-ID 누락 등) |
| LGU+ | mmsmail.uplus.co.kr | - |

## License
MIT
