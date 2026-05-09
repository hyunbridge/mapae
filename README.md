# MAPAE (Mobile Authentication Platform via Automated Email)

SMS API 비용 없이, 통신사의 MMS-to-Email 게이트웨이를 활용하여 휴대폰 인증을 구현합니다.

## 프로젝트 소개

MAPAE는 한국 이동통신 3사의 MMS-to-Email 게이트웨이 특성을 이용하여 구축한 휴대폰 인증 시스템입니다.

기존의 MO(Mobile Originated) 인증 방식은 사용자가 특정 번호(예: #1234)로 문자를 보내 인증하는 방식으로, 수신 번호 임대료와 건당 비용이 발생합니다.

MAPAE는 문자 메시지(MMS)를 이메일 주소로 발송할 수 있는 기능을 활용합니다. 사용자가 설정된 수신 주소로 인증 문자를 보내면, 통신사가 이를 이메일로 변환하여 MAPAE 서버로 전달하고, 서버가 이를 실시간으로 파싱하여 인증을 완료합니다.

### 핵심 기능
- **비용 절감**: 별도의 SMS/MO 계약 없이, 도메인과 서버만으로 인증 시스템 구축 가능
- **관대한(Permissive) SMTP 리스너**: 표준을 준수하지 않는 통신사의 깨진 헤더를 처리하고, Nonce를 추출
- **Tokio 기반 비동기**: HTTP(Warp)와 SMTP 서버를 Tokio로 동시 실행
- **스트리밍 SMTP 파서**: 메시지 전체를 메모리에 적재하지 않고, 스트리밍 방식으로 Nonce를 추출하여 메모리 사용량 최소화 (Base64, Quoted-Printable, Multipart MIME 대응)
- **보안 설계**: SPF를 통한 발신 서버 검증으로 이메일 변조 방지
- **JWT 서명**: 인증 완료 시 Ed25519 기반 JWT를 발급하여, 외부 서비스가 JWKS 엔드포인트로 검증 가능

## 아키텍처 및 동작 원리

MAPAE는 SMTP 서버와 HTTP API를 동시에 제공합니다.

1. 클라이언트가 API로 인증을 요청하면, 서버는 고유한 Nonce를 발급합니다.
2. 사용자는 화면의 링크(`sms:verify@...`)를 통해 Nonce가 포함된 문자를 전송합니다.
3. SMTP 서버는 이메일 본문의 Nonce를 추출하고, 발신자 정보를 분석하여 휴대폰 번호와 통신사를 식별합니다.
4. 클라이언트는 폴링을 통해 성공 여부를 확인합니다.

## 요구사항
- **Rust**: 1.95 이상
- **Storage**: Redis 6.2 이상 또는 In-Memory(별도 설치 불필요)
- **Network**: TCP Inbound 25번 포트 개방 필요(SMTP)

## 설정 가이드 (.env)

### 일반

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `DEBUG` | `false` | 디버그 로깅 활성화 |
| `SERVER_MODE` | `all` | 실행할 서버 조합 (`all`, `http`, `smtp`) |
| `SHUTDOWN_DRAIN_SECONDS` | `5` | 종료 요청 후 readiness를 내리고 accept loop를 멈추기 전까지 기다릴 시간 |

환경변수 값이 잘못되면 서버는 기본값으로 조용히 되돌아가지 않고 시작 단계에서 실패합니다.

### 저장소

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `USE_IN_MEMORY_STORE` | `false` | `true`로 설정 시 Redis 대신 In-Memory 스토어 사용 |
| `REDIS_URL` | *(빈 문자열)* | Redis 연결 주소 (`USE_IN_MEMORY_STORE=false`이면 필요) |
| `REDIS_WAIT_REPLICAS` | `0` | Redis write 후 기다릴 replica acknowledgement 수 (`0`이면 비활성화) |
| `REDIS_WAIT_TIMEOUT_MS` | `1000` | Redis `WAIT` 명령 타임아웃(ms) |

### SMTP 서버

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `SMTP_HOST` | `0.0.0.0` | SMTP 바인딩 호스트 |
| `SMTP_PORT` | `2525` | SMTP 바인딩 포트 |
| `SMTP_MAX_CONNECTIONS` | `1024` | 최대 동시 SMTP 연결 수 |
| `SMS_INBOUND_ADDRESS` | `verify@example.com` | 인바운드 수신 주소 (정확히 일치하지 않으면 수신 거부) |
| `DUMP_INBOUND` | `false` | 수신된 이메일의 헤더/본문을 로그에 출력 |
| `SPF_RESOLVER` | `cloudflare` | SPF 검증에 사용할 DNS 리졸버 (`cloudflare`, `google`, `quad9`) |

인증에 사용되는 발신 주소의 local-part는 10~11자리 숫자여야 합니다.
SPF 리졸버는 기본값으로 Cloudflare를 사용하며, 필요하면 `SPF_RESOLVER`로 다른 공용 리졸버를 선택할 수 있습니다.

### HTTP 서버

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `HTTP_HOST` | `0.0.0.0` | HTTP 바인딩 호스트 |
| `HTTP_PORT` | `8000` | HTTP 바인딩 포트 |
| `HTTP_MAX_CONNECTIONS` | `1024` | 최대 동시 HTTP 연결 수 |
| `CORS_ALLOW_ORIGINS` | `["*"]` | CORS 허용 Origin 목록 (JSON 배열 또는 쉼표 구분) |

### 인증

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `AUTH_TTL_SECONDS` | `600` | 인증 시도(Nonce) 유효 시간 (초) |
| `VERIFIED_TTL_SECONDS` | `300` | 인증 완료 후 결과 보관 시간 (초) |

`auth_id`는 16바이트 난수의 32자 hex 문자열이며, SMS 본문에 들어가는 Nonce는 32바이트 난수의 64자 hex 문자열입니다. 모든 TTL 값은 0보다 커야 합니다.

### JWT

| 변수명 | 기본값 | 설명 |
| :--- | :--- | :--- |
| `JWT_PRIVATE_KEY` | *(빈 문자열)* | Ed25519 PEM 개인키 (설정하지 않으면 JWT 서명 기능 비활성화) |
| `JWT_KEY_ID` | `default` | JWT header와 JWKS current key에 넣을 `kid` |
| `JWT_EXTRA_JWKS_KEYS` | `[]` | JWKS에 함께 노출할 이전 public JWK 목록(JSON 배열, 각 항목은 고유한 `kid`를 가져야 함) |
| `JWT_ISSUER` | `https://example.com` | JWT `iss` 클레임 값 |
| `JWT_TTL_SECONDS` | `3600` | 발급된 JWT의 유효 시간 (초) |

## 개발

의존성 관리는 `Cargo.toml` 기반입니다.

```bash
cargo build --release
USE_IN_MEMORY_STORE=true cargo run --release
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
  -p 2525:2525 \
  mapae:latest
```

### Stateless 스케일 아웃

운영 환경에서는 `USE_IN_MEMORY_STORE=false`로 Redis를 공유 저장소로 사용합니다. 애플리케이션 인스턴스는 인증 상태를 로컬 메모리에 보관하지 않으므로 HTTP와 SMTP를 sticky session 없이 수평 확장할 수 있습니다.

#### 권장 토폴로지

- HTTP API: `SERVER_MODE=http` 컨테이너 N개를 L7 Load Balancer 뒤에 둡니다. LB health check는 `/ready`, liveness check는 `/live`를 사용합니다.
- SMTP: 기본은 `SERVER_MODE=smtp` 컨테이너를 여러 노드에 띄우고, 동일 priority MX 레코드를 여러 A/AAAA record로 분산합니다.
- 단일 컨테이너에서 두 서버를 같이 실행해야 하면 `SERVER_MODE=all`을 사용합니다.
- SMTP 앞단에 L4 Load Balancer를 둘 경우 SPF 검증이 원 발신 IP에 의존하므로 source IP 보존이 필수입니다. source IP 보존이 불가능하면 PROXY protocol 지원을 별도로 구현해야 합니다.

예시:

```bash
# HTTP replica
docker run -d --name mapae-http-1 \
  --env-file .env \
  -e SERVER_MODE=http \
  -p 8000:8000 \
  mapae:latest

# SMTP replica
docker run -d --name mapae-smtp-1 \
  --env-file .env \
  -e SERVER_MODE=smtp \
  -p 25:2525 \
  mapae:latest
```

#### Redis HA

단일 리전에서는 Redis primary-replica HA를 권장합니다. `REDIS_WAIT_REPLICAS=1`로 설정하면 인증 상태 write 이후 replica acknowledgement를 기다리며, 충분한 replica가 확인되지 않으면 HTTP는 500, SMTP는 451 temporary error를 반환합니다.

Redis Cluster나 멀티 primary active-active 구성은 별도 설계가 필요합니다. 특히 멀티 primary eventual replication은 Nonce의 정확히 한 번 소비 보장을 깨뜨릴 수 있으므로 기본 배포 모델로 사용하지 않습니다.

#### 종료와 배포

SIGINT/SIGTERM을 받으면 먼저 `/ready`가 503으로 바뀌고, `SHUTDOWN_DRAIN_SECONDS` 이후 HTTP/SMTP accept loop가 종료됩니다. LB와 오케스트레이터의 drain 시간은 이 값보다 길게 잡습니다.

#### JWT 키 교체

1. 새 Ed25519 private key를 `JWT_PRIVATE_KEY`에 배포하고 새 `JWT_KEY_ID`를 설정합니다.
2. 이전 public JWK는 `JWT_EXTRA_JWKS_KEYS`에 JSON 배열로 넣어 JWKS에 함께 노출합니다.
3. `JWT_TTL_SECONDS`가 지난 뒤 이전 public JWK를 `JWT_EXTRA_JWKS_KEYS`에서 제거합니다.

## API 명세

아래 페이지에서 확인할 수 있습니다.

- [https://docs.mapae.hgseo.net](https://docs.mapae.hgseo.net)

## 통신사 호환성

| 통신사 | 발신 도메인 | 특이사항 대응 |
| :--- | :--- | :--- |
| SKT | vmms.nate.com | - |
| KT | mms.kt.co.kr | Broken Header 처리 (Message-ID 누락 등) |
| LGU+ | mmsmail.uplus.co.kr | - |

## License
MIT
