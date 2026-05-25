use crate::config::Settings;
use crate::metrics::METRICS;
use crate::storage::{StorageError, Store, StoreBackend};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::jwt_signer::{JwtError, JwtSigner};

const AUTH_ID_BYTES: usize = 16;
const AUTH_ID_HEX_LENGTH: usize = AUTH_ID_BYTES * 2;
const NONCE_BYTES: usize = 32;

#[cfg(test)]
const NONCE_HEX_LENGTH: usize = NONCE_BYTES * 2;

/// 클라이언트가 인증 세션을 시작할 때 받는 응답.
#[derive(Debug, Serialize)]
pub struct AuthInitResponse {
    /// 클라이언트가 상태를 폴링할 때 사용할 식별자.
    pub auth_id: String,
    /// 사용자가 SMS 이메일 주소로 보내야 하는 본문.
    pub sms_body: String,
    /// 인코딩된 본문을 포함한 `sms:` 딥링크.
    pub link: String,
    /// pending 세션 만료까지 남은 초.
    pub ttl_seconds: u64,
}

/// 인증 세션과 상태 조회 응답에서 사용하는 상태값.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthStatus {
    Pending,
    Waiting,
    Verified,
    Expired,
}

/// pending 인증 세션 저장 페이로드.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    /// 현재 세션 상태.
    pub status: AuthStatus,
    /// 세션 생성 시각(UTC).
    pub timestamp: String,
}

/// Nonce 검증 이후 저장되는 페이로드.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedPayload {
    /// 현재 세션 상태.
    pub status: AuthStatus,
    /// 통신사 이메일 주소에서 얻은 정규화된 전화번호.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// 발신 도메인에서 추론한 통신사.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    /// 검증 완료 시각(UTC).
    pub timestamp: String,
}

/// 인증 상태 조회 엔드포인트의 응답.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthCheckResponse {
    /// `waiting`, `verified`, or `expired`.
    pub status: AuthStatus,
    /// 성공 후에만 포함되는 검증된 전화번호.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// 성공 후에만 포함되는 검증된 통신사.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub carrier: Option<String>,
    /// 성공 후에만 포함되는 검증 시각.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// signed check 엔드포인트에서만 포함되는 JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

/// 인증 세션, Nonce 소비, 검증 상태, 선택적 JWT 발급을 관리합니다.
pub struct Service {
    store: StoreBackend,
    settings: Settings,
    signer: Option<JwtSigner>,
}

/// 인증 서비스에서 반환하는 오류.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid auth_id")]
    InvalidAuthId,
    #[error("jwks unavailable")]
    JwksUnavailable,
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Jwt(#[from] JwtError),
    #[error("invalid random byte length")]
    InvalidRandomLength,
    #[error("random byte generation failed: {0}")]
    Random(getrandom::Error),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

impl Service {
    /// 선택된 저장소 백엔드로 서비스를 생성합니다.
    ///
    /// `JWT_PRIVATE_KEY`가 설정된 경우에만 JWT 서명을 활성화합니다.
    pub fn new(store: StoreBackend, settings: &Settings) -> Result<Self, AuthError> {
        let signer = JwtSigner::new(settings)?;
        Ok(Self {
            store,
            settings: settings.clone(),
            signer,
        })
    }

    /// 새로운 인증 세션을 초기화합니다.
    ///
    /// 내부적으로 32바이트 Nonce와 16바이트 `auth_id`를 생성하여 분리 저장하며,
    /// 클라이언트가 SMS를 전송할 수 있는 딥링크(`sms:`)를 반환합니다.
    pub async fn init_auth(&self) -> Result<AuthInitResponse, AuthError> {
        let nonce = random_hex(NONCE_BYTES)?;
        let auth_id = random_hex(AUTH_ID_BYTES)?;

        let payload = AuthPayload {
            status: AuthStatus::Pending,
            timestamp: now_rfc3339(),
        };
        let payload_json = serde_json::to_string(&payload)?;

        let auth_key = format!("auth:{auth_id}");
        let nonce_key = format!("nonce:{nonce}");

        self.store
            .init_auth_session(
                &auth_key,
                &payload_json,
                &nonce_key,
                &auth_id,
                self.settings.auth_ttl_seconds,
            )
            .await
            .map_storage_error()?;

        let sms_body = format!("[MAPAE:{nonce}]");
        Ok(AuthInitResponse {
            auth_id,
            sms_body: sms_body.clone(),
            link: format!(
                "sms:{}?body={}",
                self.settings.sms_inbound_address,
                utf8_percent_encode(&sms_body, NON_ALPHANUMERIC)
            ),
            ttl_seconds: self.settings.auth_ttl_seconds,
        })
    }

    /// JWT를 발급하지 않고 현재 인증 상태를 반환합니다.
    pub async fn check_auth(&self, auth_id: &str) -> Result<AuthCheckResponse, AuthError> {
        self.load_auth_check_response(auth_id).await
    }

    async fn load_auth_check_response(
        &self,
        auth_id: &str,
    ) -> Result<AuthCheckResponse, AuthError> {
        if !is_valid_auth_id(auth_id) {
            return Err(AuthError::InvalidAuthId);
        }

        let key = format!("auth:{auth_id}");
        let Some(value) = self.store.get(&key).await.map_storage_error()? else {
            return Ok(auth_check_response(AuthStatus::Expired));
        };

        match serde_json::from_str::<AuthCheckResponse>(&value) {
            Ok(decoded) if is_complete_verified_response(&decoded) => Ok(decoded),
            _ => Ok(auth_check_response(AuthStatus::Waiting)),
        }
    }

    /// 설정된 저장소 백엔드가 응답하는지 확인합니다.
    pub async fn ping(&self) -> Result<(), AuthError> {
        self.store.ping().await.map_storage_error()?;
        Ok(())
    }

    /// Nonce를 단 한 번 소모하고, 같은 저장소 작업 안에서 인증 완료 상태를 저장합니다.
    pub async fn consume_nonce_and_store_verified(
        &self,
        nonce: &str,
        phone: Option<&str>,
        carrier: Option<&str>,
    ) -> Result<Option<String>, AuthError> {
        let payload = VerifiedPayload {
            status: AuthStatus::Verified,
            phone: phone.map(std::string::ToString::to_string),
            carrier: carrier.map(std::string::ToString::to_string),
            timestamp: now_rfc3339(),
        };
        let payload_json = serde_json::to_string(&payload)?;

        self.store
            .consume_nonce_and_store_verified(
                nonce,
                &payload_json,
                self.settings.verified_ttl_seconds,
            )
            .await
            .map_storage_error()
    }

    /// 서명이 설정된 경우 검증된 인증 결과와 JWT를 함께 반환합니다.
    pub async fn check_signed(&self, auth_id: &str) -> Result<AuthCheckResponse, AuthError> {
        let decoded = self.check_auth(auth_id).await?;
        if decoded.status != AuthStatus::Verified {
            return Ok(decoded);
        }

        let signer = self.signer.as_ref().ok_or(AuthError::JwksUnavailable)?;

        let phone = decoded.phone.as_deref().unwrap_or("");
        if phone.is_empty() {
            return Ok(auth_check_response(AuthStatus::Waiting));
        }

        let jti = random_hex(NONCE_BYTES)?;
        let token = signer.sign(
            auth_id,
            phone,
            decoded.carrier.as_deref().unwrap_or(""),
            &jti,
        )?;

        Ok(AuthCheckResponse {
            token: Some(token),
            ..decoded
        })
    }

    /// 설정된 서명 키의 공개 JWKS 문서를 반환합니다.
    pub fn jwks(&self) -> Result<Vec<u8>, AuthError> {
        let signer = self.signer.as_ref().ok_or(AuthError::JwksUnavailable)?;
        Ok(signer.jwks()?)
    }
}

fn is_valid_auth_id(auth_id: &str) -> bool {
    auth_id.len() == AUTH_ID_HEX_LENGTH && auth_id.chars().all(|c| c.is_ascii_hexdigit())
}

fn auth_check_response(status: AuthStatus) -> AuthCheckResponse {
    AuthCheckResponse {
        status,
        phone: None,
        carrier: None,
        timestamp: None,
        token: None,
    }
}

fn is_complete_verified_response(response: &AuthCheckResponse) -> bool {
    response.status == AuthStatus::Verified
        && response
            .phone
            .as_deref()
            .is_some_and(|phone| !phone.is_empty())
        && response
            .carrier
            .as_deref()
            .is_some_and(|carrier| !carrier.is_empty())
        && response
            .timestamp
            .as_deref()
            .is_some_and(|timestamp| !timestamp.is_empty())
}

fn random_hex(bytes_len: usize) -> Result<String, AuthError> {
    if bytes_len == 0 {
        return Err(AuthError::InvalidRandomLength);
    }
    let mut buf = vec![0u8; bytes_len];
    getrandom::getrandom(&mut buf).map_err(AuthError::Random)?;
    Ok(hex::encode(buf))
}

fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let format =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    now.format(&format)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

trait MapStorageError<T> {
    fn map_storage_error(self) -> Result<T, AuthError>;
}

impl<T> MapStorageError<T> for Result<T, StorageError> {
    fn map_storage_error(self) -> Result<T, AuthError> {
        self.map_err(|err| {
            if matches!(
                err,
                StorageError::Redis(_) | StorageError::InsufficientReplicas { .. }
            ) {
                METRICS.inc_redis_error();
            }
            AuthError::Storage(err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::storage::memory::MemoryStore;
    use crate::storage::Store;

    #[tokio::test]
    async fn test_random_hex() {
        let val = random_hex(AUTH_ID_BYTES).unwrap();
        assert_eq!(val.len(), AUTH_ID_HEX_LENGTH);
        assert!(val.chars().all(|c| c.is_ascii_hexdigit()));

        assert!(random_hex(0).is_err());
    }

    #[test]
    fn test_auth_id_validation_uses_16_byte_hex_encoding() {
        assert_eq!(AUTH_ID_HEX_LENGTH, 32);
        assert_eq!(NONCE_HEX_LENGTH, 64);

        assert!(is_valid_auth_id(&"a".repeat(AUTH_ID_HEX_LENGTH)));
        assert!(!is_valid_auth_id(&"a".repeat(AUTH_ID_HEX_LENGTH - 1)));
        assert!(!is_valid_auth_id(&"a".repeat(AUTH_ID_HEX_LENGTH + 1)));
        assert!(!is_valid_auth_id(&format!(
            "{}z",
            "a".repeat(AUTH_ID_HEX_LENGTH - 1)
        )));
    }

    #[tokio::test]
    async fn test_init_auth_and_verify_flow() {
        let store = MemoryStore::new();
        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 30,
            sms_inbound_address: "verify@example.com".to_string(),
            jwt_issuer: "https://issuer.example".to_string(),
            jwt_ttl_seconds: 120,
            ..Settings::default()
        };
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        assert_eq!(init.auth_id.len(), AUTH_ID_HEX_LENGTH);
        assert!(init.auth_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(init.sms_body.starts_with("[MAPAE:"));
        assert_eq!(
            init.link,
            format!(
                "sms:{}?body={}",
                settings.sms_inbound_address,
                utf8_percent_encode(&init.sms_body, NON_ALPHANUMERIC)
            )
        );
        assert_eq!(init.ttl_seconds, 60);

        let check = svc.check_auth(&init.auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Waiting);

        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        let auth_id = svc
            .consume_nonce_and_store_verified(nonce, Some("01012345678"), Some("KT"))
            .await
            .unwrap();
        assert_eq!(auth_id.as_deref(), Some(init.auth_id.as_str()));

        let ok = svc
            .consume_nonce_and_store_verified(nonce, Some("01000000000"), Some("SKT"))
            .await
            .unwrap();
        assert!(ok.is_none());

        let check = svc.check_auth(&init.auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Verified);
        assert_eq!(check.phone.as_deref(), Some("01012345678"));
        assert_eq!(check.carrier.as_deref(), Some("KT"));
    }

    #[tokio::test]
    async fn test_check_signed_jti_is_random() {
        use base64::Engine;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        use ed25519_dalek::pkcs8::EncodePrivateKey;
        use ed25519_dalek::SigningKey;

        let store = MemoryStore::new();
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let pkcs8 = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();

        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 30,
            sms_inbound_address: "verify@example.com".to_string(),
            jwt_private_key_pem: pkcs8.to_string(),
            jwt_key_id: "test-key".to_string(),
            jwt_issuer: "https://issuer.example".to_string(),
            jwt_ttl_seconds: 120,
            ..Settings::default()
        };

        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        svc.consume_nonce_and_store_verified(nonce, Some("01012345678"), Some("KT"))
            .await
            .unwrap();

        let first = svc.check_signed(&init.auth_id).await.unwrap();
        let second = svc.check_signed(&init.auth_id).await.unwrap();
        assert_eq!(first.status, AuthStatus::Verified);
        assert_eq!(second.status, AuthStatus::Verified);

        fn decode_claims(token: &str) -> serde_json::Value {
            let mut parts = token.split('.');
            let _header_b64 = parts.next().unwrap();
            let claims_b64 = parts.next().unwrap();
            let _signature_b64 = parts.next().unwrap();
            assert!(parts.next().is_none());

            let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(claims_b64)
                .unwrap();
            serde_json::from_slice(&claims_bytes).unwrap()
        }

        let first_claims = decode_claims(first.token.as_deref().unwrap());
        let second_claims = decode_claims(second.token.as_deref().unwrap());

        assert_eq!(
            first_claims["auth_id"].as_str(),
            Some(init.auth_id.as_str())
        );
        assert_eq!(
            second_claims["auth_id"].as_str(),
            Some(init.auth_id.as_str())
        );

        let first_jti = first_claims["jti"].as_str().unwrap();
        let second_jti = second_claims["jti"].as_str().unwrap();
        assert_ne!(first_jti, init.auth_id);
        assert_ne!(second_jti, init.auth_id);
        assert_ne!(first_jti, second_jti);
        assert_eq!(first_jti.len(), NONCE_HEX_LENGTH);
        assert_eq!(second_jti.len(), NONCE_HEX_LENGTH);
        assert!(first_jti.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(second_jti.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_check_signed_broken_payload_maps_to_waiting() {
        let store = MemoryStore::new();
        let auth_id = "b".repeat(AUTH_ID_HEX_LENGTH);
        store
            .set_ex(&format!("auth:{auth_id}"), "not-json", 60)
            .await
            .unwrap();
        let settings = Settings::default();
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let check = svc.check_signed(&auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Waiting);
    }

    #[tokio::test]
    async fn test_incomplete_verified_payload_maps_to_waiting() {
        let store = MemoryStore::new();
        let auth_id = "b".repeat(AUTH_ID_HEX_LENGTH);
        store
            .set_ex(
                &format!("auth:{auth_id}"),
                r#"{"status":"verified","timestamp":"2026-05-08T00:00:00Z"}"#,
                60,
            )
            .await
            .unwrap();
        let settings = Settings::default();
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let check = svc.check_auth(&auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Waiting);
    }

    #[test]
    fn test_auth_status_serializes_as_lowercase_string() {
        let response = auth_check_response(AuthStatus::Verified);

        assert_eq!(
            serde_json::to_value(response).unwrap()["status"],
            serde_json::json!("verified")
        );
    }

    #[tokio::test]
    async fn test_store_verified_writes_rfc3339_timestamp_without_fraction() {
        let store = MemoryStore::new();
        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 30,
            sms_inbound_address: "verify@example.com".to_string(),
            ..Settings::default()
        };
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();
        let init = svc.init_auth().await.unwrap();
        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        svc.consume_nonce_and_store_verified(nonce, Some("01012345678"), Some("KT"))
            .await
            .unwrap();
        let check = svc.check_auth(&init.auth_id).await.unwrap();

        let timestamp = check.timestamp.unwrap();
        assert_eq!(timestamp.len(), "2006-01-02T15:04:05Z".len());
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp.contains('.'));
    }

    #[tokio::test]
    async fn test_consume_nonce_and_store_verified_flow() {
        let store = MemoryStore::new();
        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 30,
            sms_inbound_address: "verify@example.com".to_string(),
            ..Settings::default()
        };
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        let auth_id = svc
            .consume_nonce_and_store_verified(nonce, Some("01012345678"), Some("KT"))
            .await
            .unwrap();
        assert_eq!(auth_id.as_deref(), Some(init.auth_id.as_str()));

        let ok = svc
            .consume_nonce_and_store_verified(nonce, Some("01000000000"), Some("SKT"))
            .await
            .unwrap();
        assert!(ok.is_none());

        let check = svc.check_auth(&init.auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Verified);
        assert_eq!(check.phone.as_deref(), Some("01012345678"));
        assert_eq!(check.carrier.as_deref(), Some("KT"));
    }

    #[tokio::test]
    async fn test_consume_nonce_and_store_verified_rejects_zero_ttl_without_consuming_nonce() {
        let store = MemoryStore::new();
        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 0,
            sms_inbound_address: "verify@example.com".to_string(),
            ..Settings::default()
        };
        let svc = Service::new(crate::storage::StoreBackend::memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        let result = svc
            .consume_nonce_and_store_verified(nonce, Some("01012345678"), Some("KT"))
            .await;
        assert!(result.is_err());

        let check = svc.check_auth(&init.auth_id).await.unwrap();
        assert_eq!(check.status, AuthStatus::Waiting);
    }
}
