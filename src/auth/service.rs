use crate::config::Settings;
use crate::storage::{StorageError, Store, StoreBackend};
use anyhow::Context;
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use super::jwt_signer::{JwtError, JwtSigner};

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

/// pending 인증 세션 저장 페이로드.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthPayload {
    /// 현재 세션 상태.
    pub status: String,
    /// 세션 생성 시각(UTC).
    pub timestamp: String,
}

/// Nonce 검증 이후 저장되는 페이로드.
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedPayload {
    /// 현재 세션 상태.
    pub status: String,
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
    pub status: String,
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
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
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
        let nonce = random_hex(32)?;
        let auth_id = random_hex(16)?;

        let payload = AuthPayload {
            status: "pending".to_string(),
            timestamp: now_rfc3339(),
        };
        let payload_json = serde_json::to_string(&payload)?;

        let auth_key = format!("auth:{auth_id}");
        let nonce_key = format!("nonce:{nonce}");

        self.store
            .set_ex(&auth_key, &payload_json, self.settings.auth_ttl_seconds)
            .await?;
        self.store
            .set_ex(&nonce_key, &auth_id, self.settings.auth_ttl_seconds)
            .await?;

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
        if !is_valid_auth_id(auth_id) {
            return Err(AuthError::InvalidAuthId);
        }

        let key = format!("auth:{auth_id}");
        let (value, ok) = self.store.get(&key).await?;
        if !ok {
            return Ok(auth_check_response("expired"));
        }

        match serde_json::from_str::<AuthCheckResponse>(&value) {
            Ok(decoded) if decoded.status == "verified" => Ok(decoded),
            _ => Ok(auth_check_response("waiting")),
        }
    }

    /// 이메일(SMTP)로 수신된 Nonce를 확인하여 해당 인증을 소모(Consume)합니다.
    ///
    /// 원자적 작업을 통해 동일한 Nonce가 중복 사용되지 않도록 보장합니다.
    pub async fn consume_auth_id_by_nonce(&self, nonce: &str) -> Result<(String, bool), AuthError> {
        Ok(self.store.take_nonce(nonce).await?)
    }

    /// 설정된 저장소 백엔드가 응답하는지 확인합니다.
    pub async fn ping(&self) -> Result<(), AuthError> {
        self.store.ping().await?;
        Ok(())
    }

    /// 소비된 인증 세션에 검증된 전화번호와 통신사를 저장합니다.
    pub async fn store_verified(
        &self,
        auth_id: &str,
        phone: Option<&str>,
        carrier: Option<&str>,
    ) -> Result<(), AuthError> {
        let payload = VerifiedPayload {
            status: "verified".to_string(),
            phone: phone.map(std::string::ToString::to_string),
            carrier: carrier.map(std::string::ToString::to_string),
            timestamp: now_rfc3339(),
        };
        let payload_json = serde_json::to_string(&payload)?;
        let key = format!("auth:{auth_id}");
        self.store
            .set_ex(&key, &payload_json, self.settings.verified_ttl_seconds)
            .await?;
        Ok(())
    }

    /// 서명이 설정된 경우 검증된 인증 결과와 JWT를 함께 반환합니다.
    pub async fn check_signed(&self, auth_id: &str) -> Result<AuthCheckResponse, AuthError> {
        if !is_valid_auth_id(auth_id) {
            return Err(AuthError::InvalidAuthId);
        }

        let key = format!("auth:{auth_id}");
        let (value, ok) = self.store.get(&key).await?;
        if !ok {
            return Ok(auth_check_response("expired"));
        }

        let decoded: AuthCheckResponse = match serde_json::from_str(&value) {
            Ok(decoded) => decoded,
            Err(_) => return Ok(auth_check_response("waiting")),
        };

        if decoded.status != "verified" {
            return Ok(auth_check_response("waiting"));
        }

        let signer = self.signer.as_ref().ok_or(AuthError::JwksUnavailable)?;

        let phone = decoded.phone.as_deref().unwrap_or("");
        if phone.is_empty() {
            return Ok(auth_check_response("waiting"));
        }

        let token = signer.sign(
            auth_id,
            phone,
            decoded.carrier.as_deref().unwrap_or(""),
            auth_id,
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
    auth_id.len() == 32 && auth_id.chars().all(|c| c.is_ascii_hexdigit())
}

fn auth_check_response(status: &'static str) -> AuthCheckResponse {
    AuthCheckResponse {
        status: status.to_string(),
        phone: None,
        carrier: None,
        timestamp: None,
        token: None,
    }
}

fn random_hex(bytes_len: usize) -> anyhow::Result<String> {
    if bytes_len == 0 {
        return Err(anyhow::anyhow!("invalid length"));
    }
    let mut buf = vec![0u8; bytes_len];
    getrandom::getrandom(&mut buf).context("generate random bytes")?;
    Ok(encode_hex(&buf))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn now_rfc3339() -> String {
    let now = OffsetDateTime::now_utc();
    let format =
        time::macros::format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    now.format(&format)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use crate::storage::memory::MemoryStore;
    use crate::storage::Store;

    #[tokio::test]
    async fn test_random_hex() {
        let val = random_hex(16).unwrap();
        assert_eq!(val.len(), 32);
        assert!(val.chars().all(|c| c.is_ascii_hexdigit()));

        assert!(random_hex(0).is_err());
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
        let svc = Service::new(crate::storage::StoreBackend::Memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        assert_eq!(init.auth_id.len(), 32);
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
        assert_eq!(check.status, "waiting");

        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        let (auth_id, ok) = svc.consume_auth_id_by_nonce(nonce).await.unwrap();
        assert!(ok);
        assert_eq!(auth_id, init.auth_id);

        let (_, ok) = svc.consume_auth_id_by_nonce(nonce).await.unwrap();
        assert!(!ok);

        svc.store_verified(&init.auth_id, Some("01012345678"), Some("KT"))
            .await
            .unwrap();

        let check = svc.check_auth(&init.auth_id).await.unwrap();
        assert_eq!(check.status, "verified");
        assert_eq!(check.phone.as_deref(), Some("01012345678"));
        assert_eq!(check.carrier.as_deref(), Some("KT"));
    }

    #[tokio::test]
    async fn test_check_signed_broken_payload_maps_to_waiting() {
        let store = MemoryStore::new();
        let auth_id = "b".repeat(32);
        store
            .set_ex(&format!("auth:{auth_id}"), "not-json", 60)
            .await
            .unwrap();
        let settings = Settings::default();
        let svc = Service::new(crate::storage::StoreBackend::Memory(store), &settings).unwrap();

        let check = svc.check_signed(&auth_id).await.unwrap();
        assert_eq!(check.status, "waiting");
    }

    #[tokio::test]
    async fn test_store_verified_writes_rfc3339_timestamp_without_fraction() {
        let store = MemoryStore::new();
        let settings = Settings::default();
        let svc = Service::new(crate::storage::StoreBackend::Memory(store), &settings).unwrap();
        let auth_id = "c".repeat(32);

        svc.store_verified(&auth_id, Some("01012345678"), Some("KT"))
            .await
            .unwrap();
        let check = svc.check_auth(&auth_id).await.unwrap();

        let timestamp = check.timestamp.unwrap();
        assert_eq!(timestamp.len(), "2006-01-02T15:04:05Z".len());
        assert!(timestamp.ends_with('Z'));
        assert!(!timestamp.contains('.'));
    }

    #[tokio::test]
    async fn test_consume_then_store_verified_flow() {
        let store = MemoryStore::new();
        let settings = Settings {
            auth_ttl_seconds: 60,
            verified_ttl_seconds: 0,
            sms_inbound_address: "verify@example.com".to_string(),
            jwt_issuer: "https://issuer.example".to_string(),
            jwt_ttl_seconds: 120,
            ..Settings::default()
        };
        let svc = Service::new(crate::storage::StoreBackend::Memory(store), &settings).unwrap();

        let init = svc.init_auth().await.unwrap();
        let nonce = init
            .sms_body
            .strip_prefix("[MAPAE:")
            .unwrap()
            .strip_suffix(']')
            .unwrap();

        let (auth_id, ok) = svc.consume_auth_id_by_nonce(nonce).await.unwrap();
        assert!(ok, "nonce should be consumed first");
        assert_eq!(auth_id, init.auth_id);

        let (_, ok) = svc.consume_auth_id_by_nonce(nonce).await.unwrap();
        assert!(!ok, "nonce should be consumed exactly once");

        let result = svc
            .store_verified(&auth_id, Some("01012345678"), Some("KT"))
            .await;
        assert!(result.is_err(), "store_verified should fail with ttl=0");

        let check = svc.check_auth(&auth_id).await.unwrap();
        assert_eq!(check.status, "waiting", "auth should not be verified");
    }
}
