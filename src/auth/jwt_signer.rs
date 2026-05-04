use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, Error as Pkcs8Error};
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use time::OffsetDateTime;

use crate::config::Settings;

/// Ed25519 알고리즘을 사용한 JWT 서명기.
///
/// 휴대폰 인증이 성공적으로 완료되었을 때 클라이언트에게 반환할 보안 토큰(JWT)을 발급하고,
/// 외부 시스템에서 이를 검증할 수 있도록 JWKS 형식의 공개키를 제공합니다.
pub struct JwtSigner {
    encoding_key: EncodingKey,
    verifying_key: VerifyingKey,
    issuer: String,
    ttl_seconds: u64,
}

/// JWT 서명 설정 또는 사용 중 발생하는 오류.
#[derive(Debug, Error)]
pub enum JwtError {
    #[error("parse ed25519 private key")]
    PrivateKey(#[from] Pkcs8Error),
    #[error("invalid jwt config: {0}")]
    InvalidConfig(&'static str),
    #[error("system clock before unix epoch")]
    ClockBeforeUnixEpoch,
    #[error("build jwt encoding key")]
    EncodingKey(jsonwebtoken::errors::Error),
    #[error("jwt encode")]
    Encode(#[from] jsonwebtoken::errors::Error),
    #[error("jwks marshal")]
    Jwks(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    auth_id: String,
    iat: usize,
    exp: usize,
    phone_number: String,
    carrier: String,
    jti: String,
}

impl JwtSigner {
    /// `JWT_PRIVATE_KEY`에서 서명기를 생성합니다.
    ///
    /// private key가 설정되지 않았으면 `Ok(None)`을 반환합니다.
    pub fn new(settings: &Settings) -> Result<Option<Self>, JwtError> {
        let pem_str = settings.jwt_private_key_pem.trim();
        if pem_str.is_empty() {
            return Ok(None);
        }

        let pem_str = normalize_pem(pem_str);
        let signing_key = SigningKey::from_pkcs8_pem(&pem_str)?;
        let verifying_key = signing_key.verifying_key();
        let encoding_key =
            EncodingKey::from_ed_pem(pem_str.as_bytes()).map_err(JwtError::EncodingKey)?;

        if settings.jwt_ttl_seconds == 0 {
            return Err(JwtError::InvalidConfig(
                "JWT_TTL_SECONDS must be greater than 0",
            ));
        }

        Ok(Some(Self {
            encoding_key,
            verifying_key,
            issuer: settings.jwt_issuer.clone(),
            ttl_seconds: settings.jwt_ttl_seconds,
        }))
    }

    /// 인증 정보를 기반으로 JWT를 발급합니다.
    ///
    /// 토큰의 페이로드(Claims)에는 `auth_id`, `phone_number`, `carrier` 등
    /// 인증된 사용자 정보와 식별자(`jti`)가 포함됩니다.
    pub fn sign(
        &self,
        auth_id: &str,
        phone_number: &str,
        carrier: &str,
        jti: &str,
    ) -> Result<String, JwtError> {
        let now = jwt_timestamp(OffsetDateTime::now_utc())?;
        let ttl = usize::try_from(self.ttl_seconds)
            .map_err(|_| JwtError::InvalidConfig("JWT_TTL_SECONDS is too large"))?;
        let exp = now
            .checked_add(ttl)
            .ok_or(JwtError::InvalidConfig("JWT_TTL_SECONDS is too large"))?;

        let claims = JwtClaims {
            iss: self.issuer.clone(),
            sub: phone_number.to_string(),
            auth_id: auth_id.to_string(),
            iat: now,
            exp,
            phone_number: phone_number.to_string(),
            carrier: carrier.to_string(),
            jti: jti.to_string(),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("JWT".to_string());

        jsonwebtoken::encode(&header, &claims, &self.encoding_key).map_err(JwtError::from)
    }

    /// Ed25519 공개키를 JWKS 문서로 직렬화합니다.
    pub fn jwks(&self) -> Result<Vec<u8>, JwtError> {
        let pub_bytes = self.verifying_key.to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);

        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": x,
                "use": "sig",
                "alg": "EdDSA"
            }]
        });

        serde_json::to_vec(&jwks).map_err(JwtError::from)
    }
}

fn jwt_timestamp(now: OffsetDateTime) -> Result<usize, JwtError> {
    usize::try_from(now.unix_timestamp()).map_err(|_| JwtError::ClockBeforeUnixEpoch)
}

fn normalize_pem(raw: &str) -> String {
    let mut value = raw.trim().to_string();

    while let Some(stripped) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
    {
        value = stripped.trim().to_string();
    }

    value = value.replace("\\r\\n", "\n");
    value = value.replace("\\n", "\n");
    value = value.replace("\r\n", "\n");

    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
    use pkcs8::LineEnding;

    #[test]
    fn test_normalize_pem() {
        let raw = "\"-----BEGIN PRIVATE KEY-----\\nabc\\r\\ndef\\n-----END PRIVATE KEY-----\"";
        let got = normalize_pem(raw);
        assert!(!got.contains("\\n"));
        assert!(!got.contains('"'));
        assert!(got.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(got.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_signer_optional() {
        let settings = Settings::default();
        let signer = JwtSigner::new(&Settings {
            jwt_private_key_pem: String::new(),
            ..settings
        })
        .unwrap();
        assert!(signer.is_none());
    }

    #[test]
    fn test_signer_rejects_zero_ttl_when_enabled() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let pkcs8 = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();

        let settings = Settings {
            jwt_private_key_pem: pkcs8.to_string(),
            jwt_ttl_seconds: 0,
            ..Settings::default()
        };

        assert!(matches!(
            JwtSigner::new(&settings),
            Err(JwtError::InvalidConfig(_))
        ));
    }

    #[test]
    fn test_jwt_timestamp_rejects_pre_epoch_clock() {
        let before_epoch = OffsetDateTime::from_unix_timestamp(-1).unwrap();
        assert!(matches!(
            jwt_timestamp(before_epoch),
            Err(JwtError::ClockBeforeUnixEpoch)
        ));
    }

    #[test]
    fn test_sign_and_jwks() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let pkcs8 = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();

        let settings = Settings {
            jwt_private_key_pem: pkcs8.to_string(),
            jwt_issuer: "https://issuer.example".to_string(),
            jwt_ttl_seconds: 3600,
            ..Settings::default()
        };

        let signer = JwtSigner::new(&settings).unwrap().unwrap();

        let token = signer
            .sign("test-auth-id", "01012345678", "KT", "test-jti")
            .unwrap();

        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.typ.as_deref(), Some("JWT"));

        let public_pem = signer
            .verifying_key
            .to_public_key_pem(LineEnding::default())
            .unwrap();
        let claims = decode::<JwtClaims>(
            &token,
            &DecodingKey::from_ed_pem(public_pem.as_bytes()).unwrap(),
            &Validation::new(Algorithm::EdDSA),
        )
        .unwrap();
        assert_eq!(claims.claims.auth_id, "test-auth-id");
        assert_eq!(claims.claims.phone_number, "01012345678");
        assert_eq!(claims.claims.carrier, "KT");
        assert_eq!(claims.claims.iss, "https://issuer.example");

        let jwks_bytes = signer.jwks().unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&jwks_bytes).unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["crv"], "Ed25519");
    }
}
