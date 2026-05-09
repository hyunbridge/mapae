use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, Error as Pkcs8Error};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashSet;
use thiserror::Error;
use time::OffsetDateTime;

use crate::config::Settings;

/// Ed25519 알고리즘을 사용한 JWT 서명기.
///
/// 휴대폰 인증이 성공적으로 완료되었을 때 클라이언트에게 반환할 보안 토큰(JWT)을 발급하고,
/// 외부 시스템에서 이를 검증할 수 있도록 JWKS 형식의 공개키를 제공합니다.
pub struct JwtSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    issuer: String,
    ttl_seconds: u64,
    key_id: String,
    extra_jwks_keys: Vec<Value>,
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
    #[error("serialize jwt")]
    Json(#[from] serde_json::Error),
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

#[derive(Serialize)]
struct JwtHeader<'a> {
    alg: &'static str,
    typ: &'static str,
    kid: &'a str,
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

        if settings.jwt_ttl_seconds == 0 {
            return Err(JwtError::InvalidConfig(
                "JWT_TTL_SECONDS must be greater than 0",
            ));
        }
        let key_id = normalize_key_id(&settings.jwt_key_id);
        let extra_jwks_keys = parse_extra_jwks_keys(&settings.jwt_extra_jwks_keys, &key_id)?;

        Ok(Some(Self {
            signing_key,
            verifying_key,
            issuer: settings.jwt_issuer.clone(),
            ttl_seconds: settings.jwt_ttl_seconds,
            key_id,
            extra_jwks_keys,
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

        let header = JwtHeader {
            alg: "EdDSA",
            typ: "JWT",
            kid: &self.key_id,
        };

        let header_json = serde_json::to_vec(&header)?;
        let claims_json = serde_json::to_vec(&claims)?;

        let encoded_header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);
        let encoded_claims = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims_json);

        let mut token = String::with_capacity(encoded_header.len() + encoded_claims.len() + 88);
        token.push_str(&encoded_header);
        token.push('.');
        token.push_str(&encoded_claims);

        let signature = self.signing_key.sign(token.as_bytes());
        token.push('.');
        token.push_str(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        );

        Ok(token)
    }

    /// Ed25519 공개키를 JWKS 문서로 직렬화합니다.
    pub fn jwks(&self) -> Result<Vec<u8>, JwtError> {
        let pub_bytes = self.verifying_key.to_bytes();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pub_bytes);

        let mut keys = vec![json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "use": "sig",
            "alg": "EdDSA",
            "kid": self.key_id.clone()
        })];
        keys.extend(self.extra_jwks_keys.iter().cloned());

        let jwks = json!({ "keys": keys });

        Ok(serde_json::to_vec(&jwks)?)
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

fn normalize_key_id(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        Settings::default().jwt_key_id
    } else {
        trimmed.to_string()
    }
}

fn parse_extra_jwks_keys(raw: &str, current_key_id: &str) -> Result<Vec<Value>, JwtError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let parsed: Vec<Value> = serde_json::from_str(trimmed)
        .map_err(|_| JwtError::InvalidConfig("JWT_EXTRA_JWKS_KEYS must be a JSON array"))?;

    let mut seen_kids = HashSet::new();
    for key in &parsed {
        let Some(object) = key.as_object() else {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must be JSON objects",
            ));
        };

        let Some(kid) = object.get("kid").and_then(Value::as_str) else {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must include string kid values",
            ));
        };
        let kid = kid.trim();
        if kid.is_empty() {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must include string kid values",
            ));
        }
        if kid == current_key_id {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS cannot duplicate the current kid",
            ));
        }
        if !seen_kids.insert(kid.to_string()) {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS contains duplicate kid values",
            ));
        }

        if object.get("kty").and_then(Value::as_str) != Some("OKP") {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must be OKP keys",
            ));
        }
        if object.get("crv").and_then(Value::as_str) != Some("Ed25519") {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must use Ed25519",
            ));
        }
        if let Some(key_use) = object.get("use").and_then(Value::as_str) {
            if key_use != "sig" {
                return Err(JwtError::InvalidConfig(
                    "JWT_EXTRA_JWKS_KEYS entries must be signature keys",
                ));
            }
        }
        if let Some(alg) = object.get("alg").and_then(Value::as_str) {
            if alg != "EdDSA" {
                return Err(JwtError::InvalidConfig(
                    "JWT_EXTRA_JWKS_KEYS entries must use EdDSA",
                ));
            }
        }

        let Some(x) = object.get("x").and_then(Value::as_str) else {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS entries must include public x values",
            ));
        };
        let decoded_x = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|_| {
                JwtError::InvalidConfig(
                    "JWT_EXTRA_JWKS_KEYS x values must be base64url-encoded public keys",
                )
            })?;
        if decoded_x.len() != 32 {
            return Err(JwtError::InvalidConfig(
                "JWT_EXTRA_JWKS_KEYS x values must be 32-byte Ed25519 public keys",
            ));
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{Signature, Verifier};
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
    fn test_normalize_key_id() {
        assert_eq!(normalize_key_id(" current "), "current");
        assert_eq!(normalize_key_id("  "), "default");
    }

    #[test]
    fn test_parse_extra_jwks_keys() {
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]);
        let keys = parse_extra_jwks_keys(
            &format!(r#"[{{"kid":"old","kty":"OKP","crv":"Ed25519","x":"{x}"}}]"#),
            "current",
        )
        .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "old");

        assert!(parse_extra_jwks_keys("", "current").unwrap().is_empty());
        assert!(parse_extra_jwks_keys("{}", "current").is_err());
        assert!(parse_extra_jwks_keys(r#"["bad"]"#, "current").is_err());
        assert!(parse_extra_jwks_keys(
            &format!(r#"[{{"kid":"current","kty":"OKP","crv":"Ed25519","x":"{x}"}}]"#),
            "current"
        )
        .is_err());
        assert!(parse_extra_jwks_keys(
            &format!(
                r#"[
                        {{"kid":"a","kty":"OKP","crv":"Ed25519","x":"{x}"}},
                        {{"kid":"a","kty":"OKP","crv":"Ed25519","x":"{x}"}}
                    ]"#
            ),
            "current"
        )
        .is_err());
        assert!(parse_extra_jwks_keys(
            r#"[{"kid":"old","kty":"RSA","crv":"Ed25519","x":"bad"}]"#,
            "current"
        )
        .is_err());
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
            jwt_key_id: "current-key".to_string(),
            jwt_extra_jwks_keys: format!(
                r#"[{{"kty":"OKP","crv":"Ed25519","x":"{}","use":"sig","alg":"EdDSA","kid":"old-key"}}]"#,
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32])
            ),
            jwt_issuer: "https://issuer.example".to_string(),
            jwt_ttl_seconds: 3600,
            ..Settings::default()
        };

        let signer = JwtSigner::new(&settings).unwrap().unwrap();

        let token = signer
            .sign("test-auth-id", "01012345678", "KT", "test-jti")
            .unwrap();

        let mut parts = token.split('.');
        let header_b64 = parts.next().unwrap();
        let claims_b64 = parts.next().unwrap();
        let signature_b64 = parts.next().unwrap();
        assert!(parts.next().is_none());

        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "current-key");

        let claims_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(claims_b64)
            .unwrap();
        let claims: JwtClaims = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims.auth_id, "test-auth-id");
        assert_eq!(claims.phone_number, "01012345678");
        assert_eq!(claims.carrier, "KT");
        assert_eq!(claims.iss, "https://issuer.example");

        let signing_input = format!("{header_b64}.{claims_b64}");
        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .unwrap();
        let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();
        assert!(signer
            .verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .is_ok());

        let jwks_bytes = signer.jwks().unwrap();
        let jwks: serde_json::Value = serde_json::from_slice(&jwks_bytes).unwrap();
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0]["alg"], "EdDSA");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["kid"], "current-key");
        assert_eq!(keys[1]["kid"], "old-key");
    }

    #[test]
    fn test_signer_rejects_invalid_extra_jwks_keys_when_enabled() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let pkcs8 = signing_key.to_pkcs8_pem(LineEnding::default()).unwrap();

        let settings = Settings {
            jwt_private_key_pem: pkcs8.to_string(),
            jwt_extra_jwks_keys: "not-json".to_string(),
            ..Settings::default()
        };

        assert!(matches!(
            JwtSigner::new(&settings),
            Err(JwtError::InvalidConfig(_))
        ));
    }
}
