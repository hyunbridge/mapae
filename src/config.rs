use std::fmt::Display;
use std::str::FromStr;

use anyhow::bail;
use serde::de::Error as _;
use serde::Deserialize;

/// 런타임에서 실행할 서버 조합.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerMode {
    All,
    Http,
    Smtp,
}

impl ServerMode {
    pub fn runs_http(self) -> bool {
        matches!(self, Self::All | Self::Http)
    }

    pub fn runs_smtp(self) -> bool {
        matches!(self, Self::All | Self::Smtp)
    }
}

/// 환경변수에서 읽어오는 런타임 설정.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// `RUST_LOG`가 없을 때 debug 레벨 로그를 활성화합니다.
    #[serde(deserialize_with = "deserialize_bool_or_default")]
    pub debug: bool,
    /// 실행할 서버 조합.
    #[serde(deserialize_with = "deserialize_server_mode")]
    pub server_mode: ServerMode,
    /// 종료 요청 후 readiness를 내리고 accept loop를 멈추기 전까지 기다릴 시간.
    #[serde(deserialize_with = "deserialize_shutdown_drain_seconds")]
    pub shutdown_drain_seconds: u64,
    /// Redis 대신 프로세스 로컬 메모리 저장소를 사용합니다.
    #[serde(deserialize_with = "deserialize_bool_or_default")]
    pub use_in_memory_store: bool,
    /// 메모리 저장소를 쓰지 않을 때 사용할 Redis 연결 URL.
    pub redis_url: String,
    /// Redis write 후 기다릴 replica acknowledgement 개수. 0이면 비활성화합니다.
    #[serde(deserialize_with = "deserialize_redis_wait_replicas")]
    pub redis_wait_replicas: usize,
    /// Redis WAIT 명령 타임아웃(ms).
    #[serde(deserialize_with = "deserialize_redis_wait_timeout_ms")]
    pub redis_wait_timeout_ms: u64,
    /// SMTP 리스너 호스트.
    pub smtp_host: String,
    /// SMTP 리스너 포트.
    #[serde(deserialize_with = "deserialize_smtp_port")]
    pub smtp_port: u16,
    /// 동시에 처리할 최대 SMTP 세션 수.
    #[serde(deserialize_with = "deserialize_smtp_max_connections")]
    pub smtp_max_connections: usize,
    /// 통신사 MMS 이메일을 수신할 주소.
    pub sms_inbound_address: String,
    /// 디버깅용 inbound 메시지 일부를 로그로 남깁니다.
    #[serde(deserialize_with = "deserialize_bool_or_default")]
    pub dump_inbound: bool,
    /// HTTP 리스너 호스트.
    pub http_host: String,
    /// HTTP 리스너 포트.
    #[serde(deserialize_with = "deserialize_http_port")]
    pub http_port: u16,
    /// 동시에 처리할 최대 HTTP 연결 수.
    #[serde(deserialize_with = "deserialize_http_max_connections")]
    pub http_max_connections: usize,
    /// 허용할 CORS origin 목록. `*`는 모든 origin을 허용합니다.
    #[serde(deserialize_with = "deserialize_cors_allow_origins")]
    pub cors_allow_origins: Vec<String>,
    /// pending 인증 세션 TTL.
    #[serde(deserialize_with = "deserialize_auth_ttl_seconds")]
    pub auth_ttl_seconds: u64,
    /// verified 인증 결과 TTL.
    #[serde(deserialize_with = "deserialize_verified_ttl_seconds")]
    pub verified_ttl_seconds: u64,
    /// JWT 서명에 사용할 Ed25519 PKCS#8 private key PEM.
    #[serde(rename = "jwt_private_key")]
    pub jwt_private_key_pem: String,
    /// JWT header와 JWKS current key에 넣을 key id.
    pub jwt_key_id: String,
    /// JWKS에 함께 노출할 이전 public JWK 목록(JSON array).
    pub jwt_extra_jwks_keys: String,
    /// JWT issuer claim.
    pub jwt_issuer: String,
    /// JWT 유효 기간.
    #[serde(deserialize_with = "deserialize_jwt_ttl_seconds")]
    pub jwt_ttl_seconds: u64,
}

impl Settings {
    /// 환경변수를 읽고 비어 있는 값은 기본값으로 채웁니다.
    pub fn load() -> anyhow::Result<Self> {
        envy::from_env::<Self>()?.normalized()
    }

    fn normalized(mut self) -> anyhow::Result<Self> {
        self.redis_url = self.redis_url.trim().to_string();
        self.smtp_host = self.smtp_host.trim().to_string();
        self.sms_inbound_address = self.sms_inbound_address.trim().to_string();
        self.http_host = self.http_host.trim().to_string();
        self.jwt_key_id = self.jwt_key_id.trim().to_string();
        self.jwt_extra_jwks_keys = self.jwt_extra_jwks_keys.trim().to_string();
        self.jwt_issuer = self.jwt_issuer.trim().to_string();
        self.cors_allow_origins = normalize_cors_allow_origins(self.cors_allow_origins);
        if self.smtp_max_connections == 0 {
            bail!("SMTP_MAX_CONNECTIONS must be greater than 0");
        }
        if self.http_max_connections == 0 {
            bail!("HTTP_MAX_CONNECTIONS must be greater than 0");
        }

        if self.auth_ttl_seconds == 0 {
            bail!("AUTH_TTL_SECONDS must be greater than 0");
        }
        if self.verified_ttl_seconds == 0 {
            bail!("VERIFIED_TTL_SECONDS must be greater than 0");
        }
        if self.jwt_ttl_seconds == 0 {
            bail!("JWT_TTL_SECONDS must be greater than 0");
        }
        if self.redis_wait_replicas > 0 && self.redis_wait_timeout_ms == 0 {
            bail!("REDIS_WAIT_TIMEOUT_MS must be greater than 0 when REDIS_WAIT_REPLICAS is set");
        }

        Ok(self)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            debug: false,
            server_mode: ServerMode::All,
            shutdown_drain_seconds: 5,
            use_in_memory_store: false,
            redis_url: String::new(),
            redis_wait_replicas: 0,
            redis_wait_timeout_ms: 1000,
            smtp_host: "0.0.0.0".to_string(),
            smtp_port: 2525,
            smtp_max_connections: 1024,
            sms_inbound_address: "verify@example.com".to_string(),
            dump_inbound: false,
            http_host: "0.0.0.0".to_string(),
            http_port: 8000,
            http_max_connections: 1024,
            cors_allow_origins: vec!["*".to_string()],
            auth_ttl_seconds: 600,
            verified_ttl_seconds: 300,
            jwt_private_key_pem: String::new(),
            jwt_key_id: "default".to_string(),
            jwt_extra_jwks_keys: "[]".to_string(),
            jwt_issuer: "https://example.com".to_string(),
            jwt_ttl_seconds: 3600,
        }
    }
}

fn deserialize_bool_or_default<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(false);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }

    match trimmed.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(D::Error::custom(format!("invalid boolean value: {value}"))),
    }
}

fn deserialize_server_mode<'de, D>(deserializer: D) -> Result<ServerMode, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(Settings::default().server_mode);
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(ServerMode::All),
        "http" => Ok(ServerMode::Http),
        "smtp" => Ok(ServerMode::Smtp),
        _ => Err(D::Error::custom(format!("invalid server mode: {value}"))),
    }
}

fn deserialize_smtp_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().smtp_port)
}

fn deserialize_shutdown_drain_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().shutdown_drain_seconds)
}

fn deserialize_smtp_max_connections<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().smtp_max_connections)
}

fn deserialize_http_port<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().http_port)
}

fn deserialize_http_max_connections<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().http_max_connections)
}

fn deserialize_redis_wait_replicas<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().redis_wait_replicas)
}

fn deserialize_redis_wait_timeout_ms<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().redis_wait_timeout_ms)
}

fn deserialize_auth_ttl_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().auth_ttl_seconds)
}

fn deserialize_verified_ttl_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().verified_ttl_seconds)
}

fn deserialize_jwt_ttl_seconds<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_from_str_or_missing(deserializer, || Settings::default().jwt_ttl_seconds)
}

fn deserialize_from_str_or_missing<'de, D, T>(
    deserializer: D,
    default: impl FnOnce() -> T,
) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
    T::Err: Display,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(default());
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(default());
    }

    trimmed.parse::<T>().map_err(|err| {
        D::Error::custom(format!(
            "invalid value for environment variable: {trimmed}: {err}"
        ))
    })
}

fn deserialize_cors_allow_origins<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(Settings::default().cors_allow_origins);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(Settings::default().cors_allow_origins);
    }

    if trimmed.starts_with('[') {
        let parsed = serde_json::from_str::<Vec<String>>(trimmed)
            .map_err(|err| D::Error::custom(format!("invalid CORS_ALLOW_ORIGINS JSON: {err}")))?;
        return Ok(parsed);
    }

    let out: Vec<String> = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        Ok(Settings::default().cors_allow_origins)
    } else {
        Ok(out)
    }
}

fn normalize_cors_allow_origins(origins: Vec<String>) -> Vec<String> {
    let mut normalized: Vec<String> = origins
        .into_iter()
        .map(|origin| origin.trim().to_string())
        .filter(|origin| !origin.is_empty())
        .collect();

    if normalized.is_empty() {
        normalized = Settings::default().cors_allow_origins;
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn settings_result_from_env(values: &[(&str, &str)]) -> anyhow::Result<Settings> {
        envy::from_iter::<_, Settings>(
            values
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string())),
        )?
        .normalized()
    }

    fn settings_from_env(values: &[(&str, &str)]) -> Settings {
        settings_result_from_env(values).unwrap()
    }

    #[test]
    fn test_env_bool() {
        assert!(settings_from_env(&[("DEBUG", "yes")]).debug);
        assert!(!settings_from_env(&[("DEBUG", "off")]).debug);

        assert!(
            envy::from_iter::<_, Settings>(vec![("DEBUG".to_string(), "unknown".to_string())])
                .is_err()
        );
    }

    #[test]
    fn test_env_server_mode() {
        assert_eq!(
            settings_from_env(&[("SERVER_MODE", "http")]).server_mode,
            ServerMode::Http
        );
        assert_eq!(
            settings_from_env(&[("SERVER_MODE", "SMTP")]).server_mode,
            ServerMode::Smtp
        );
        assert!(envy::from_iter::<_, Settings>(vec![(
            "SERVER_MODE".to_string(),
            "invalid".to_string()
        )])
        .is_err());
    }

    #[test]
    fn test_env_numbers() {
        let settings = settings_from_env(&[
            ("SMTP_PORT", "2526"),
            ("HTTP_PORT", " 9000 "),
            ("SMTP_MAX_CONNECTIONS", "512"),
            ("HTTP_MAX_CONNECTIONS", "2048"),
            ("REDIS_WAIT_REPLICAS", "2"),
            ("REDIS_WAIT_TIMEOUT_MS", "1500"),
            ("SHUTDOWN_DRAIN_SECONDS", "7"),
        ]);

        assert_eq!(settings.smtp_port, 2526);
        assert_eq!(settings.http_port, 9000);
        assert_eq!(settings.smtp_max_connections, 512);
        assert_eq!(settings.http_max_connections, 2048);
        assert_eq!(settings.redis_wait_replicas, 2);
        assert_eq!(settings.redis_wait_timeout_ms, 1500);
        assert_eq!(settings.shutdown_drain_seconds, 7);

        assert!(envy::from_iter::<_, Settings>(vec![(
            "HTTP_MAX_CONNECTIONS".to_string(),
            "not-a-number".to_string()
        )])
        .is_err());

        assert!(settings_result_from_env(&[("SMTP_MAX_CONNECTIONS", "0")]).is_err());
        assert!(settings_result_from_env(&[("HTTP_MAX_CONNECTIONS", "0")]).is_err());
        assert!(settings_result_from_env(&[
            ("REDIS_WAIT_REPLICAS", "1"),
            ("REDIS_WAIT_TIMEOUT_MS", "0")
        ])
        .is_err());
        assert!(settings_result_from_env(&[("JWT_TTL_SECONDS", "0")]).is_err());
    }

    #[test]
    fn test_env_list() {
        assert_eq!(
            settings_from_env(&[("CORS_ALLOW_ORIGINS", "a, b, ,c")]).cors_allow_origins,
            vec!["a", "b", "c"]
        );

        assert_eq!(
            settings_from_env(&[(
                "CORS_ALLOW_ORIGINS",
                r#"["https://a.example"," https://b.example "]"#
            )])
            .cors_allow_origins,
            vec!["https://a.example", "https://b.example"]
        );

        assert_eq!(
            settings_from_env(&[("CORS_ALLOW_ORIGINS", "[]")]).cors_allow_origins,
            vec!["*"]
        );
        assert_eq!(
            settings_from_env(&[("CORS_ALLOW_ORIGINS", "  ")]).cors_allow_origins,
            vec!["*"]
        );
    }

    #[test]
    fn test_load_defaults() {
        for var in &[
            "DEBUG",
            "SERVER_MODE",
            "SHUTDOWN_DRAIN_SECONDS",
            "USE_IN_MEMORY_STORE",
            "REDIS_URL",
            "REDIS_WAIT_REPLICAS",
            "REDIS_WAIT_TIMEOUT_MS",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_MAX_CONNECTIONS",
            "SMS_INBOUND_ADDRESS",
            "DUMP_INBOUND",
            "HTTP_HOST",
            "HTTP_PORT",
            "HTTP_MAX_CONNECTIONS",
            "CORS_ALLOW_ORIGINS",
            "AUTH_TTL_SECONDS",
            "VERIFIED_TTL_SECONDS",
            "JWT_PRIVATE_KEY",
            "JWT_KEY_ID",
            "JWT_EXTRA_JWKS_KEYS",
            "JWT_ISSUER",
            "JWT_TTL_SECONDS",
        ] {
            env::remove_var(var);
        }
        let s = Settings::load().unwrap();
        assert!(!s.debug);
        assert_eq!(s.server_mode, ServerMode::All);
        assert_eq!(s.shutdown_drain_seconds, 5);
        assert!(!s.use_in_memory_store);
        assert!(s.redis_url.is_empty());
        assert_eq!(s.redis_wait_replicas, 0);
        assert_eq!(s.redis_wait_timeout_ms, 1000);
        assert_eq!(s.smtp_host, "0.0.0.0");
        assert_eq!(s.smtp_port, 2525);
        assert_eq!(s.smtp_max_connections, 1024);
        assert_eq!(s.sms_inbound_address, "verify@example.com");
        assert!(!s.dump_inbound);
        assert_eq!(s.http_host, "0.0.0.0");
        assert_eq!(s.http_port, 8000);
        assert_eq!(s.http_max_connections, 1024);
        assert_eq!(s.cors_allow_origins, vec!["*"]);
        assert_eq!(s.auth_ttl_seconds, 600);
        assert_eq!(s.verified_ttl_seconds, 300);
        assert_eq!(s.jwt_key_id, "default");
        assert_eq!(s.jwt_extra_jwks_keys, "[]");
        assert_eq!(s.jwt_issuer, "https://example.com");
        assert_eq!(s.jwt_ttl_seconds, 3600);
    }
}
