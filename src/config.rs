use std::str::FromStr;

use serde::Deserialize;

/// 환경변수에서 읽어오는 런타임 설정.
#[derive(Debug, Clone)]
pub struct Settings {
    /// `RUST_LOG`가 없을 때 debug 레벨 로그를 활성화합니다.
    pub debug: bool,
    /// Redis 대신 프로세스 로컬 메모리 저장소를 사용합니다.
    pub use_in_memory_store: bool,
    /// 메모리 저장소를 쓰지 않을 때 사용할 Redis 연결 URL.
    pub redis_url: String,
    /// SMTP 리스너 호스트.
    pub smtp_host: String,
    /// SMTP 리스너 포트.
    pub smtp_port: u16,
    /// 동시에 처리할 최대 SMTP 세션 수.
    pub smtp_max_connections: usize,
    /// 통신사 MMS 이메일을 수신할 주소.
    pub sms_inbound_address: String,
    /// 디버깅용 inbound 메시지 일부를 로그로 남깁니다.
    pub dump_inbound: bool,
    /// HTTP 리스너 호스트.
    pub http_host: String,
    /// HTTP 리스너 포트.
    pub http_port: u16,
    /// 동시에 처리할 최대 HTTP 연결 수.
    pub http_max_connections: usize,
    /// 허용할 CORS origin 목록. `*`는 모든 origin을 허용합니다.
    pub cors_allow_origins: Vec<String>,
    /// pending 인증 세션 TTL.
    pub auth_ttl_seconds: u64,
    /// verified 인증 결과 TTL.
    pub verified_ttl_seconds: u64,
    /// JWT 서명에 사용할 Ed25519 PKCS#8 private key PEM.
    pub jwt_private_key_pem: String,
    /// JWT issuer claim.
    pub jwt_issuer: String,
    /// JWT 유효 기간.
    pub jwt_ttl_seconds: u64,
}

impl Settings {
    /// 환경변수를 읽고 비어 있는 값은 기본값으로 채웁니다.
    pub fn load() -> Self {
        Self::from_env_settings(EnvSettings::load())
    }

    fn from_env_settings(env: EnvSettings) -> Self {
        let mut settings = Self::default();

        if let Some(value) = env.debug {
            settings.debug = value;
        }
        if let Some(value) = env.use_in_memory_store {
            settings.use_in_memory_store = value;
        }
        if let Some(value) = env.redis_url {
            settings.redis_url = value;
        }
        if let Some(value) = env.smtp_host {
            settings.smtp_host = value;
        }
        if let Some(value) = env.smtp_port {
            settings.smtp_port = value;
        }
        if let Some(value) = env.smtp_max_connections {
            settings.smtp_max_connections = value;
        }
        if let Some(value) = env.sms_inbound_address {
            settings.sms_inbound_address = value;
        }
        if let Some(value) = env.dump_inbound {
            settings.dump_inbound = value;
        }
        if let Some(value) = env.http_host {
            settings.http_host = value;
        }
        if let Some(value) = env.http_port {
            settings.http_port = value;
        }
        if let Some(value) = env.http_max_connections {
            settings.http_max_connections = value;
        }
        if let Some(value) = env.cors_allow_origins {
            settings.cors_allow_origins = value;
        }
        if let Some(value) = env.auth_ttl_seconds {
            settings.auth_ttl_seconds = value;
        }
        if let Some(value) = env.verified_ttl_seconds {
            settings.verified_ttl_seconds = value;
        }
        if let Some(value) = env.jwt_private_key_pem {
            settings.jwt_private_key_pem = value;
        }
        if let Some(value) = env.jwt_issuer {
            settings.jwt_issuer = value;
        }
        if let Some(value) = env.jwt_ttl_seconds {
            settings.jwt_ttl_seconds = value;
        }

        settings.smtp_max_connections = settings.smtp_max_connections.max(1);
        settings.http_max_connections = settings.http_max_connections.max(1);
        settings
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            debug: false,
            use_in_memory_store: false,
            redis_url: String::new(),
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
            jwt_issuer: "https://example.com".to_string(),
            jwt_ttl_seconds: 3600,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct EnvSettings {
    #[serde(default, deserialize_with = "deserialize_optional_bool")]
    debug: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_bool")]
    use_in_memory_store: Option<bool>,
    redis_url: Option<String>,
    smtp_host: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u16")]
    smtp_port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_optional_usize")]
    smtp_max_connections: Option<usize>,
    sms_inbound_address: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_bool")]
    dump_inbound: Option<bool>,
    http_host: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u16")]
    http_port: Option<u16>,
    #[serde(default, deserialize_with = "deserialize_optional_usize")]
    http_max_connections: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_optional_list")]
    cors_allow_origins: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    auth_ttl_seconds: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    verified_ttl_seconds: Option<u64>,
    #[serde(rename = "jwt_private_key")]
    jwt_private_key_pem: Option<String>,
    jwt_issuer: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    jwt_ttl_seconds: Option<u64>,
}

impl EnvSettings {
    fn load() -> Self {
        envy::from_env().unwrap_or_else(|err| {
            eprintln!("warning: ignoring invalid environment configuration: {err}");
            Self::default()
        })
    }
}

fn deserialize_optional_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };

    Ok(match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    })
}

fn deserialize_optional_u16<'de, D>(deserializer: D) -> Result<Option<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_from_str(deserializer)
}

fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_from_str(deserializer)
}

fn deserialize_optional_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_from_str(deserializer)
}

fn deserialize_optional_from_str<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: FromStr,
{
    Ok(Option::<String>::deserialize(deserializer)?
        .and_then(|value| value.trim().parse::<T>().ok()))
}

fn deserialize_optional_list<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(value) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if trimmed.starts_with('[') {
        return Ok(serde_json::from_str::<Vec<String>>(trimmed)
            .ok()
            .filter(|parsed| !parsed.is_empty()));
    }

    let out: Vec<String> = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn settings_from_env(values: &[(&str, &str)]) -> Settings {
        let env = envy::from_iter::<_, EnvSettings>(
            values
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string())),
        )
        .unwrap();
        Settings::from_env_settings(env)
    }

    #[test]
    fn test_env_bool() {
        assert!(settings_from_env(&[("DEBUG", "yes")]).debug);
        assert!(!settings_from_env(&[("DEBUG", "off")]).debug);

        let settings = settings_from_env(&[("DEBUG", "unknown"), ("DUMP_INBOUND", "TRUE")]);
        assert!(!settings.debug);
        assert!(settings.dump_inbound);
    }

    #[test]
    fn test_env_numbers() {
        let settings = settings_from_env(&[
            ("SMTP_PORT", "2526"),
            ("HTTP_PORT", " 9000 "),
            ("SMTP_MAX_CONNECTIONS", "0"),
            ("HTTP_MAX_CONNECTIONS", "not-a-number"),
        ]);

        assert_eq!(settings.smtp_port, 2526);
        assert_eq!(settings.http_port, 9000);
        assert_eq!(settings.smtp_max_connections, 1);
        assert_eq!(settings.http_max_connections, 1024);
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
                r#"["https://a.example","https://b.example"]"#
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
            "USE_IN_MEMORY_STORE",
            "REDIS_URL",
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
            "JWT_ISSUER",
            "JWT_TTL_SECONDS",
        ] {
            env::remove_var(var);
        }
        let s = Settings::load();
        assert!(!s.debug);
        assert!(!s.use_in_memory_store);
        assert!(s.redis_url.is_empty());
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
        assert_eq!(s.jwt_issuer, "https://example.com");
        assert_eq!(s.jwt_ttl_seconds, 3600);
    }
}
