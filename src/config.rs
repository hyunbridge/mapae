use std::env;

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
        let default = Self::default();
        Self {
            debug: env_bool("DEBUG", default.debug),
            use_in_memory_store: env_bool("USE_IN_MEMORY_STORE", default.use_in_memory_store),
            redis_url: env_string("REDIS_URL", &default.redis_url),
            smtp_host: env_string("SMTP_HOST", &default.smtp_host),
            smtp_port: env_u16("SMTP_PORT", default.smtp_port),
            smtp_max_connections: env_usize("SMTP_MAX_CONNECTIONS", default.smtp_max_connections)
                .max(1),
            sms_inbound_address: env_string("SMS_INBOUND_ADDRESS", &default.sms_inbound_address),
            dump_inbound: env_bool("DUMP_INBOUND", default.dump_inbound),
            http_host: env_string("HTTP_HOST", &default.http_host),
            http_port: env_u16("HTTP_PORT", default.http_port),
            http_max_connections: env_usize("HTTP_MAX_CONNECTIONS", default.http_max_connections)
                .max(1),
            cors_allow_origins: env_list("CORS_ALLOW_ORIGINS", default.cors_allow_origins),
            auth_ttl_seconds: env_u64("AUTH_TTL_SECONDS", default.auth_ttl_seconds),
            verified_ttl_seconds: env_u64("VERIFIED_TTL_SECONDS", default.verified_ttl_seconds),
            jwt_private_key_pem: env_string("JWT_PRIVATE_KEY", &default.jwt_private_key_pem),
            jwt_issuer: env_string("JWT_ISSUER", &default.jwt_issuer),
            jwt_ttl_seconds: env_u64("JWT_TTL_SECONDS", default.jwt_ttl_seconds),
        }
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

fn env_string(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    let Some(val) = env::var(key).ok() else {
        return default;
    };

    match val.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|val| val.trim().parse().ok())
        .unwrap_or(default)
}

fn env_list(key: &str, default: Vec<String>) -> Vec<String> {
    let Ok(val) = env::var(key) else {
        return default;
    };

    let trimmed = val.trim();
    if trimmed.is_empty() {
        return default;
    }

    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<String>>(trimmed) {
            Ok(parsed) if !parsed.is_empty() => return parsed,
            Ok(_) => return default,
            Err(err) => {
                eprintln!("warning: ignoring invalid JSON in {key}: {err}");
                return default;
            }
        }
    }

    let out: Vec<String> = trimmed
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if out.is_empty() {
        default
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_bool() {
        env::set_var("TEST_BOOL_VAL", "yes");
        assert!(env_bool("TEST_BOOL_VAL", false));

        env::set_var("TEST_BOOL_VAL", "off");
        assert!(!env_bool("TEST_BOOL_VAL", true));

        env::set_var("TEST_BOOL_VAL", "unknown");
        assert!(env_bool("TEST_BOOL_VAL", true));

        assert!(env_bool("TEST_BOOL_MISSING", true));
    }

    #[test]
    fn test_env_list() {
        let def = vec!["*".to_string()];

        env::set_var("TEST_LIST_VAL", "a, b, ,c");
        assert_eq!(env_list("TEST_LIST_VAL", def.clone()), vec!["a", "b", "c"]);

        env::set_var(
            "TEST_LIST_VAL",
            r#"["https://a.example","https://b.example"]"#,
        );
        assert_eq!(
            env_list("TEST_LIST_VAL", def.clone()),
            vec!["https://a.example", "https://b.example"]
        );

        env::set_var("TEST_LIST_VAL", "[]");
        assert_eq!(env_list("TEST_LIST_VAL", def.clone()), def);

        env::set_var("TEST_LIST_VAL", "  ");
        assert_eq!(env_list("TEST_LIST_VAL", def.clone()), def);
    }

    #[test]
    fn test_env_usize() {
        env::set_var("TEST_USIZE_VAL", "42");
        assert_eq!(env_usize("TEST_USIZE_VAL", 7), 42);

        env::set_var("TEST_USIZE_VAL", "not-a-number");
        assert_eq!(env_usize("TEST_USIZE_VAL", 7), 7);
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
