use super::{StorageError, Store};

const CONSUME_NONCE_AND_STORE_VERIFIED_SCRIPT: &str = r#"
local auth_id = redis.call("GET", KEYS[1])
if not auth_id then
  return {0, ""}
end
redis.call("SETEX", "auth:" .. auth_id, tonumber(ARGV[2]), ARGV[1])
redis.call("DEL", KEYS[1])
return {1, auth_id}
"#;

const INIT_AUTH_SESSION_SCRIPT: &str = r#"
redis.call("SETEX", KEYS[1], tonumber(ARGV[1]), ARGV[2])
redis.call("SETEX", KEYS[2], tonumber(ARGV[1]), ARGV[3])
return 1
"#;

/// 인증 상태를 공유하기 위한 Redis 저장소.
pub struct RedisStore {
    connection: redis::aio::ConnectionManager,
}

impl RedisStore {
    /// Redis URL로 connection manager를 엽니다.
    pub async fn new(redis_url: &str) -> Result<Self, StorageError> {
        let client = redis::Client::open(redis_url)?;
        let connection = client.get_connection_manager().await?;
        Ok(Self { connection })
    }
}

impl Store for RedisStore {
    async fn ping(&self) -> Result<(), StorageError> {
        let mut conn = self.connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(StorageError::from)?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        let mut conn = self.connection.clone();
        let result: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
        Ok(result)
    }

    #[cfg(test)]
    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        if ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }
        let mut conn = self.connection.clone();
        redis::cmd("SETEX")
            .arg(key)
            .arg(ttl_seconds)
            .arg(value)
            .query_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    async fn init_auth_session(
        &self,
        auth_key: &str,
        auth_payload: &str,
        nonce_key: &str,
        nonce_value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StorageError> {
        if ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }

        let mut conn = self.connection.clone();
        redis::Script::new(INIT_AUTH_SESSION_SCRIPT)
            .key(auth_key)
            .key(nonce_key)
            .arg(ttl_seconds)
            .arg(auth_payload)
            .arg(nonce_value)
            .invoke_async::<()>(&mut conn)
            .await?;
        Ok(())
    }

    #[cfg(test)]
    async fn take(&self, key: &str) -> Result<Option<String>, StorageError> {
        let mut conn = self.connection.clone();
        let result: Option<String> = redis::cmd("GETDEL").arg(key).query_async(&mut conn).await?;
        Ok(result)
    }

    async fn consume_nonce_and_store_verified(
        &self,
        nonce: &str,
        verified_payload: &str,
        verified_ttl_seconds: u64,
    ) -> Result<Option<String>, StorageError> {
        if verified_ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }

        let mut conn = self.connection.clone();
        let nonce_key = format!("nonce:{nonce}");
        let (found, auth_id): (i32, String) =
            redis::Script::new(CONSUME_NONCE_AND_STORE_VERIFIED_SCRIPT)
                .key(nonce_key)
                .arg(verified_payload)
                .arg(verified_ttl_seconds)
                .invoke_async(&mut conn)
                .await?;

        if found == 1 {
            Ok(Some(auth_id))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_new_invalid_url() {
        assert!(RedisStore::new("not-a-redis-url").await.is_err());
    }
}
