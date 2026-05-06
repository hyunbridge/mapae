use super::{StorageError, Store, StoreFuture};

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
    fn ping(&self) -> StoreFuture<'_, ()> {
        Box::pin(async move {
            let mut conn = self.connection.clone();
            redis::cmd("PING")
                .query_async::<String>(&mut conn)
                .await
                .map_err(StorageError::from)?;
            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, (String, bool)> {
        Box::pin(async move {
            let mut conn = self.connection.clone();
            let result: Option<String> = redis::cmd("GET").arg(key).query_async(&mut conn).await?;
            result.map_or_else(|| Ok((String::new(), false)), |val| Ok((val, true)))
        })
    }

    fn take<'a>(&'a self, key: &'a str) -> StoreFuture<'a, (String, bool)> {
        Box::pin(async move {
            let mut conn = self.connection.clone();
            let result: Option<String> =
                redis::cmd("GETDEL").arg(key).query_async(&mut conn).await?;
            result.map_or_else(|| Ok((String::new(), false)), |val| Ok((val, true)))
        })
    }

    fn set_ex<'a>(&'a self, key: &'a str, value: &'a str, ttl_seconds: u64) -> StoreFuture<'a, ()> {
        Box::pin(async move {
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
        })
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
