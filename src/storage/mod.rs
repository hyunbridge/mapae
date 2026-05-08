pub mod memory;
pub mod redis;

use memory::MemoryStore;
use redis::RedisStore;
use thiserror::Error;

/// 저장소 백엔드에서 반환하는 오류.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid ttl")]
    InvalidTtl,
    #[error("redis error: {0}")]
    Redis(#[from] ::redis::RedisError),
}

/// Redis 및 인메모리 저장소의 공통 규약.
///
/// 분산 환경에서 인증 상태(Nonce, Auth ID)를 원자적으로 처리하고 TTL을 보장하기 위해 사용됩니다.
pub trait Store: Send + Sync + 'static {
    /// 백엔드 가용성을 확인합니다.
    async fn ping(&self) -> Result<(), StorageError>;

    /// 살아 있는 키가 있으면 `Some(value)`, 없으면 `None`을 반환합니다.
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// 키를 원자적으로 삭제하고 만료되지 않은 값이 있으면 반환합니다.
    #[cfg(test)]
    async fn take(&self, key: &str) -> Result<Option<String>, StorageError>;

    /// 키를 초 단위 TTL과 함께 저장합니다.
    ///
    /// 구현체는 0초 TTL을 거부합니다.
    #[cfg(test)]
    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError>;

    /// 인증 시작 시 auth 레코드와 nonce 레코드를 원자적으로 함께 저장합니다.
    ///
    /// 구현체는 둘 중 하나만 저장되는 상태를 허용하지 않아야 합니다.
    async fn init_auth_session(
        &self,
        auth_key: &str,
        auth_payload: &str,
        nonce_key: &str,
        nonce_value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StorageError>;

    /// Nonce를 단 한 번 소모하고, 같은 원자적 작업 안에서 검증 결과를 저장합니다.
    ///
    /// 성공 시 `Some(auth_id)`를 반환하고, Nonce가 없거나 만료되었으면 `None`을 반환합니다.
    /// 저장 TTL이 0이면 Nonce를 소모하지 않고 오류를 반환해야 합니다.
    async fn consume_nonce_and_store_verified(
        &self,
        nonce: &str,
        verified_payload: &str,
        verified_ttl_seconds: u64,
    ) -> Result<Option<String>, StorageError>;
}

/// 선택된 저장소 백엔드.
pub enum StoreBackend {
    Memory(MemoryStore),
    Redis(RedisStore),
}

impl StoreBackend {
    pub fn memory(store: MemoryStore) -> Self {
        Self::Memory(store)
    }

    pub fn redis(store: RedisStore) -> Self {
        Self::Redis(store)
    }
}

impl Store for StoreBackend {
    async fn ping(&self) -> Result<(), StorageError> {
        match self {
            Self::Memory(s) => s.ping().await,
            Self::Redis(s) => s.ping().await,
        }
    }

    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        match self {
            Self::Memory(s) => s.get(key).await,
            Self::Redis(s) => s.get(key).await,
        }
    }

    #[cfg(test)]
    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        match self {
            Self::Memory(s) => s.set_ex(key, value, ttl_seconds).await,
            Self::Redis(s) => s.set_ex(key, value, ttl_seconds).await,
        }
    }

    async fn init_auth_session(
        &self,
        auth_key: &str,
        auth_payload: &str,
        nonce_key: &str,
        nonce_value: &str,
        ttl_seconds: u64,
    ) -> Result<(), StorageError> {
        match self {
            Self::Memory(s) => {
                s.init_auth_session(auth_key, auth_payload, nonce_key, nonce_value, ttl_seconds)
                    .await
            }
            Self::Redis(s) => {
                s.init_auth_session(auth_key, auth_payload, nonce_key, nonce_value, ttl_seconds)
                    .await
            }
        }
    }

    #[cfg(test)]
    async fn take(&self, key: &str) -> Result<Option<String>, StorageError> {
        match self {
            Self::Memory(s) => s.take(key).await,
            Self::Redis(s) => s.take(key).await,
        }
    }

    async fn consume_nonce_and_store_verified(
        &self,
        nonce: &str,
        verified_payload: &str,
        verified_ttl_seconds: u64,
    ) -> Result<Option<String>, StorageError> {
        match self {
            Self::Memory(s) => {
                s.consume_nonce_and_store_verified(nonce, verified_payload, verified_ttl_seconds)
                    .await
            }
            Self::Redis(s) => {
                s.consume_nonce_and_store_verified(nonce, verified_payload, verified_ttl_seconds)
                    .await
            }
        }
    }
}
