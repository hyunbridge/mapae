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

    /// 살아 있는 키가 있으면 `(value, true)`, 없으면 `(String::new(), false)`를 반환합니다.
    async fn get(&self, key: &str) -> Result<(String, bool), StorageError>;

    /// 키를 원자적으로 삭제하고 만료되지 않은 값이 있으면 반환합니다.
    async fn take(&self, key: &str) -> Result<(String, bool), StorageError>;

    /// 키를 초 단위 TTL과 함께 저장합니다.
    ///
    /// 구현체는 0초 TTL을 거부합니다.
    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError>;

    /// Nonce를 소모하여 연관된 `auth_id`를 가져옵니다.
    ///
    /// 중복 처리나 Race Condition을 방지하기 위해 단 한 번만 성공해야 합니다.
    async fn take_nonce(&self, nonce: &str) -> Result<(String, bool), StorageError> {
        self.take(&format!("nonce:{nonce}")).await
    }
}

/// 선택된 저장소 백엔드.
pub enum StoreBackend {
    Memory(MemoryStore),
    Redis(RedisStore),
}

impl Store for StoreBackend {
    async fn ping(&self) -> Result<(), StorageError> {
        match self {
            Self::Memory(store) => store.ping().await,
            Self::Redis(store) => store.ping().await,
        }
    }

    async fn get(&self, key: &str) -> Result<(String, bool), StorageError> {
        match self {
            Self::Memory(store) => store.get(key).await,
            Self::Redis(store) => store.get(key).await,
        }
    }

    async fn take(&self, key: &str) -> Result<(String, bool), StorageError> {
        match self {
            Self::Memory(store) => store.take(key).await,
            Self::Redis(store) => store.take(key).await,
        }
    }

    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        match self {
            Self::Memory(store) => store.set_ex(key, value, ttl_seconds).await,
            Self::Redis(store) => store.set_ex(key, value, ttl_seconds).await,
        }
    }
}
