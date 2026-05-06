pub mod memory;
pub mod redis;

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;

use memory::MemoryStore;
use redis::RedisStore;
use thiserror::Error;

pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StorageError>> + Send + 'a>>;

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
    fn ping(&self) -> StoreFuture<'_, ()>;

    /// 살아 있는 키가 있으면 `(value, true)`, 없으면 `(String::new(), false)`를 반환합니다.
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, (String, bool)>;

    /// 키를 원자적으로 삭제하고 만료되지 않은 값이 있으면 반환합니다.
    fn take<'a>(&'a self, key: &'a str) -> StoreFuture<'a, (String, bool)>;

    /// 키를 초 단위 TTL과 함께 저장합니다.
    ///
    /// 구현체는 0초 TTL을 거부합니다.
    fn set_ex<'a>(&'a self, key: &'a str, value: &'a str, ttl_seconds: u64) -> StoreFuture<'a, ()>;

    /// Nonce를 소모하여 연관된 `auth_id`를 가져옵니다.
    ///
    /// 중복 처리나 Race Condition을 방지하기 위해 단 한 번만 성공해야 합니다.
    fn take_nonce<'a>(&'a self, nonce: &'a str) -> StoreFuture<'a, (String, bool)> {
        Box::pin(async move {
            let key = format!("nonce:{nonce}");
            self.take(&key).await
        })
    }
}

/// 선택된 저장소 백엔드.
pub struct StoreBackend {
    inner: Box<dyn Store>,
}

impl StoreBackend {
    pub fn memory(store: MemoryStore) -> Self {
        Self {
            inner: Box::new(store),
        }
    }

    pub fn redis(store: RedisStore) -> Self {
        Self {
            inner: Box::new(store),
        }
    }
}

impl Deref for StoreBackend {
    type Target = dyn Store;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref()
    }
}
