use std::sync::Mutex;
use std::time::{Duration, Instant};

use moka::{
    ops::compute::{CompResult, Op},
    sync::Cache,
    Expiry,
};

use super::{StorageError, Store};

#[derive(Clone)]
struct Entry {
    value: String,
    ttl: Duration,
    expires_at: Instant,
}

impl Entry {
    fn is_alive(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

struct EntryExpiry;

impl Expiry<String, Entry> for EntryExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Entry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &String,
        value: &Entry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// 개발 및 단일 인스턴스용 프로세스 로컬 저장소.
///
/// 데이터는 영속화되지 않으며 프로세스 간 공유되지 않습니다.
pub struct MemoryStore {
    cache: Cache<String, Entry>,
    write_lock: Mutex<()>,
}

impl MemoryStore {
    /// 비어 있는 striped in-memory 저장소를 생성합니다.
    pub fn new() -> Self {
        Self {
            cache: Cache::builder().expire_after(EntryExpiry).build(),
            write_lock: Mutex::new(()),
        }
    }

    fn entry(value: &str, ttl_seconds: u64) -> Result<Entry, StorageError> {
        if ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }
        let now = Instant::now();
        let ttl = Duration::from_secs(ttl_seconds);
        let expires_at = now.checked_add(ttl).ok_or(StorageError::InvalidTtl)?;
        Ok(Entry {
            value: value.to_string(),
            ttl,
            expires_at,
        })
    }
}

impl Store for MemoryStore {
    async fn ping(&self) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        Ok(self
            .cache
            .get(key)
            .filter(Entry::is_alive)
            .map(|entry| entry.value))
    }

    #[cfg(test)]
    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        self.cache
            .insert(key.to_string(), Self::entry(value, ttl_seconds)?);
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
        let auth_entry = Self::entry(auth_payload, ttl_seconds)?;
        let nonce_entry = Self::entry(nonce_value, ttl_seconds)?;
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        self.cache.insert(auth_key.to_string(), auth_entry);
        self.cache.insert(nonce_key.to_string(), nonce_entry);
        Ok(())
    }

    #[cfg(test)]
    async fn take(&self, key: &str) -> Result<Option<String>, StorageError> {
        match self
            .cache
            .entry_by_ref(key)
            .and_compute_with(|entry| match entry {
                Some(_) => Op::Remove,
                None => Op::Nop,
            }) {
            CompResult::Removed(entry) => {
                let entry = entry.into_value();
                if entry.is_alive() {
                    Ok(Some(entry.value))
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    async fn consume_nonce_and_store_verified(
        &self,
        nonce: &str,
        verified_payload: &str,
        verified_ttl_seconds: u64,
    ) -> Result<Option<String>, StorageError> {
        let verified_entry = Self::entry(verified_payload, verified_ttl_seconds)?;
        let _guard = self
            .write_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        let nonce_key = format!("nonce:{nonce}");
        let auth_id =
            match self
                .cache
                .entry_by_ref(&nonce_key)
                .and_compute_with(|entry| match entry {
                    Some(_) => Op::Remove,
                    None => Op::Nop,
                }) {
                CompResult::Removed(entry) => {
                    let entry = entry.into_value();
                    if entry.is_alive() {
                        Some(entry.value)
                    } else {
                        None
                    }
                }
                _ => None,
            };

        let Some(auth_id) = auth_id else {
            return Ok(None);
        };

        self.cache.insert(format!("auth:{auth_id}"), verified_entry);
        Ok(Some(auth_id))
    }
}

#[cfg(test)]
impl MemoryStore {
    fn insert_expired_for_test(&self, key: &str, value: &str) {
        self.cache.insert(
            key.to_string(),
            Entry {
                value: value.to_string(),
                ttl: Duration::from_secs(60),
                expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            },
        );
    }

    async fn nonce_exists_for_test(&self, nonce: &str) -> bool {
        self.get(&format!("nonce:{nonce}")).await.unwrap().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_set_ex_get_take_flow() {
        let store = MemoryStore::new();
        store.set_ex("k", "v", 10).await.unwrap();

        let val = store.get("k").await.unwrap();
        assert_eq!(val.as_deref(), Some("v"));

        let taken = store.take("k").await.unwrap();
        assert_eq!(taken.as_deref(), Some("v"));

        let got = store.get("k").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_set_ex_rejects_zero_ttl() {
        let store = MemoryStore::new();
        assert!(store.set_ex("k", "v", 0).await.is_err());
    }

    #[tokio::test]
    async fn test_get_expired_entry() {
        let store = MemoryStore::new();
        store.insert_expired_for_test("expired", "v");

        let got = store.get("expired").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_take_expired_entry_does_not_succeed() {
        let store = MemoryStore::new();
        store.insert_expired_for_test("expired", "v");

        let value = store.take("expired").await.unwrap();
        assert!(value.is_none());

        let got = store.get("expired").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn test_set_ex_replaces_expired_entry() {
        let store = MemoryStore::new();
        store.insert_expired_for_test("k", "old");

        store.set_ex("k", "new", 60).await.unwrap();

        let value = store.get("k").await.unwrap();
        assert_eq!(value.as_deref(), Some("new"));
    }

    #[tokio::test]
    async fn test_init_auth_session_writes_auth_and_nonce_together() {
        let store = MemoryStore::new();

        store
            .init_auth_session(
                "auth:abc",
                "{\"status\":\"pending\"}",
                "nonce:def",
                "abc",
                60,
            )
            .await
            .unwrap();

        let auth = store.get("auth:abc").await.unwrap();
        let nonce = store.get("nonce:def").await.unwrap();
        assert_eq!(auth.as_deref(), Some("{\"status\":\"pending\"}"));
        assert_eq!(nonce.as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn test_init_auth_session_rejects_zero_ttl() {
        let store = MemoryStore::new();

        let result = store
            .init_auth_session(
                "auth:abc",
                "{\"status\":\"pending\"}",
                "nonce:def",
                "abc",
                0,
            )
            .await;

        assert!(result.is_err());
        assert!(store.get("auth:abc").await.unwrap().is_none());
        assert!(store.get("nonce:def").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_take_is_atomic_under_concurrency() {
        let store = MemoryStore::new();
        store.set_ex("nonce", "auth-id", 60).await.unwrap();

        let store = Arc::new(store);
        let mut handles = vec![];
        let success_count = Arc::new(std::sync::atomic::AtomicI32::new(0));

        for _ in 0..64 {
            let s = store.clone();
            let sc = success_count.clone();
            handles.push(tokio::spawn(async move {
                if s.take("nonce").await.unwrap().is_some() {
                    sc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(success_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_consume_nonce_and_store_verified_flow() {
        let store = MemoryStore::new();
        store.set_ex("nonce:abc", "auth-id", 60).await.unwrap();

        let auth_id = store
            .consume_nonce_and_store_verified("abc", "{\"status\":\"verified\"}", 30)
            .await
            .unwrap();
        assert_eq!(auth_id.as_deref(), Some("auth-id"));

        let nonce = store.get("nonce:abc").await.unwrap();
        assert!(nonce.is_none());

        let value = store.get("auth:auth-id").await.unwrap();
        assert_eq!(value.as_deref(), Some("{\"status\":\"verified\"}"));
    }

    #[tokio::test]
    async fn test_consume_nonce_and_store_verified_rejects_zero_ttl_without_consuming_nonce() {
        let store = MemoryStore::new();
        store.set_ex("nonce:abc", "auth-id", 60).await.unwrap();

        let result = store
            .consume_nonce_and_store_verified("abc", "{\"status\":\"verified\"}", 0)
            .await;
        assert!(result.is_err());
        assert!(store.nonce_exists_for_test("abc").await);
    }

    #[tokio::test]
    async fn test_consume_nonce_and_store_verified_is_atomic_under_concurrency() {
        let store = MemoryStore::new();
        store.set_ex("nonce:abc", "auth-id", 60).await.unwrap();

        let store = Arc::new(store);
        let success_count = Arc::new(std::sync::atomic::AtomicI32::new(0));
        let mut handles = vec![];

        for _ in 0..64 {
            let s = store.clone();
            let sc = success_count.clone();
            handles.push(tokio::spawn(async move {
                let ok = s
                    .consume_nonce_and_store_verified("abc", "{\"status\":\"verified\"}", 30)
                    .await
                    .unwrap();
                if ok.is_some() {
                    sc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(success_count.load(std::sync::atomic::Ordering::SeqCst), 1);
        let value = store.get("auth:auth-id").await.unwrap();
        assert_eq!(value.as_deref(), Some("{\"status\":\"verified\"}"));
    }
}
