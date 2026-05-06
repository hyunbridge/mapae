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
}

impl MemoryStore {
    /// 비어 있는 striped in-memory 저장소를 생성합니다.
    pub fn new() -> Self {
        Self {
            cache: Cache::builder().expire_after(EntryExpiry).build(),
        }
    }
}

impl Store for MemoryStore {
    async fn ping(&self) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<(String, bool), StorageError> {
        match self.cache.get(key).filter(Entry::is_alive) {
            Some(entry) => Ok((entry.value, true)),
            None => Ok((String::new(), false)),
        }
    }

    async fn take(&self, key: &str) -> Result<(String, bool), StorageError> {
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
                    Ok((entry.value, true))
                } else {
                    Ok((String::new(), false))
                }
            }
            _ => Ok((String::new(), false)),
        }
    }

    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        if ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }
        let key = key.to_string();
        let value = value.to_string();
        let now = Instant::now();
        let ttl = Duration::from_secs(ttl_seconds);
        let expires_at = now.checked_add(ttl).ok_or(StorageError::InvalidTtl)?;
        self.cache.insert(
            key,
            Entry {
                value,
                ttl,
                expires_at,
            },
        );
        Ok(())
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

        let (val, ok) = store.get("k").await.unwrap();
        assert!(ok);
        assert_eq!(val, "v");

        let (taken, ok) = store.take("k").await.unwrap();
        assert!(ok);
        assert_eq!(taken, "v");

        let (_, ok) = store.get("k").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_set_ex_rejects_zero_ttl() {
        let store = MemoryStore::new();
        assert!(store.set_ex("k", "v", 0).await.is_err());
    }

    #[tokio::test]
    async fn test_get_expired_entry() {
        let store = MemoryStore::new();
        store.cache.insert(
            "expired".to_string(),
            Entry {
                value: "v".to_string(),
                ttl: Duration::from_secs(60),
                expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            },
        );

        let (_, ok) = store.get("expired").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_take_expired_entry_does_not_succeed() {
        let store = MemoryStore::new();
        store.cache.insert(
            "expired".to_string(),
            Entry {
                value: "v".to_string(),
                ttl: Duration::from_secs(60),
                expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            },
        );

        let (value, ok) = store.take("expired").await.unwrap();
        assert!(!ok);
        assert!(value.is_empty());

        let (_, ok) = store.get("expired").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_set_ex_replaces_expired_entry() {
        let store = MemoryStore::new();
        store.cache.insert(
            "k".to_string(),
            Entry {
                value: "old".to_string(),
                ttl: Duration::from_secs(60),
                expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
            },
        );

        store.set_ex("k", "new", 60).await.unwrap();

        let (value, ok) = store.get("k").await.unwrap();
        assert!(ok);
        assert_eq!(value, "new");
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
                let (_, ok) = s.take("nonce").await.unwrap();
                if ok {
                    sc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(success_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
