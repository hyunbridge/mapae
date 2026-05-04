use std::array::from_fn;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::{StorageError, Store};

struct Entry {
    value: String,
    expires_at: Instant,
}

struct Stripe {
    entries: HashMap<String, Entry>,
    last_prune: Instant,
}

const STRIPE_COUNT: usize = 256;
const PRUNE_INTERVAL: Duration = Duration::from_secs(60);

/// 개발 및 단일 인스턴스용 프로세스 로컬 저장소.
///
/// 데이터는 영속화되지 않으며 프로세스 간 공유되지 않습니다.
pub struct MemoryStore {
    stripes: Arc<[Mutex<Stripe>; STRIPE_COUNT]>,
}

impl MemoryStore {
    /// 비어 있는 striped in-memory 저장소를 생성합니다.
    pub fn new() -> Self {
        Self {
            stripes: Arc::new(from_fn(|_| {
                Mutex::new(Stripe {
                    entries: HashMap::new(),
                    last_prune: Instant::now(),
                })
            })),
        }
    }
}

fn stripe_index(key: &str) -> usize {
    const NONCE_PREFIX: &str = "nonce:";
    if let Some(rest) = key.strip_prefix(NONCE_PREFIX) {
        if rest.len() >= 2 {
            let bytes = rest.as_bytes();
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[0]), hex_nibble(bytes[1])) {
                return ((hi as usize) << 4) | (lo as usize);
            }
        }
    }

    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    (hasher.finish() as usize) % STRIPE_COUNT
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn prune_expired(stripe: &mut Stripe, now: Instant) {
    if now.duration_since(stripe.last_prune) < PRUNE_INTERVAL {
        return;
    }

    stripe.entries.retain(|_, entry| now < entry.expires_at);
    stripe.last_prune = now;
}

impl Store for MemoryStore {
    async fn ping(&self) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<(String, bool), StorageError> {
        let now = Instant::now();
        let mut stripe = self.stripes[stripe_index(key)]
            .lock()
            .map_err(|_| StorageError::MemoryLockPoisoned)?;
        match stripe.entries.get(key) {
            Some(entry) if now < entry.expires_at => Ok((entry.value.clone(), true)),
            Some(_) => {
                stripe.entries.remove(key);
                Ok((String::new(), false))
            }
            None => Ok((String::new(), false)),
        }
    }

    async fn take(&self, key: &str) -> Result<(String, bool), StorageError> {
        let now = Instant::now();
        let mut stripe = self.stripes[stripe_index(key)]
            .lock()
            .map_err(|_| StorageError::MemoryLockPoisoned)?;
        match stripe.entries.remove(key) {
            Some(entry) if now < entry.expires_at => Ok((entry.value, true)),
            Some(_) => Ok((String::new(), false)),
            None => Ok((String::new(), false)),
        }
    }

    async fn set_ex(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), StorageError> {
        if ttl_seconds == 0 {
            return Err(StorageError::InvalidTtl);
        }
        let key = key.to_string();
        let value = value.to_string();
        let now = Instant::now();
        let expires_at = now
            .checked_add(Duration::from_secs(ttl_seconds))
            .ok_or(StorageError::InvalidTtl)?;
        let mut stripe = self.stripes[stripe_index(&key)]
            .lock()
            .map_err(|_| StorageError::MemoryLockPoisoned)?;
        prune_expired(&mut stripe, now);
        stripe.entries.insert(key, Entry { value, expires_at });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        {
            let mut stripe = store.stripes[stripe_index("expired")].lock().unwrap();
            stripe.entries.insert(
                "expired".to_string(),
                Entry {
                    value: "v".to_string(),
                    expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
                },
            );
        }

        let (_, ok) = store.get("expired").await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn test_set_ex_prunes_expired_entries_periodically() {
        let store = MemoryStore::new();
        let old_key = "old";
        let new_key = (0..)
            .map(|i| format!("new:{i}"))
            .find(|key| stripe_index(key) == stripe_index(old_key))
            .unwrap();
        let stripe_index = stripe_index(old_key);

        {
            let mut stripe = store.stripes[stripe_index].lock().unwrap();
            stripe.last_prune = Instant::now().checked_sub(PRUNE_INTERVAL).unwrap();
            stripe.entries.insert(
                old_key.to_string(),
                Entry {
                    value: "v".to_string(),
                    expires_at: Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
                },
            );
        }

        store.set_ex(&new_key, "new", 60).await.unwrap();

        let stripe = store.stripes[stripe_index].lock().unwrap();
        assert_eq!(stripe.entries.len(), 1);
        assert!(stripe.entries.contains_key(&new_key));
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

    #[test]
    fn test_stripe_index_hashes_full_key_for_non_nonce_keys() {
        let a = stripe_index("auth:shared");
        let b = stripe_index("verified:shared");
        assert_ne!(a, b);
    }
}
