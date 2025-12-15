use hashlink::LruCache;
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

const MAPPING_TIMEOUT: u64 = 300; // Mapping timeout in seconds

struct CacheEntry {
    name: String,
    expiry: Instant,
}

pub struct DnsCache {
    lru_cache: LruCache<IpAddr, CacheEntry>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            lru_cache: LruCache::new(5000),
        }
    }

    pub fn insert(&mut self, ip: IpAddr, name: String) {
        let expiry = Instant::now() + Duration::from_secs(MAPPING_TIMEOUT);
        self.lru_cache.insert(ip, CacheEntry { name, expiry });
    }

    pub fn lookup(&mut self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        if let Some(entry) = self.lru_cache.get(ip) {
            if now > entry.expiry {
                self.lru_cache.remove(ip);
                return None;
            }
            return Some(entry.name.clone());
        }
        None
    }
}
