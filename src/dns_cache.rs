use hashlink::LinkedHashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct DnsCache {
    cache: Mutex<LinkedHashMap<IpAddr, (String, Instant)>>,
    ttl: Duration,
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: Mutex::new(LinkedHashMap::new()),
            ttl,
        }
    }

    pub fn insert(&self, ip: IpAddr, domain: String) {
        let mut cache = self.cache.lock().unwrap();
        if cache.contains_key(&ip) {
            cache.remove(&ip);
        }
        cache.insert(ip, (domain, Instant::now() + self.ttl));
    }

    pub fn get(&self, ip: &IpAddr) -> Option<String> {
        let mut cache = self.cache.lock().unwrap();
        if let Some((_, expiry)) = cache.get(ip) {
            if *expiry < Instant::now() {
                cache.remove(ip);
                return None;
            }
        }

        // We need to update expiry and move to back.
        // Since we cannot have mutable reference from get_mut and call to_back at the same time,
        // we can just use remove and insert, or to_back then get_mut.
        // cache.to_back(ip) moves the key to back if it exists.

        if cache.contains_key(ip) {
             cache.to_back(ip);
             if let Some((domain, expiry)) = cache.get_mut(ip) {
                 *expiry = Instant::now() + self.ttl;
                 return Some(domain.clone());
             }
        }

        Some(ip.to_string())
    }
}
