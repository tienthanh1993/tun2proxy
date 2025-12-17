#[cfg(test)]
mod tests {
    use crate::dns_cache::DnsCache;
    use std::time::Duration;
    use std::net::IpAddr;

    #[test]
    fn test_dns_cache_miss() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Should return the IP as string instead of None
        let result = cache.get(&ip);
        assert_eq!(result, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_dns_cache_hit() {
        let cache = DnsCache::new(Duration::from_secs(60));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        cache.insert(ip, "localhost".to_string());

        // Should return the domain
        let result = cache.get(&ip);
        assert_eq!(result, Some("localhost".to_string()));
    }
}
