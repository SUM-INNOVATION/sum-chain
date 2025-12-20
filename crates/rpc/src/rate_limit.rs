//! RPC rate limiting.
//!
//! Provides per-IP and global rate limiting for the JSON-RPC server
//! using a token bucket algorithm.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Maximum requests per second per IP
    #[serde(default = "default_requests_per_second")]
    pub requests_per_second: u32,

    /// Burst size (max tokens in bucket)
    #[serde(default = "default_burst_size")]
    pub burst_size: u32,

    /// Global rate limit (total requests per second across all IPs)
    #[serde(default = "default_global_rps")]
    pub global_requests_per_second: u32,

    /// IPs exempt from rate limiting (e.g., localhost)
    #[serde(default)]
    pub exempt_ips: Vec<String>,
}

fn default_enabled() -> bool {
    false
}

fn default_requests_per_second() -> u32 {
    100
}

fn default_burst_size() -> u32 {
    200
}

fn default_global_rps() -> u32 {
    10000
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            requests_per_second: 100,
            burst_size: 200,
            global_requests_per_second: 10000,
            exempt_ips: vec!["127.0.0.1".to_string(), "::1".to_string()],
        }
    }
}

impl RateLimitConfig {
    /// Create a disabled rate limiter config
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }

    /// Create with custom per-IP limits
    pub fn with_limits(requests_per_second: u32, burst_size: u32) -> Self {
        Self {
            enabled: true,
            requests_per_second,
            burst_size,
            ..Default::default()
        }
    }
}

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_update: Instant,
    rate: f64,       // tokens per second
    capacity: f64,   // max tokens
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_update: Instant::now(),
            rate,
            capacity,
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;

        // Refill tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get remaining tokens
    fn remaining(&self) -> u32 {
        self.tokens as u32
    }
}

/// Rate limiter
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    per_ip_buckets: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    global_bucket: Arc<Mutex<TokenBucket>>,
    exempt_ips: Vec<IpAddr>,
    last_cleanup: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter from config
    pub fn new(config: RateLimitConfig) -> Self {
        let exempt_ips: Vec<IpAddr> = config
            .exempt_ips
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        let global_bucket = TokenBucket::new(
            config.global_requests_per_second as f64,
            config.global_requests_per_second as f64 * 2.0,
        );

        Self {
            config: config.clone(),
            per_ip_buckets: Arc::new(Mutex::new(HashMap::new())),
            global_bucket: Arc::new(Mutex::new(global_bucket)),
            exempt_ips,
            last_cleanup: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if an IP is exempt from rate limiting
    pub fn is_exempt(&self, ip: &IpAddr) -> bool {
        self.exempt_ips.contains(ip)
    }

    /// Check if a request is allowed. Returns Ok(()) if allowed, Err with message if rate limited.
    pub fn check(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if IP is exempt
        if self.is_exempt(&ip) {
            return Ok(());
        }

        // Check global rate limit
        {
            let mut global = self.global_bucket.lock();
            if !global.try_consume() {
                return Err(RateLimitError::GlobalLimitExceeded);
            }
        }

        // Check per-IP rate limit
        {
            let mut buckets = self.per_ip_buckets.lock();
            let bucket = buckets.entry(ip).or_insert_with(|| {
                TokenBucket::new(
                    self.config.requests_per_second as f64,
                    self.config.burst_size as f64,
                )
            });

            if !bucket.try_consume() {
                return Err(RateLimitError::IpLimitExceeded {
                    retry_after_ms: (1000.0 / self.config.requests_per_second as f64) as u64,
                });
            }
        }

        // Periodic cleanup of old buckets
        self.maybe_cleanup();

        Ok(())
    }

    /// Get rate limit info for an IP
    pub fn get_info(&self, ip: &IpAddr) -> RateLimitInfo {
        if !self.config.enabled || self.is_exempt(ip) {
            return RateLimitInfo {
                limited: false,
                remaining: self.config.burst_size,
                limit: self.config.requests_per_second,
                reset_ms: 0,
            };
        }

        let buckets = self.per_ip_buckets.lock();
        match buckets.get(ip) {
            Some(bucket) => RateLimitInfo {
                limited: bucket.remaining() == 0,
                remaining: bucket.remaining(),
                limit: self.config.requests_per_second,
                reset_ms: (1000.0 / self.config.requests_per_second as f64) as u64,
            },
            None => RateLimitInfo {
                limited: false,
                remaining: self.config.burst_size,
                limit: self.config.requests_per_second,
                reset_ms: 0,
            },
        }
    }

    /// Cleanup old bucket entries (called periodically)
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let cleanup_interval = Duration::from_secs(60);

        let should_cleanup = {
            let last = self.last_cleanup.lock();
            now.duration_since(*last) > cleanup_interval
        };

        if should_cleanup {
            let mut last = self.last_cleanup.lock();
            *last = now;
            drop(last);

            let mut buckets = self.per_ip_buckets.lock();
            // Remove buckets that haven't been used in 5 minutes
            let stale_threshold = Duration::from_secs(300);
            buckets.retain(|_, bucket| {
                now.duration_since(bucket.last_update) < stale_threshold
            });
        }
    }
}

/// Rate limit error
#[derive(Debug, Clone)]
pub enum RateLimitError {
    /// Per-IP rate limit exceeded
    IpLimitExceeded { retry_after_ms: u64 },
    /// Global rate limit exceeded
    GlobalLimitExceeded,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::IpLimitExceeded { retry_after_ms } => {
                write!(f, "Rate limit exceeded. Retry after {}ms", retry_after_ms)
            }
            RateLimitError::GlobalLimitExceeded => {
                write!(f, "Server is overloaded. Please try again later.")
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

/// Rate limit info for headers
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub limited: bool,
    pub remaining: u32,
    pub limit: u32,
    pub reset_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_disabled_rate_limiter() {
        let config = RateLimitConfig::disabled();
        let limiter = RateLimiter::new(config);

        let ip: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();

        // Should always allow when disabled
        for _ in 0..1000 {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn test_exempt_ip() {
        let config = RateLimitConfig::with_limits(1, 1);
        let limiter = RateLimiter::new(config);

        let localhost: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();

        // Localhost should be exempt
        for _ in 0..100 {
            assert!(limiter.check(localhost).is_ok());
        }
    }

    #[test]
    fn test_rate_limiting() {
        let config = RateLimitConfig::with_limits(10, 5);
        let limiter = RateLimiter::new(config);

        let ip: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();

        // First 5 requests should succeed (burst)
        for i in 0..5 {
            assert!(limiter.check(ip).is_ok(), "Request {} should succeed", i);
        }

        // 6th request should fail
        assert!(limiter.check(ip).is_err());
    }

    #[test]
    fn test_rate_limit_info() {
        let config = RateLimitConfig::with_limits(100, 50);
        let limiter = RateLimiter::new(config);

        let ip: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();

        // Check initial info
        let info = limiter.get_info(&ip);
        assert!(!info.limited);
        assert_eq!(info.remaining, 50);
        assert_eq!(info.limit, 100);

        // Make some requests
        for _ in 0..10 {
            let _ = limiter.check(ip);
        }

        // Check updated info
        let info = limiter.get_info(&ip);
        assert_eq!(info.remaining, 40);
    }

    #[test]
    fn test_multiple_ips() {
        let config = RateLimitConfig::with_limits(5, 3);
        let limiter = RateLimiter::new(config);

        let ip1: IpAddr = Ipv4Addr::new(1, 1, 1, 1).into();
        let ip2: IpAddr = Ipv4Addr::new(2, 2, 2, 2).into();

        // Each IP has its own bucket
        for _ in 0..3 {
            assert!(limiter.check(ip1).is_ok());
            assert!(limiter.check(ip2).is_ok());
        }

        // Both should now be limited
        assert!(limiter.check(ip1).is_err());
        assert!(limiter.check(ip2).is_err());
    }
}
