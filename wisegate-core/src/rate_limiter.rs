//! Rate limiting implementation for WiseGate.
//!
//! Provides per-IP rate limiting using a sliding window algorithm with
//! automatic cleanup of expired entries to prevent memory exhaustion.
//!
//! # Algorithm
//!
//! Uses a simple sliding window approach:
//! - Each IP has a counter and a timestamp of the last request
//! - If the window has expired, the counter resets
//! - If under the limit, the counter increments and the request is allowed
//! - If over the limit, the request is denied
//!
//! # Memory Management
//!
//! To prevent memory exhaustion from tracking many unique IPs, the rate limiter
//! performs automatic cleanup when:
//! - Entry count exceeds the configured threshold
//! - Minimum interval since last cleanup has passed
//!
//! # Thread Safety
//!
//! Uses `tokio::sync::Mutex` for async-friendly locking that won't block
//! the Tokio thread pool.
//!
//! # Example
//!
//! ```ignore
//! use wisegate_core::{rate_limiter, RateLimiter};
//!
//! let limiter = RateLimiter::new();
//!
//! if rate_limiter::check_rate_limit(&limiter, "192.168.1.1", &config).await {
//!     // Request allowed
//! } else {
//!     // Rate limit exceeded
//! }
//! ```

use std::time::Instant;
use tokio::sync::Mutex;
use tracing::debug;

use crate::types::{ConfigProvider, RateLimitEntry, RateLimiter};

/// Tracks the last cleanup time to enforce minimum interval between cleanups.
static LAST_CLEANUP: Mutex<Option<Instant>> = Mutex::const_new(None);

/// Checks if a request from the given IP should be allowed based on rate limits.
///
/// Returns `true` if the request is allowed, `false` if rate limited.
///
/// # Algorithm
///
/// 1. If the time window has expired for this IP, reset the counter
/// 2. If the request count is under the limit, increment and allow
/// 3. If the request count exceeds the limit, deny
///
/// # Cleanup
///
/// Automatically cleans up expired entries when:
/// - Entry count exceeds `RATE_LIMIT_CLEANUP_THRESHOLD`
/// - At least `RATE_LIMIT_CLEANUP_INTERVAL_SECS` since last cleanup
///
/// # Arguments
///
/// * `limiter` - Shared rate limiter state
/// * `ip` - Client IP address to check
/// * `config` - Configuration provider for rate limit settings
///
/// # Returns
///
/// - `true` - Request is allowed
/// - `false` - Request is rate limited (should return 429)
///
/// # Example
///
/// ```ignore
/// use wisegate_core::rate_limiter::check_rate_limit;
///
/// if !check_rate_limit(&limiter, &client_ip, &config).await {
///     return Err(StatusCode::TOO_MANY_REQUESTS);
/// }
/// ```
pub async fn check_rate_limit(
    limiter: &RateLimiter,
    ip: &str,
    config: &impl ConfigProvider,
) -> bool {
    let rate_config = config.rate_limit_config();
    let cleanup_config = config.rate_limit_cleanup_config();
    let mut rate_map = limiter.inner().lock().await;
    let now = Instant::now();

    // Perform cleanup if needed (threshold exceeded and interval passed)
    if cleanup_config.is_enabled() && rate_map.len() > cleanup_config.threshold {
        let should_cleanup = {
            let mut last_cleanup = LAST_CLEANUP.lock().await;
            match *last_cleanup {
                None => {
                    *last_cleanup = Some(now);
                    true
                }
                Some(last) if now.duration_since(last) >= cleanup_config.interval => {
                    *last_cleanup = Some(now);
                    true
                }
                _ => false,
            }
        };

        if should_cleanup {
            let before_count = rate_map.len();
            // Remove entries that have expired (older than 2x window duration for safety margin)
            let expiry_threshold = rate_config.window_duration * 2;
            rate_map.retain(|_, entry| now.duration_since(entry.window_start) < expiry_threshold);
            let removed = before_count - rate_map.len();
            if removed > 0 {
                debug!(
                    removed_entries = removed,
                    remaining_entries = rate_map.len(),
                    "Rate limiter cleanup completed"
                );
            }
        }
    }

    match rate_map.get_mut(ip) {
        Some(entry) => {
            // Check if we're in a new time window
            if now.duration_since(entry.window_start) >= rate_config.window_duration {
                // Reset window
                entry.window_start = now;
                entry.request_count = 1;
                true
            } else if entry.request_count < rate_config.max_requests {
                // Within limit, increment counter
                entry.request_count += 1;
                true
            } else {
                // Rate limit exceeded
                false
            }
        }
        None => {
            // First request from this IP
            rate_map.insert(ip.to_string(), RateLimitEntry::new());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ProxyConfig, RateLimitCleanupConfig, RateLimitConfig};
    use std::time::Duration;

    /// Test configuration for unit tests
    struct TestConfig {
        rate_limit: RateLimitConfig,
        cleanup: RateLimitCleanupConfig,
    }

    impl TestConfig {
        fn new(max_requests: u32, window_secs: u64) -> Self {
            Self {
                rate_limit: RateLimitConfig {
                    max_requests,
                    window_duration: Duration::from_secs(window_secs),
                },
                cleanup: RateLimitCleanupConfig {
                    threshold: 0, // Disabled by default
                    interval: Duration::from_secs(60),
                },
            }
        }

        #[allow(dead_code)]
        fn with_cleanup(mut self, threshold: usize) -> Self {
            self.cleanup.threshold = threshold;
            self
        }
    }

    impl ConfigProvider for TestConfig {
        fn rate_limit_config(&self) -> &RateLimitConfig {
            &self.rate_limit
        }

        fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
            &self.cleanup
        }

        fn proxy_config(&self) -> &ProxyConfig {
            static CONFIG: ProxyConfig = ProxyConfig {
                timeout: Duration::from_secs(30),
                max_body_size: 100 * 1024 * 1024,
            };
            &CONFIG
        }

        fn allowed_proxy_ips(&self) -> Option<&[String]> {
            None
        }

        fn blocked_ips(&self) -> &[String] {
            &[]
        }

        fn blocked_methods(&self) -> &[String] {
            &[]
        }

        fn blocked_patterns(&self) -> &[String] {
            &[]
        }

        fn max_connections(&self) -> usize {
            10_000
        }
    }

    // ===========================================
    // Basic rate limiting tests
    // ===========================================

    #[tokio::test]
    async fn test_first_request_allowed() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(5, 60);

        let allowed = check_rate_limit(&limiter, "192.168.1.1", &config).await;
        assert!(allowed);
    }

    #[tokio::test]
    async fn test_requests_within_limit_allowed() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(5, 60);

        for i in 0..5 {
            let allowed = check_rate_limit(&limiter, "192.168.1.1", &config).await;
            assert!(allowed, "Request {} should be allowed", i + 1);
        }
    }

    #[tokio::test]
    async fn test_request_exceeding_limit_blocked() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(3, 60);

        // First 3 requests should be allowed
        for _ in 0..3 {
            assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        }

        // 4th request should be blocked
        let blocked = check_rate_limit(&limiter, "192.168.1.1", &config).await;
        assert!(!blocked, "Request exceeding limit should be blocked");
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(2, 60);

        // IP 1 makes 2 requests
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // IP 2 should still have its full quota
        assert!(check_rate_limit(&limiter, "192.168.1.2", &config).await);
        assert!(check_rate_limit(&limiter, "192.168.1.2", &config).await);
        assert!(!check_rate_limit(&limiter, "192.168.1.2", &config).await);
    }

    #[tokio::test]
    async fn test_counter_increments_correctly() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(5, 60);

        // Make some requests
        check_rate_limit(&limiter, "192.168.1.1", &config).await;
        check_rate_limit(&limiter, "192.168.1.1", &config).await;
        check_rate_limit(&limiter, "192.168.1.1", &config).await;

        // Check the counter
        let inner = limiter.inner().lock().await;
        let entry = inner.get("192.168.1.1").unwrap();
        assert_eq!(entry.request_count, 3);
    }

    // ===========================================
    // Edge case tests
    // ===========================================

    #[tokio::test]
    async fn test_limit_of_one() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(1, 60);

        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);
    }

    #[tokio::test]
    async fn test_ipv6_addresses() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(2, 60);

        assert!(check_rate_limit(&limiter, "::1", &config).await);
        assert!(check_rate_limit(&limiter, "::1", &config).await);
        assert!(!check_rate_limit(&limiter, "::1", &config).await);

        // Different IPv6 should be independent
        assert!(check_rate_limit(&limiter, "2001:db8::1", &config).await);
    }

    #[tokio::test]
    async fn test_multiple_blocked_requests() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(1, 60);

        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Multiple blocked requests should all return false
        for _ in 0..5 {
            assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);
        }

        // Counter should not increase beyond limit
        let inner = limiter.inner().lock().await;
        let entry = inner.get("192.168.1.1").unwrap();
        assert_eq!(entry.request_count, 1);
    }

    // ===========================================
    // Concurrent access tests
    // ===========================================

    #[tokio::test]
    async fn test_limiter_clone_shares_state() {
        let limiter1 = RateLimiter::new();
        let limiter2 = limiter1.clone();
        let config = TestConfig::new(2, 60);

        // Use limiter1 for first request
        assert!(check_rate_limit(&limiter1, "192.168.1.1", &config).await);

        // Use limiter2 for second request - should share state
        assert!(check_rate_limit(&limiter2, "192.168.1.1", &config).await);

        // Third request on either should be blocked
        assert!(!check_rate_limit(&limiter1, "192.168.1.1", &config).await);
    }

    // ===========================================
    // Cleanup tests
    // ===========================================

    #[tokio::test]
    async fn test_cleanup_disabled_when_threshold_zero() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(100, 60); // Cleanup disabled (threshold = 0)

        // Add many entries
        for i in 0..100 {
            check_rate_limit(&limiter, &format!("192.168.1.{}", i), &config).await;
        }

        // All entries should remain (no cleanup)
        let inner = limiter.inner().lock().await;
        assert_eq!(inner.len(), 100);
    }

    #[tokio::test]
    async fn test_entries_tracked_per_ip() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(10, 60);

        // Make requests from 5 different IPs
        for i in 0..5 {
            check_rate_limit(&limiter, &format!("10.0.0.{}", i), &config).await;
        }

        let inner = limiter.inner().lock().await;
        assert_eq!(inner.len(), 5);
    }
}
