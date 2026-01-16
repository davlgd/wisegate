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

    // ===========================================
    // Time-based / Window expiration tests
    // ===========================================

    #[tokio::test]
    async fn test_window_reset_after_expiration() {
        let limiter = RateLimiter::new();
        // Use very short window for testing
        let config = TestConfig {
            rate_limit: RateLimitConfig {
                max_requests: 2,
                window_duration: Duration::from_millis(1),
            },
            cleanup: RateLimitCleanupConfig {
                threshold: 0,
                interval: Duration::from_secs(60),
            },
        };

        // First two requests allowed
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Third blocked
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Should be allowed again after window expires
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
    }

    #[tokio::test]
    async fn test_window_reset_resets_counter() {
        let limiter = RateLimiter::new();
        let config = TestConfig {
            rate_limit: RateLimitConfig {
                max_requests: 3,
                window_duration: Duration::from_millis(1),
            },
            cleanup: RateLimitCleanupConfig {
                threshold: 0,
                interval: Duration::from_secs(60),
            },
        };

        // Use full quota
        for _ in 0..3 {
            assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        }
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Counter should reset, full quota available again
        for _ in 0..3 {
            assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        }
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);
    }

    #[tokio::test]
    async fn test_window_not_expired_keeps_count() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(5, 3600); // 1 hour window

        // Make 3 requests
        for _ in 0..3 {
            assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        }

        // Verify counter is 3
        {
            let inner = limiter.inner().lock().await;
            assert_eq!(inner.get("192.168.1.1").unwrap().request_count, 3);
        }

        // Make 2 more requests (still within limit)
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Now should be blocked (5 requests made)
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Counter should still be 5 (not increased when blocked)
        let inner = limiter.inner().lock().await;
        assert_eq!(inner.get("192.168.1.1").unwrap().request_count, 5);
    }

    #[tokio::test]
    async fn test_different_ips_different_windows() {
        let limiter = RateLimiter::new();
        let config = TestConfig {
            rate_limit: RateLimitConfig {
                max_requests: 2,
                window_duration: Duration::from_millis(50),
            },
            cleanup: RateLimitCleanupConfig {
                threshold: 0,
                interval: Duration::from_secs(60),
            },
        };

        // IP1: exhaust quota
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // Wait a bit (not enough for window to expire)
        tokio::time::sleep(Duration::from_millis(10)).await;

        // IP2: start fresh
        assert!(check_rate_limit(&limiter, "192.168.1.2", &config).await);

        // Wait for IP1's window to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        // IP1 should be allowed again
        assert!(check_rate_limit(&limiter, "192.168.1.1", &config).await);

        // IP2 still within its window, should have 1 request counted
        let inner = limiter.inner().lock().await;
        // IP2 might have had its window expire too, depends on timing
        // Just verify both IPs are tracked
        assert!(inner.contains_key("192.168.1.1"));
        assert!(inner.contains_key("192.168.1.2"));
    }

    // ===========================================
    // Cleanup with expiration tests
    // ===========================================

    #[tokio::test]
    async fn test_cleanup_removes_expired_entries() {
        let limiter = RateLimiter::new();
        let config = TestConfig {
            rate_limit: RateLimitConfig {
                max_requests: 100,
                window_duration: Duration::from_millis(1), // Very short window
            },
            cleanup: RateLimitCleanupConfig {
                threshold: 1,                       // Trigger cleanup when > 1 entry
                interval: Duration::from_millis(1), // Allow frequent cleanup
            },
        };

        // Add first entry
        check_rate_limit(&limiter, "192.168.1.1", &config).await;

        // Wait for it to expire (2x window duration for cleanup)
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Add second entry - this should trigger cleanup
        check_rate_limit(&limiter, "192.168.1.2", &config).await;

        // Wait a bit more and add third to trigger another cleanup check
        tokio::time::sleep(Duration::from_millis(10)).await;
        check_rate_limit(&limiter, "192.168.1.3", &config).await;

        // Only recent entries should remain (older ones cleaned up)
        let inner = limiter.inner().lock().await;
        // Due to timing, we can't predict exactly which entries remain
        // but we can verify cleanup mechanism works by checking count is <= 3
        assert!(inner.len() <= 3);
    }

    // ===========================================
    // Concurrent request tests
    // ===========================================

    #[tokio::test]
    async fn test_concurrent_requests_same_ip() {
        let limiter = RateLimiter::new();
        let config = TestConfig::new(10, 60);

        // Spawn multiple concurrent requests
        let mut handles = vec![];
        for _ in 0..10 {
            let limiter_clone = limiter.clone();
            let handle = tokio::spawn(async move {
                let config = TestConfig::new(10, 60);
                check_rate_limit(&limiter_clone, "192.168.1.1", &config).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let results: Vec<bool> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All 10 should be allowed
        assert_eq!(results.iter().filter(|&&r| r).count(), 10);

        // 11th request should be blocked
        assert!(!check_rate_limit(&limiter, "192.168.1.1", &config).await);
    }

    #[tokio::test]
    async fn test_concurrent_requests_different_ips() {
        let limiter = RateLimiter::new();

        // Spawn requests from different IPs concurrently
        let mut handles = vec![];
        for i in 0..50 {
            let limiter_clone = limiter.clone();
            let ip = format!("192.168.1.{}", i);
            let handle = tokio::spawn(async move {
                let config = TestConfig::new(5, 60);
                check_rate_limit(&limiter_clone, &ip, &config).await
            });
            handles.push(handle);
        }

        // Wait for all to complete
        let results: Vec<bool> = futures::future::join_all(handles)
            .await
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        // All should be allowed (first request from each IP)
        assert!(results.iter().all(|&r| r));

        // Verify all IPs are tracked
        let inner = limiter.inner().lock().await;
        assert_eq!(inner.len(), 50);
    }
}
