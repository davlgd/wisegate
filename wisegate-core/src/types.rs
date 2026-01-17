//! Type definitions for WiseGate configuration and state management.
//!
//! This module contains the core types used throughout WiseGate for:
//! - Rate limiting configuration and state
//! - Proxy behavior configuration
//! - Cleanup configuration for memory management

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

// ============================================================================
// Composable Configuration Traits (Interface Segregation Principle)
// ============================================================================

/// Configuration for rate limiting behavior.
///
/// Implement this trait to customize how rate limiting is applied.
pub trait RateLimitingProvider: Send + Sync {
    /// Returns the rate limiting configuration.
    fn rate_limit_config(&self) -> &RateLimitConfig;

    /// Returns the rate limiter cleanup configuration.
    fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig;
}

/// Configuration for proxy behavior.
///
/// Implement this trait to customize upstream proxy settings.
pub trait ProxyProvider: Send + Sync {
    /// Returns the proxy configuration.
    fn proxy_config(&self) -> &ProxyConfig;

    /// Returns the list of allowed proxy IPs, if configured.
    /// When `Some`, strict mode is enabled. When `None`, permissive mode is used.
    fn allowed_proxy_ips(&self) -> Option<&[String]>;
}

/// Configuration for request filtering.
///
/// Implement this trait to customize which requests are blocked.
pub trait FilteringProvider: Send + Sync {
    /// Returns the list of blocked IP addresses.
    fn blocked_ips(&self) -> &[String];

    /// Returns the list of blocked HTTP methods.
    fn blocked_methods(&self) -> &[String];

    /// Returns the list of blocked URL patterns.
    fn blocked_patterns(&self) -> &[String];
}

/// Configuration for connection limits.
///
/// Implement this trait to customize connection handling.
pub trait ConnectionProvider: Send + Sync {
    /// Returns the maximum number of concurrent connections.
    fn max_connections(&self) -> usize;
}

/// Configuration for HTTP Basic Authentication and Bearer Token.
///
/// Implement this trait to enable optional authentication.
pub trait AuthenticationProvider: Send + Sync {
    /// Returns the list of authentication credentials for Basic Auth.
    fn auth_credentials(&self) -> &crate::auth::Credentials;

    /// Returns the realm for WWW-Authenticate header.
    fn auth_realm(&self) -> &str;

    /// Returns the bearer token, if configured.
    fn bearer_token(&self) -> Option<&str>;

    /// Returns true if Basic Auth is enabled (credentials configured).
    fn is_basic_auth_enabled(&self) -> bool {
        !self.auth_credentials().is_empty()
    }

    /// Returns true if Bearer Token auth is enabled.
    fn is_bearer_auth_enabled(&self) -> bool {
        self.bearer_token().is_some_and(|t| !t.is_empty())
    }

    /// Returns true if any authentication is enabled.
    fn is_auth_enabled(&self) -> bool {
        self.is_basic_auth_enabled() || self.is_bearer_auth_enabled()
    }
}

// ============================================================================
// ConfigProvider - Aggregated trait for full configuration
// ============================================================================

/// Trait for complete configuration injection.
///
/// This trait combines all specialized configuration traits into one.
/// Implement this trait to provide configuration from any source:
/// environment variables, files, remote services, etc.
///
/// For more granular control, implement the individual traits:
/// - [`RateLimitingProvider`] for rate limiting settings
/// - [`ProxyProvider`] for proxy behavior
/// - [`FilteringProvider`] for request filtering
/// - [`ConnectionProvider`] for connection limits
/// - [`AuthenticationProvider`] for HTTP Basic Authentication
///
/// # Example
///
/// ```
/// use wisegate_core::{
///     RateLimitingProvider, ProxyProvider, FilteringProvider, ConnectionProvider,
///     AuthenticationProvider, Credentials,
///     RateLimitConfig, RateLimitCleanupConfig, ProxyConfig,
/// };
/// use std::time::Duration;
///
/// struct MyConfig {
///     credentials: Credentials,
/// }
///
/// impl RateLimitingProvider for MyConfig {
///     fn rate_limit_config(&self) -> &RateLimitConfig {
///         static CONFIG: RateLimitConfig = RateLimitConfig {
///             max_requests: 100,
///             window_duration: Duration::from_secs(60),
///         };
///         &CONFIG
///     }
///
///     fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
///         static CONFIG: RateLimitCleanupConfig = RateLimitCleanupConfig {
///             threshold: 10_000,
///             interval: Duration::from_secs(60),
///         };
///         &CONFIG
///     }
/// }
///
/// impl ProxyProvider for MyConfig {
///     fn proxy_config(&self) -> &ProxyConfig {
///         static CONFIG: ProxyConfig = ProxyConfig {
///             timeout: Duration::from_secs(30),
///             max_body_size: 100 * 1024 * 1024,
///         };
///         &CONFIG
///     }
///
///     fn allowed_proxy_ips(&self) -> Option<&[String]> { None }
/// }
///
/// impl FilteringProvider for MyConfig {
///     fn blocked_ips(&self) -> &[String] { &[] }
///     fn blocked_methods(&self) -> &[String] { &[] }
///     fn blocked_patterns(&self) -> &[String] { &[] }
/// }
///
/// impl ConnectionProvider for MyConfig {
///     fn max_connections(&self) -> usize { 10_000 }
/// }
///
/// impl AuthenticationProvider for MyConfig {
///     fn auth_credentials(&self) -> &Credentials { &self.credentials }
///     fn auth_realm(&self) -> &str { "WiseGate" }
///     fn bearer_token(&self) -> Option<&str> { None }
/// }
/// ```
pub trait ConfigProvider:
    RateLimitingProvider
    + ProxyProvider
    + FilteringProvider
    + ConnectionProvider
    + AuthenticationProvider
{
}

// Blanket implementation: any type implementing all sub-traits is a ConfigProvider
impl<T> ConfigProvider for T where
    T: RateLimitingProvider
        + ProxyProvider
        + FilteringProvider
        + ConnectionProvider
        + AuthenticationProvider
{
}

/// Configuration for rate limiting per IP address.
///
/// Controls how many requests a single IP can make within a time window.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use wisegate_core::RateLimitConfig;
///
/// let config = RateLimitConfig {
///     max_requests: 100,
///     window_duration: Duration::from_secs(60),
/// };
///
/// assert!(config.is_valid());
/// ```
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per IP within the window
    pub max_requests: u32,
    /// Duration of the sliding window for rate limiting
    pub window_duration: Duration,
}

impl RateLimitConfig {
    /// Returns `true` if the configuration is valid.
    ///
    /// A valid configuration has at least one allowed request and a non-zero window.
    pub fn is_valid(&self) -> bool {
        self.max_requests > 0 && !self.window_duration.is_zero()
    }
}

/// Configuration for automatic cleanup of expired rate limit entries.
///
/// Prevents memory exhaustion by periodically removing stale entries
/// from the rate limiter when the entry count exceeds a threshold.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use wisegate_core::RateLimitCleanupConfig;
///
/// let config = RateLimitCleanupConfig {
///     threshold: 10_000,
///     interval: Duration::from_secs(60),
/// };
///
/// assert!(config.is_enabled());
/// ```
#[derive(Clone, Debug)]
pub struct RateLimitCleanupConfig {
    /// Number of entries before triggering cleanup (0 = disabled)
    pub threshold: usize,
    /// Minimum interval between cleanup operations
    pub interval: Duration,
}

impl RateLimitCleanupConfig {
    /// Returns `true` if automatic cleanup is enabled.
    ///
    /// Cleanup is enabled when threshold is greater than zero.
    pub fn is_enabled(&self) -> bool {
        self.threshold > 0
    }
}

/// Configuration for proxy behavior and upstream communication.
///
/// Controls timeouts and request size limits for proxied requests.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use wisegate_core::ProxyConfig;
///
/// let config = ProxyConfig {
///     timeout: Duration::from_secs(30),
///     max_body_size: ProxyConfig::mb_to_bytes(100),
/// };
///
/// assert!(config.is_valid());
/// assert_eq!(config.max_body_size_mb(), "100");
/// ```
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Timeout for upstream requests
    pub timeout: Duration,
    /// Maximum request body size in bytes (0 = unlimited)
    pub max_body_size: usize,
}

impl ProxyConfig {
    /// Returns `true` if the configuration is valid.
    ///
    /// A valid configuration has a non-zero timeout.
    pub fn is_valid(&self) -> bool {
        !self.timeout.is_zero()
    }

    /// Returns the maximum body size formatted for display.
    ///
    /// Returns "unlimited" if max_body_size is 0, otherwise returns the size in MB.
    pub fn max_body_size_mb(&self) -> String {
        if self.max_body_size == 0 {
            "unlimited".to_string()
        } else {
            (self.max_body_size / 1024 / 1024).to_string()
        }
    }

    /// Converts megabytes to bytes.
    ///
    /// Returns 0 if input is 0 (representing unlimited).
    ///
    /// # Arguments
    ///
    /// * `mb` - Size in megabytes
    ///
    /// # Returns
    ///
    /// Size in bytes, or 0 for unlimited
    pub fn mb_to_bytes(mb: usize) -> usize {
        if mb == 0 { 0 } else { mb * 1024 * 1024 }
    }
}

/// Entry for tracking rate limit state per IP address.
///
/// Stores the timestamp of the window start and the request count.
#[derive(Clone, Debug)]
pub struct RateLimitEntry {
    /// Timestamp of the first request in the current window
    pub window_start: Instant,
    /// Number of requests in the current window
    pub request_count: u32,
}

impl RateLimitEntry {
    /// Creates a new rate limit entry with count of 1.
    pub fn new() -> Self {
        Self {
            window_start: Instant::now(),
            request_count: 1,
        }
    }
}

impl Default for RateLimitEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe rate limiter state shared across all connections.
///
/// Wraps a HashMap mapping IP addresses to their rate limit entries.
/// Uses `tokio::sync::Mutex` for async-friendly locking that won't block
/// the Tokio thread pool.
///
/// # Example
///
/// ```
/// use wisegate_core::RateLimiter;
///
/// let limiter = RateLimiter::new();
/// ```
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl RateLimiter {
    /// Creates a new empty rate limiter.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns a reference to the inner mutex-protected map.
    pub fn inner(&self) -> &Arc<Mutex<HashMap<String, RateLimitEntry>>> {
        &self.inner
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // RateLimitConfig tests
    // ===========================================

    #[test]
    fn test_rate_limit_config_valid() {
        let config = RateLimitConfig {
            max_requests: 100,
            window_duration: Duration::from_secs(60),
        };
        assert!(config.is_valid());
    }

    #[test]
    fn test_rate_limit_config_invalid_zero_requests() {
        let config = RateLimitConfig {
            max_requests: 0,
            window_duration: Duration::from_secs(60),
        };
        assert!(!config.is_valid());
    }

    #[test]
    fn test_rate_limit_config_invalid_zero_duration() {
        let config = RateLimitConfig {
            max_requests: 100,
            window_duration: Duration::ZERO,
        };
        assert!(!config.is_valid());
    }

    #[test]
    fn test_rate_limit_config_invalid_both_zero() {
        let config = RateLimitConfig {
            max_requests: 0,
            window_duration: Duration::ZERO,
        };
        assert!(!config.is_valid());
    }

    // ===========================================
    // RateLimitCleanupConfig tests
    // ===========================================

    #[test]
    fn test_cleanup_config_enabled() {
        let config = RateLimitCleanupConfig {
            threshold: 10_000,
            interval: Duration::from_secs(60),
        };
        assert!(config.is_enabled());
    }

    #[test]
    fn test_cleanup_config_disabled_zero_threshold() {
        let config = RateLimitCleanupConfig {
            threshold: 0,
            interval: Duration::from_secs(60),
        };
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_cleanup_config_enabled_with_one() {
        let config = RateLimitCleanupConfig {
            threshold: 1,
            interval: Duration::from_secs(1),
        };
        assert!(config.is_enabled());
    }

    // ===========================================
    // ProxyConfig tests
    // ===========================================

    #[test]
    fn test_proxy_config_valid() {
        let config = ProxyConfig {
            timeout: Duration::from_secs(30),
            max_body_size: 100 * 1024 * 1024,
        };
        assert!(config.is_valid());
    }

    #[test]
    fn test_proxy_config_invalid_zero_timeout() {
        let config = ProxyConfig {
            timeout: Duration::ZERO,
            max_body_size: 100 * 1024 * 1024,
        };
        assert!(!config.is_valid());
    }

    #[test]
    fn test_proxy_config_valid_unlimited_body() {
        let config = ProxyConfig {
            timeout: Duration::from_secs(30),
            max_body_size: 0, // unlimited
        };
        assert!(config.is_valid());
    }

    #[test]
    fn test_proxy_config_max_body_size_mb_unlimited() {
        let config = ProxyConfig {
            timeout: Duration::from_secs(30),
            max_body_size: 0,
        };
        assert_eq!(config.max_body_size_mb(), "unlimited");
    }

    #[test]
    fn test_proxy_config_max_body_size_mb_100() {
        let config = ProxyConfig {
            timeout: Duration::from_secs(30),
            max_body_size: 100 * 1024 * 1024,
        };
        assert_eq!(config.max_body_size_mb(), "100");
    }

    #[test]
    fn test_proxy_config_max_body_size_mb_1() {
        let config = ProxyConfig {
            timeout: Duration::from_secs(30),
            max_body_size: 1 * 1024 * 1024,
        };
        assert_eq!(config.max_body_size_mb(), "1");
    }

    #[test]
    fn test_proxy_config_mb_to_bytes() {
        assert_eq!(ProxyConfig::mb_to_bytes(0), 0);
        assert_eq!(ProxyConfig::mb_to_bytes(1), 1024 * 1024);
        assert_eq!(ProxyConfig::mb_to_bytes(100), 100 * 1024 * 1024);
        assert_eq!(ProxyConfig::mb_to_bytes(1024), 1024 * 1024 * 1024);
    }

    // ===========================================
    // RateLimitEntry tests
    // ===========================================

    #[test]
    fn test_rate_limit_entry_new() {
        let entry = RateLimitEntry::new();
        assert_eq!(entry.request_count, 1);
        // window_start should be close to now (within a few ms)
        assert!(entry.window_start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn test_rate_limit_entry_default() {
        let entry = RateLimitEntry::default();
        assert_eq!(entry.request_count, 1);
    }

    // ===========================================
    // RateLimiter tests
    // ===========================================

    #[tokio::test]
    async fn test_rate_limiter_new_is_empty() {
        let limiter = RateLimiter::new();
        let inner = limiter.inner().lock().await;
        assert!(inner.is_empty());
    }

    #[tokio::test]
    async fn test_rate_limiter_default_is_empty() {
        let limiter = RateLimiter::default();
        let inner = limiter.inner().lock().await;
        assert!(inner.is_empty());
    }

    #[tokio::test]
    async fn test_rate_limiter_can_insert_and_retrieve() {
        let limiter = RateLimiter::new();
        {
            let mut inner = limiter.inner().lock().await;
            inner.insert("192.168.1.1".to_string(), RateLimitEntry::new());
        }
        {
            let inner = limiter.inner().lock().await;
            assert!(inner.contains_key("192.168.1.1"));
            assert_eq!(inner.len(), 1);
        }
    }

    #[test]
    fn test_rate_limiter_clone() {
        let limiter1 = RateLimiter::new();
        let limiter2 = limiter1.clone();
        // Both should point to the same inner Arc
        assert!(Arc::ptr_eq(limiter1.inner(), limiter2.inner()));
    }
}
