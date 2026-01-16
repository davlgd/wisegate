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

/// Configuration for rate limiting per IP address.
///
/// Controls how many requests a single IP can make within a time window.
///
/// # Example
///
/// ```
/// use std::time::Duration;
/// use wisegate::types::RateLimitConfig;
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
/// use wisegate::types::RateLimitCleanupConfig;
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
/// use wisegate::types::ProxyConfig;
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
/// use wisegate::types::RateLimiter;
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
