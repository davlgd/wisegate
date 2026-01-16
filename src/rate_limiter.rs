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
//! use wisegate::rate_limiter::check_rate_limit;
//! use wisegate::types::RateLimiter;
//!
//! let limiter: RateLimiter = Arc::new(Mutex::new(HashMap::new()));
//!
//! if check_rate_limit(&limiter, "192.168.1.1").await {
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
/// use wisegate::rate_limiter::check_rate_limit;
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
