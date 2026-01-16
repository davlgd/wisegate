use std::time::Instant;
use tokio::sync::Mutex;
use tracing::debug;

use crate::config;
use crate::types::RateLimiter;

/// Tracks the last cleanup time to enforce minimum interval between cleanups
static LAST_CLEANUP: Mutex<Option<Instant>> = Mutex::const_new(None);

/// Rate limiting module
/// Check if a request from the given IP should be rate limited
///
/// Uses a sliding window approach:
/// - If window has expired, reset counter
/// - If under limit, increment counter and allow
/// - If over limit, deny request
///
/// Also performs periodic cleanup of expired entries to prevent memory exhaustion
///
/// Uses tokio::sync::Mutex for async-friendly locking that won't block the thread pool
pub async fn check_rate_limit(limiter: &RateLimiter, ip: &str) -> bool {
    let rate_config = config::get_rate_limit_config();
    let cleanup_config = config::get_rate_limit_cleanup_config();
    let mut rate_map = limiter.lock().await;
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
            rate_map.retain(|_, (last_time, _)| now.duration_since(*last_time) < expiry_threshold);
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
        Some((last_request_time, request_count)) => {
            // Check if we're in a new time window
            if now.duration_since(*last_request_time) >= rate_config.window_duration {
                // Reset window
                *last_request_time = now;
                *request_count = 1;
                true
            } else if *request_count < rate_config.max_requests {
                // Within limit, increment counter
                *request_count += 1;
                true
            } else {
                // Rate limit exceeded
                false
            }
        }
        None => {
            // First request from this IP
            rate_map.insert(ip.to_string(), (now, 1));
            true
        }
    }
}
