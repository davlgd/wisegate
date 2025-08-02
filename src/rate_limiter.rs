use std::time::Instant;

use crate::config;
use crate::types::RateLimiter;

/// Rate limiting module
/// Check if a request from the given IP should be rate limited
///
/// Uses a sliding window approach:
/// - If window has expired, reset counter
/// - If under limit, increment counter and allow
/// - If over limit, deny request
pub fn check_rate_limit(limiter: &RateLimiter, ip: &str) -> bool {
    let config = config::get_rate_limit_config();
    let mut rate_map = limiter.lock().unwrap();
    let now = Instant::now();

    match rate_map.get_mut(ip) {
        Some((last_request_time, request_count)) => {
            // Check if we're in a new time window
            if now.duration_since(*last_request_time) >= config.window_duration {
                // Reset window
                *last_request_time = now;
                *request_count = 1;
                true
            } else if *request_count < config.max_requests {
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
