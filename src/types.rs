use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for rate limiting per IP address
#[derive(Clone, Debug)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_duration: Duration,
}

impl RateLimitConfig {
    /// Check if the configuration is valid
    pub fn is_valid(&self) -> bool {
        self.max_requests > 0 && !self.window_duration.is_zero()
    }
}

/// Configuration for proxy behavior and performance
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub timeout: Duration,
    pub max_body_size: usize,
}

impl ProxyConfig {
    /// Check if the configuration is valid
    pub fn is_valid(&self) -> bool {
        !self.timeout.is_zero()
    }

    /// Get max body size in MB for display
    pub fn max_body_size_mb(&self) -> String {
        if self.max_body_size == 0 {
            "unlimited".to_string()
        } else {
            (self.max_body_size / 1024 / 1024).to_string()
        }
    }

    /// Convert MB to bytes for internal use
    pub fn mb_to_bytes(mb: usize) -> usize {
        if mb == 0 { 0 } else { mb * 1024 * 1024 }
    }
}

/// Rate limiter state: tracks request counts per IP with timestamps
/// Tuple format: (last_request_time, request_count)
pub type RateLimiter = Arc<Mutex<HashMap<String, (Instant, u32)>>>;
