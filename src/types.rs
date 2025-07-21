use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for rate limiting per IP address
#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_duration: Duration,
}

/// Rate limiter state: tracks request counts per IP with timestamps
pub type RateLimiter = Arc<Mutex<HashMap<String, (Instant, u32)>>>;
