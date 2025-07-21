use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Configuration for rate limiting per IP address
#[derive(Clone)]
pub struct RateLimitConfig {
    pub max_requests: u32,
    pub window_duration: Duration,
}

/// Configuration for proxy behavior and performance
#[derive(Clone)]
pub struct ProxyConfig {
    /// Request timeout for upstream connections
    pub timeout: Duration,
    /// Maximum body size in bytes (0 = unlimited)
    pub max_body_size: usize,
    /// Enable streaming for large bodies
    pub enable_streaming: bool,
}

/// Rate limiter state: tracks request counts per IP with timestamps
pub type RateLimiter = Arc<Mutex<HashMap<String, (Instant, u32)>>>;
