//! Default configuration values for WiseGate.
//!
//! This module centralizes all default values used throughout WiseGate,
//! ensuring consistency between production code and tests.

use std::time::Duration;

/// Default maximum requests per rate limit window.
pub const RATE_LIMIT_REQUESTS: u32 = 100;

/// Default rate limit window duration in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Default rate limit window duration.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

/// Default cleanup threshold (number of entries before triggering cleanup).
pub const RATE_LIMIT_CLEANUP_THRESHOLD: usize = 10_000;

/// Default cleanup interval in seconds.
pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 60;

/// Default cleanup interval duration.
pub const RATE_LIMIT_CLEANUP_INTERVAL: Duration =
    Duration::from_secs(RATE_LIMIT_CLEANUP_INTERVAL_SECS);

/// Default proxy timeout in seconds.
pub const PROXY_TIMEOUT_SECS: u64 = 30;

/// Default proxy timeout duration.
pub const PROXY_TIMEOUT: Duration = Duration::from_secs(PROXY_TIMEOUT_SECS);

/// Default maximum body size in megabytes.
pub const MAX_BODY_SIZE_MB: usize = 100;

/// Default maximum body size in bytes.
pub const MAX_BODY_SIZE: usize = MAX_BODY_SIZE_MB * 1024 * 1024;

/// Default maximum concurrent connections.
pub const MAX_CONNECTIONS: usize = 10_000;

/// Default authentication realm.
pub const AUTH_REALM: &str = "WiseGate";
