//! Environment variable names used throughout WiseGate configuration

/// Proxy security configuration
pub const ALLOWED_PROXY_IPS: &str = "CC_REVERSE_PROXY_IPS";
pub const TRUSTED_PROXY_IPS_VAR: &str = "TRUSTED_PROXY_IPS_VAR";

/// IP and request filtering
pub const BLOCKED_IPS: &str = "BLOCKED_IPS";
pub const BLOCKED_METHODS: &str = "BLOCKED_METHODS";
pub const BLOCKED_PATTERNS: &str = "BLOCKED_PATTERNS";

/// Rate limiting configuration
pub const RATE_LIMIT_REQUESTS: &str = "RATE_LIMIT_REQUESTS";
pub const RATE_LIMIT_WINDOW_SECS: &str = "RATE_LIMIT_WINDOW_SECS";

/// Proxy behavior configuration
pub const PROXY_TIMEOUT_SECS: &str = "PROXY_TIMEOUT_SECS";
pub const MAX_BODY_SIZE_MB: &str = "MAX_BODY_SIZE_MB";
pub const ENABLE_STREAMING: &str = "ENABLE_STREAMING";

/// Get all environment variable names for documentation/validation
pub fn all_env_vars() -> &'static [&'static str] {
    &[
        ALLOWED_PROXY_IPS,
        TRUSTED_PROXY_IPS_VAR,
        BLOCKED_IPS,
        BLOCKED_METHODS,
        BLOCKED_PATTERNS,
        RATE_LIMIT_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
        PROXY_TIMEOUT_SECS,
        MAX_BODY_SIZE_MB,
        ENABLE_STREAMING,
    ]
}
