//! Environment variable constants for WiseGate configuration.
//!
//! This module centralizes all environment variable names used by WiseGate,
//! making it easy to document and maintain configuration options.
//!
//! # Categories
//!
//! - **Proxy Security**: Control trusted proxy IPs and validation
//! - **Filtering**: Block IPs, HTTP methods, and URL patterns
//! - **Rate Limiting**: Configure request limits and cleanup
//! - **Proxy Behavior**: Timeouts and size limits
//!
//! # Example
//!
//! ```bash
//! export CC_REVERSE_PROXY_IPS="192.168.1.1,10.0.0.1"
//! export BLOCKED_IPS="malicious.ip.here"
//! export RATE_LIMIT_REQUESTS=100
//! ```

// ============================================================================
// Proxy Security Configuration
// ============================================================================

/// Comma-separated list of trusted proxy/load balancer IPs.
///
/// When set, enables strict mode with header validation.
/// Requests must come from these IPs to be accepted.
///
/// **Example**: `"192.168.1.1,10.0.0.1,172.16.0.0/24"`
pub const ALLOWED_PROXY_IPS: &str = "CC_REVERSE_PROXY_IPS";

/// Alternative environment variable name for trusted proxy IPs.
///
/// Must be one of the whitelisted names for security:
/// `TRUSTED_PROXY_IPS`, `REVERSE_PROXY_IPS`, `PROXY_ALLOWLIST`,
/// `ALLOWED_PROXY_IPS`, `PROXY_IPS`
///
/// **Example**: `"TRUSTED_PROXY_IPS"`
pub const TRUSTED_PROXY_IPS_VAR: &str = "TRUSTED_PROXY_IPS_VAR";

// ============================================================================
// IP and Request Filtering
// ============================================================================

/// Comma-separated list of blocked client IP addresses.
///
/// Requests from these IPs will receive a 403 Forbidden response.
///
/// **Example**: `"192.168.1.100,10.0.0.50"`
pub const BLOCKED_IPS: &str = "BLOCKED_IPS";

/// Comma-separated list of blocked HTTP methods.
///
/// Requests using these methods will receive a 405 Method Not Allowed response.
///
/// **Example**: `"PUT,DELETE,PATCH"`
pub const BLOCKED_METHODS: &str = "BLOCKED_METHODS";

/// Comma-separated list of blocked URL patterns.
///
/// Requests with URLs containing these patterns will receive a 404 Not Found response.
/// Patterns are matched as substrings (case-sensitive).
///
/// **Example**: `".php,.yaml,/admin,wp-login"`
pub const BLOCKED_PATTERNS: &str = "BLOCKED_PATTERNS";

// ============================================================================
// Rate Limiting Configuration
// ============================================================================

/// Maximum requests allowed per IP within the time window.
///
/// **Default**: `100`
///
/// **Example**: `"200"`
pub const RATE_LIMIT_REQUESTS: &str = "RATE_LIMIT_REQUESTS";

/// Duration of the rate limiting window in seconds.
///
/// **Default**: `60`
///
/// **Example**: `"120"`
pub const RATE_LIMIT_WINDOW_SECS: &str = "RATE_LIMIT_WINDOW_SECS";

/// Number of rate limit entries before triggering automatic cleanup.
///
/// Set to `0` to disable automatic cleanup.
///
/// **Default**: `10000`
///
/// **Example**: `"50000"`
pub const RATE_LIMIT_CLEANUP_THRESHOLD: &str = "RATE_LIMIT_CLEANUP_THRESHOLD";

/// Minimum interval between cleanup operations in seconds.
///
/// **Default**: `60`
///
/// **Example**: `"300"`
pub const RATE_LIMIT_CLEANUP_INTERVAL_SECS: &str = "RATE_LIMIT_CLEANUP_INTERVAL_SECS";

// ============================================================================
// Proxy Behavior Configuration
// ============================================================================

/// Timeout for upstream requests in seconds.
///
/// **Default**: `30`
///
/// **Example**: `"60"`
pub const PROXY_TIMEOUT_SECS: &str = "PROXY_TIMEOUT_SECS";

/// Maximum request body size in megabytes.
///
/// Set to `0` for unlimited size.
///
/// **Default**: `100`
///
/// **Example**: `"50"`
pub const MAX_BODY_SIZE_MB: &str = "MAX_BODY_SIZE_MB";

// ============================================================================
// Utility Functions
// ============================================================================

/// Returns a slice containing all environment variable names.
///
/// Useful for documentation, validation, and verbose logging.
///
/// # Example
///
/// ```
/// use wisegate::env_vars::all_env_vars;
///
/// for var_name in all_env_vars() {
///     println!("Supported: {}", var_name);
/// }
/// ```
pub fn all_env_vars() -> &'static [&'static str] {
    &[
        ALLOWED_PROXY_IPS,
        TRUSTED_PROXY_IPS_VAR,
        BLOCKED_IPS,
        BLOCKED_METHODS,
        BLOCKED_PATTERNS,
        RATE_LIMIT_REQUESTS,
        RATE_LIMIT_WINDOW_SECS,
        RATE_LIMIT_CLEANUP_THRESHOLD,
        RATE_LIMIT_CLEANUP_INTERVAL_SECS,
        PROXY_TIMEOUT_SECS,
        MAX_BODY_SIZE_MB,
    ]
}
