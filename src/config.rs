//! Configuration management for WiseGate.
//!
//! This module handles loading and caching configuration from environment variables.
//! All configurations are computed once at first access and cached for the lifetime
//! of the application using `once_cell::sync::Lazy`.
//!
//! # Caching
//!
//! Configuration values are read from environment variables only once, at startup.
//! This provides:
//! - Consistent configuration throughout the application lifetime
//! - No runtime overhead from repeated environment lookups
//! - Thread-safe access without locking
//!
//! # Example
//!
//! ```
//! use wisegate::config;
//!
//! // Get cached configuration
//! let rate_config = config::get_rate_limit_config();
//! println!("Max requests: {}", rate_config.max_requests);
//!
//! let proxy_config = config::get_proxy_config();
//! println!("Timeout: {:?}", proxy_config.timeout);
//! ```

use std::env;
use std::str::FromStr;
use std::time::Duration;

use once_cell::sync::Lazy;
use tracing::warn;

use crate::env_vars;
use wisegate_core::{ConfigProvider, ProxyConfig, RateLimitCleanupConfig, RateLimitConfig};

// ============================================================================
// Cached Configuration (computed once at first access)
// ============================================================================

static RATE_LIMIT_CONFIG: Lazy<RateLimitConfig> = Lazy::new(compute_rate_limit_config);
static RATE_LIMIT_CLEANUP_CONFIG: Lazy<RateLimitCleanupConfig> =
    Lazy::new(compute_rate_limit_cleanup_config);
static PROXY_CONFIG: Lazy<ProxyConfig> = Lazy::new(compute_proxy_config);
static BLOCKED_IPS: Lazy<Vec<String>> = Lazy::new(compute_blocked_ips);
static BLOCKED_PATTERNS: Lazy<Vec<String>> = Lazy::new(compute_blocked_patterns);
static BLOCKED_METHODS: Lazy<Vec<String>> = Lazy::new(compute_blocked_methods);
static ALLOWED_PROXY_IPS: Lazy<Option<Vec<String>>> =
    Lazy::new(|| compute_allowed_proxy_ips_internal(|key| std::env::var(key)));
static MAX_CONNECTIONS: Lazy<usize> = Lazy::new(compute_max_connections);

// ============================================================================
// Default Values
// ============================================================================

const DEFAULT_RATE_LIMIT_REQUESTS: u32 = 100;
const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const DEFAULT_RATE_LIMIT_CLEANUP_THRESHOLD: usize = 10_000;
const DEFAULT_RATE_LIMIT_CLEANUP_INTERVAL_SECS: u64 = 60;
const DEFAULT_PROXY_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_BODY_SIZE_MB: usize = 100;
const DEFAULT_MAX_CONNECTIONS: usize = 10_000;

/// Whitelisted environment variable names for proxy IPs.
///
/// This prevents arbitrary environment variable disclosure via `TRUSTED_PROXY_IPS_VAR`.
const ALLOWED_PROXY_VAR_NAMES: &[&str] = &[
    "TRUSTED_PROXY_IPS",
    "REVERSE_PROXY_IPS",
    "PROXY_ALLOWLIST",
    "ALLOWED_PROXY_IPS",
    "PROXY_IPS",
];

// ============================================================================
// Internal Helpers
// ============================================================================

/// Parses an environment variable with fallback to a default value.
///
/// Logs a warning if the value exists but cannot be parsed.
fn parse_env_var_or_default<T>(var_name: &str, default: T) -> T
where
    T: FromStr + Copy,
{
    match env::var(var_name) {
        Ok(value) => match value.parse() {
            Ok(parsed) => parsed,
            Err(_) => {
                warn!(var = var_name, value = %value, "Invalid env var value, using default");
                default
            }
        },
        Err(_) => default,
    }
}

/// Parses a comma-separated string into a Vec of trimmed strings.
///
/// Filters out empty entries after trimming.
///
/// # Arguments
///
/// * `input` - The comma-separated string to parse
///
/// # Returns
///
/// A Vec of non-empty, trimmed strings
fn parse_comma_separated(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parses a comma-separated string with uppercase normalization.
///
/// Used for HTTP methods and other case-insensitive values.
///
/// # Arguments
///
/// * `input` - The comma-separated string to parse
///
/// # Returns
///
/// A Vec of non-empty, trimmed, uppercase strings
fn parse_comma_separated_uppercase(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_uppercase())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Public Configuration Getters
// ============================================================================

/// Returns the cached rate limiting configuration.
///
/// Configuration is read from environment variables on first access:
/// - `RATE_LIMIT_REQUESTS`: Max requests per window (default: 100)
/// - `RATE_LIMIT_WINDOW_SECS`: Window duration in seconds (default: 60)
///
/// # Example
///
/// ```
/// use wisegate::config::get_rate_limit_config;
///
/// let config = get_rate_limit_config();
/// println!("Allowing {} requests per {:?}", config.max_requests, config.window_duration);
/// ```
pub fn get_rate_limit_config() -> &'static RateLimitConfig {
    &RATE_LIMIT_CONFIG
}

/// Compute rate limiting configuration from environment variables
/// Invalid values fall back to defaults and log warnings
fn compute_rate_limit_config() -> RateLimitConfig {
    let max_requests =
        parse_env_var_or_default(env_vars::RATE_LIMIT_REQUESTS, DEFAULT_RATE_LIMIT_REQUESTS);

    let window_secs = parse_env_var_or_default(
        env_vars::RATE_LIMIT_WINDOW_SECS,
        DEFAULT_RATE_LIMIT_WINDOW_SECS,
    );

    let config = RateLimitConfig {
        max_requests,
        window_duration: Duration::from_secs(window_secs),
    };

    // Validate configuration
    if !config.is_valid() {
        warn!("Invalid rate limit configuration, using defaults");
        return RateLimitConfig {
            max_requests: DEFAULT_RATE_LIMIT_REQUESTS,
            window_duration: Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
        };
    }

    config
}

/// Returns the cached rate limiter cleanup configuration.
///
/// Controls automatic cleanup of expired entries to prevent memory exhaustion.
///
/// Configuration is read from environment variables on first access:
/// - `RATE_LIMIT_CLEANUP_THRESHOLD`: Entry count before cleanup (default: 10000, 0 = disabled)
/// - `RATE_LIMIT_CLEANUP_INTERVAL_SECS`: Minimum interval between cleanups (default: 60)
///
/// # Example
///
/// ```
/// use wisegate::config::get_rate_limit_cleanup_config;
///
/// let config = get_rate_limit_cleanup_config();
/// if config.is_enabled() {
///     println!("Cleanup triggers at {} entries", config.threshold);
/// }
/// ```
pub fn get_rate_limit_cleanup_config() -> &'static RateLimitCleanupConfig {
    &RATE_LIMIT_CLEANUP_CONFIG
}

/// Computes rate limiter cleanup configuration from environment variables.
fn compute_rate_limit_cleanup_config() -> RateLimitCleanupConfig {
    let threshold = parse_env_var_or_default(
        env_vars::RATE_LIMIT_CLEANUP_THRESHOLD,
        DEFAULT_RATE_LIMIT_CLEANUP_THRESHOLD,
    );

    let interval_secs = parse_env_var_or_default(
        env_vars::RATE_LIMIT_CLEANUP_INTERVAL_SECS,
        DEFAULT_RATE_LIMIT_CLEANUP_INTERVAL_SECS,
    );

    RateLimitCleanupConfig {
        threshold,
        interval: Duration::from_secs(interval_secs),
    }
}

/// Returns the cached proxy configuration.
///
/// Controls upstream request behavior including timeouts and size limits.
///
/// Configuration is read from environment variables on first access:
/// - `PROXY_TIMEOUT_SECS`: Upstream request timeout (default: 30)
/// - `MAX_BODY_SIZE_MB`: Maximum request body size (default: 100, 0 = unlimited)
///
/// # Example
///
/// ```
/// use wisegate::config::get_proxy_config;
///
/// let config = get_proxy_config();
/// println!("Timeout: {:?}, Max body: {}", config.timeout, config.max_body_size_mb());
/// ```
pub fn get_proxy_config() -> &'static ProxyConfig {
    &PROXY_CONFIG
}

/// Computes proxy configuration from environment variables.
fn compute_proxy_config() -> ProxyConfig {
    let timeout_secs =
        parse_env_var_or_default(env_vars::PROXY_TIMEOUT_SECS, DEFAULT_PROXY_TIMEOUT_SECS);

    let max_body_mb =
        parse_env_var_or_default(env_vars::MAX_BODY_SIZE_MB, DEFAULT_MAX_BODY_SIZE_MB);

    let config = ProxyConfig {
        timeout: Duration::from_secs(timeout_secs),
        max_body_size: ProxyConfig::mb_to_bytes(max_body_mb),
    };

    // Validate configuration
    if !config.is_valid() {
        warn!("Invalid proxy configuration, using defaults");
        return ProxyConfig {
            timeout: Duration::from_secs(DEFAULT_PROXY_TIMEOUT_SECS),
            max_body_size: ProxyConfig::mb_to_bytes(DEFAULT_MAX_BODY_SIZE_MB),
        };
    }

    config
}

/// Returns the cached maximum number of concurrent connections.
///
/// Limits simultaneous connections to prevent resource exhaustion under attack.
/// When the limit is reached, new connections are rejected immediately.
///
/// Configuration is read from `MAX_CONNECTIONS` environment variable on first access.
///
/// # Returns
///
/// - `0`: Unlimited connections (not recommended for production)
/// - `> 0`: Maximum number of concurrent connections
///
/// **Default**: `10000`
///
/// # Example
///
/// ```
/// use wisegate::config::get_max_connections;
///
/// let max_conn = get_max_connections();
/// if max_conn > 0 {
///     println!("Limiting to {} concurrent connections", max_conn);
/// } else {
///     println!("Unlimited connections (not recommended)");
/// }
/// ```
pub fn get_max_connections() -> usize {
    *MAX_CONNECTIONS
}

/// Computes maximum connections from environment variable.
fn compute_max_connections() -> usize {
    parse_env_var_or_default(env_vars::MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS)
}

/// Returns the cached list of allowed proxy IPs, if configured.
///
/// When `Some`, WiseGate operates in strict mode, validating that requests
/// come from trusted proxies. When `None`, permissive mode is used.
///
/// Configuration is read from environment variables on first access:
/// - `CC_REVERSE_PROXY_IPS`: Primary variable for trusted proxy IPs
/// - `TRUSTED_PROXY_IPS_VAR`: Alternative variable name (must be whitelisted)
///
/// # Returns
///
/// - `Some(&Vec<String>)`: List of trusted proxy IPs (strict mode)
/// - `None`: No proxy validation (permissive mode)
///
/// # Example
///
/// ```
/// use wisegate::config::get_allowed_proxy_ips;
///
/// match get_allowed_proxy_ips() {
///     Some(ips) => println!("Strict mode with {} trusted proxies", ips.len()),
///     None => println!("Permissive mode"),
/// }
/// ```
pub fn get_allowed_proxy_ips() -> Option<&'static Vec<String>> {
    ALLOWED_PROXY_IPS.as_ref()
}

/// Computes allowed proxy IPs from environment variables.
fn compute_allowed_proxy_ips_internal<F>(env_var: F) -> Option<Vec<String>>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    // Try primary variable first
    if let Ok(ips) = env_var(env_vars::ALLOWED_PROXY_IPS)
        && !ips.trim().is_empty()
    {
        return Some(parse_comma_separated(&ips));
    }

    // Try user-defined alternative variable if set (only from whitelist)
    if let Ok(alt_var_name) = env_var(env_vars::TRUSTED_PROXY_IPS_VAR) {
        // Security: only allow reading from whitelisted variable names
        // This prevents arbitrary environment variable disclosure
        if ALLOWED_PROXY_VAR_NAMES.contains(&alt_var_name.as_str())
            && let Ok(ips) = env_var(&alt_var_name)
            && !ips.trim().is_empty()
        {
            return Some(parse_comma_separated(&ips));
        } else if !ALLOWED_PROXY_VAR_NAMES.contains(&alt_var_name.as_str()) {
            warn!(
                var = %alt_var_name,
                allowed = ?ALLOWED_PROXY_VAR_NAMES,
                "Invalid TRUSTED_PROXY_IPS_VAR value"
            );
        }
    }

    None
}

/// Returns the cached list of blocked IP addresses.
///
/// Requests from these IPs will receive a 403 Forbidden response.
///
/// Configuration is read from `BLOCKED_IPS` environment variable on first access.
///
/// # Example
///
/// ```
/// use wisegate::config::get_blocked_ips;
///
/// let blocked = get_blocked_ips();
/// println!("{} IPs are blocked", blocked.len());
/// ```
pub fn get_blocked_ips() -> &'static Vec<String> {
    &BLOCKED_IPS
}

/// Computes blocked IPs from environment variable.
fn compute_blocked_ips() -> Vec<String> {
    env::var(env_vars::BLOCKED_IPS)
        .map(|s| parse_comma_separated(&s))
        .unwrap_or_default()
}

/// Returns the cached list of blocked URL patterns.
///
/// Requests with URLs containing these patterns will receive a 404 Not Found response.
/// Patterns are matched as substrings and also checked after URL decoding.
///
/// Configuration is read from `BLOCKED_PATTERNS` environment variable on first access.
///
/// # Example
///
/// ```
/// use wisegate::config::get_blocked_patterns;
///
/// let patterns = get_blocked_patterns();
/// for pattern in patterns.iter() {
///     println!("Blocking URLs containing: {}", pattern);
/// }
/// ```
pub fn get_blocked_patterns() -> &'static Vec<String> {
    &BLOCKED_PATTERNS
}

/// Computes blocked URL patterns from environment variable.
fn compute_blocked_patterns() -> Vec<String> {
    env::var(env_vars::BLOCKED_PATTERNS)
        .map(|s| parse_comma_separated(&s))
        .unwrap_or_default()
}

/// Returns the cached list of blocked HTTP methods.
///
/// Requests using these methods will receive a 405 Method Not Allowed response.
/// Method names are normalized to uppercase.
///
/// Configuration is read from `BLOCKED_METHODS` environment variable on first access.
///
/// # Example
///
/// ```
/// use wisegate::config::get_blocked_methods;
///
/// let methods = get_blocked_methods();
/// if methods.contains(&"DELETE".to_string()) {
///     println!("DELETE requests are blocked");
/// }
/// ```
pub fn get_blocked_methods() -> &'static Vec<String> {
    &BLOCKED_METHODS
}

/// Computes blocked HTTP methods from environment variable.
fn compute_blocked_methods() -> Vec<String> {
    env::var(env_vars::BLOCKED_METHODS)
        .map(|s| parse_comma_separated_uppercase(&s))
        .unwrap_or_default()
}

// ============================================================================
// EnvVarConfig - ConfigProvider implementation using environment variables
// ============================================================================

/// Configuration provider that reads from environment variables.
///
/// This is the default configuration provider for WiseGate CLI.
/// All values are cached at creation time using the global lazy statics.
///
/// # Example
///
/// ```
/// use wisegate::config::EnvVarConfig;
/// use wisegate::types::ConfigProvider;
///
/// let config = EnvVarConfig::new();
/// println!("Max requests: {}", config.rate_limit_config().max_requests);
/// ```
#[derive(Clone, Debug)]
pub struct EnvVarConfig {
    // We use references to the global lazy statics for zero-copy access
    _private: (),
}

impl EnvVarConfig {
    /// Creates a new configuration provider from environment variables.
    ///
    /// This triggers lazy initialization of all configuration values
    /// if they haven't been accessed yet.
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl Default for EnvVarConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigProvider for EnvVarConfig {
    fn rate_limit_config(&self) -> &RateLimitConfig {
        get_rate_limit_config()
    }

    fn rate_limit_cleanup_config(&self) -> &RateLimitCleanupConfig {
        get_rate_limit_cleanup_config()
    }

    fn proxy_config(&self) -> &ProxyConfig {
        get_proxy_config()
    }

    fn allowed_proxy_ips(&self) -> Option<&[String]> {
        get_allowed_proxy_ips().map(|v| v.as_slice())
    }

    fn blocked_ips(&self) -> &[String] {
        get_blocked_ips()
    }

    fn blocked_methods(&self) -> &[String] {
        get_blocked_methods()
    }

    fn blocked_patterns(&self) -> &[String] {
        get_blocked_patterns()
    }

    fn max_connections(&self) -> usize {
        get_max_connections()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Helper function to create a mock environment function for testing
    fn create_mock_env(
        vars: HashMap<&str, &str>,
    ) -> impl Fn(&str) -> Result<String, std::env::VarError> {
        move |key: &str| {
            vars.get(key)
                .map(|v| v.to_string())
                .ok_or(std::env::VarError::NotPresent)
        }
    }

    #[test]
    fn test_get_allowed_proxy_ips_with_cc_reverse_proxy_ips() {
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::ALLOWED_PROXY_IPS, "192.168.1.1,10.0.0.1");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "192.168.1.1");
        assert_eq!(ips[1], "10.0.0.1");
    }

    #[test]
    fn test_get_allowed_proxy_ips_with_alternative_var() {
        let mut env_vars = HashMap::new();
        // Use a whitelisted variable name
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "TRUSTED_PROXY_IPS");
        env_vars.insert("TRUSTED_PROXY_IPS", "172.16.0.1,203.0.113.1");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "172.16.0.1");
        assert_eq!(ips[1], "203.0.113.1");
    }

    #[test]
    fn test_get_allowed_proxy_ips_cc_takes_priority() {
        // Both variables set - CC_REVERSE_PROXY_IPS should take priority
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::ALLOWED_PROXY_IPS, "192.168.1.1");
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "MY_CUSTOM_PROXY_IPS");
        env_vars.insert("MY_CUSTOM_PROXY_IPS", "172.16.0.1");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "192.168.1.1"); // Should use CC_REVERSE_PROXY_IPS value
    }

    #[test]
    fn test_get_allowed_proxy_ips_fallback_to_alternative() {
        // Don't set CC_REVERSE_PROXY_IPS, only alternative (using whitelisted name)
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "PROXY_ALLOWLIST");
        env_vars.insert("PROXY_ALLOWLIST", "10.1.1.1,10.1.1.2,10.1.1.3");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.1.1.1");
        assert_eq!(ips[1], "10.1.1.2");
        assert_eq!(ips[2], "10.1.1.3");
    }

    #[test]
    fn test_get_allowed_proxy_ips_rejects_non_whitelisted_var() {
        // Try to use a non-whitelisted variable name - should be rejected
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "DATABASE_URL");
        env_vars.insert("DATABASE_URL", "10.1.1.1,10.1.1.2");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        // Should return None because DATABASE_URL is not in the whitelist
        assert!(result.is_none());
    }

    #[test]
    fn test_get_allowed_proxy_ips_none_when_no_vars() {
        // No relevant env vars set
        let env_vars = HashMap::new();
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_none());
    }

    #[test]
    fn test_get_allowed_proxy_ips_handles_whitespace() {
        // Test with whitespace around IPs
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::ALLOWED_PROXY_IPS, " 192.168.1.1 , 10.0.0.1 ");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "192.168.1.1");
        assert_eq!(ips[1], "10.0.0.1");
    }

    #[test]
    fn test_get_allowed_proxy_ips_ignores_empty_alternative_var() {
        // Set alternative var but with empty value
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "EMPTY_PROXY_VAR");
        env_vars.insert("EMPTY_PROXY_VAR", "");
        let env_fn = create_mock_env(env_vars);

        let result = compute_allowed_proxy_ips_internal(env_fn);

        assert!(result.is_none());
    }
}
