use std::env;
use std::time::Duration;

use crate::env_vars;
use crate::types::{ProxyConfig, RateLimitConfig};

/// Configuration management module
/// Get rate limiting configuration from environment variables
pub fn get_rate_limit_config() -> RateLimitConfig {
    let max_requests = env::var(env_vars::RATE_LIMIT_REQUESTS)
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100);

    let window_secs = env::var(env_vars::RATE_LIMIT_WINDOW_SECS)
        .unwrap_or_else(|_| "60".to_string())
        .parse()
        .unwrap_or(60);

    RateLimitConfig {
        max_requests,
        window_duration: Duration::from_secs(window_secs),
    }
}

/// Get proxy configuration from environment variables
pub fn get_proxy_config() -> ProxyConfig {
    let timeout_secs = env::var(env_vars::PROXY_TIMEOUT_SECS)
        .unwrap_or_else(|_| "30".to_string())
        .parse()
        .unwrap_or(30);

    let max_body_mb = env::var(env_vars::MAX_BODY_SIZE_MB)
        .unwrap_or_else(|_| "100".to_string())
        .parse()
        .unwrap_or(100);

    let enable_streaming = env::var(env_vars::ENABLE_STREAMING)
        .unwrap_or_else(|_| "true".to_string())
        .parse()
        .unwrap_or(true);

    ProxyConfig {
        timeout: Duration::from_secs(timeout_secs),
        max_body_size: if max_body_mb == 0 { 0 } else { max_body_mb * 1024 * 1024 }, // Convert MB to bytes
        enable_streaming,
    }
}

/// Get list of allowed proxy IPs from environment
pub fn get_allowed_proxy_ips() -> Option<Vec<String>> {
    env::var(env_vars::ALLOWED_PROXY_IPS).ok().map(|ips| {
        ips.split(',').map(|ip| ip.trim().to_string()).collect()
    })
}

/// Get list of blocked IPs from environment
pub fn get_blocked_ips() -> Vec<String> {
    env::var(env_vars::BLOCKED_IPS)
        .unwrap_or_default()
        .split(',')
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
        .collect()
}

/// Get list of blocked URL patterns from environment
pub fn get_blocked_patterns() -> Vec<String> {
    env::var(env_vars::BLOCKED_PATTERNS)
        .unwrap_or_default()
        .split(',')
        .map(|pattern| pattern.trim().to_string())
        .filter(|pattern| !pattern.is_empty())
        .collect()
}

/// Get list of blocked HTTP methods from environment
pub fn get_blocked_methods() -> Vec<String> {
    env::var(env_vars::BLOCKED_METHODS)
        .unwrap_or_default()
        .split(',')
        .map(|method| method.trim().to_uppercase())
        .filter(|method| !method.is_empty())
        .collect()
}
