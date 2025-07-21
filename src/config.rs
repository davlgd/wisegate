use std::env;
use std::time::Duration;
use crate::types::RateLimitConfig;
use crate::env_vars;

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
