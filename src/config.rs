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
/// Uses the simplified logic from env_vars to try primary then alternative variable
pub fn get_allowed_proxy_ips() -> Option<Vec<String>> {
    get_allowed_proxy_ips_internal(|key| std::env::var(key))
}

/// Internal function that accepts an environment variable lookup function
/// This allows for easier testing without modifying global environment
fn get_allowed_proxy_ips_internal<F>(env_var: F) -> Option<Vec<String>>
where
    F: Fn(&str) -> Result<String, std::env::VarError>,
{
    // Try primary variable first
    if let Ok(ips) = env_var(env_vars::ALLOWED_PROXY_IPS) {
        if !ips.trim().is_empty() {
            return Some(ips.split(',').map(|ip| ip.trim().to_string()).collect());
        }
    }
    
    // Try user-defined alternative variable if set
    if let Ok(alt_var_name) = env_var(env_vars::TRUSTED_PROXY_IPS_VAR) {
        if let Ok(ips) = env_var(&alt_var_name) {
            if !ips.trim().is_empty() {
                return Some(ips.split(',').map(|ip| ip.trim().to_string()).collect());
            }
        }
    }
    
    None
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

#[cfg(test)]  
mod tests {
    use super::*;
    use std::collections::HashMap;

    // Helper function to create a mock environment function for testing
    fn create_mock_env(vars: HashMap<&str, &str>) -> impl Fn(&str) -> Result<String, std::env::VarError> {
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
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], "192.168.1.1");
        assert_eq!(ips[1], "10.0.0.1");
    }

    #[test]
    fn test_get_allowed_proxy_ips_with_alternative_var() {
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "MY_CUSTOM_PROXY_IPS");
        env_vars.insert("MY_CUSTOM_PROXY_IPS", "172.16.0.1,203.0.113.1");
        let env_fn = create_mock_env(env_vars);
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
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
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], "192.168.1.1"); // Should use CC_REVERSE_PROXY_IPS value
    }

    #[test]
    fn test_get_allowed_proxy_ips_fallback_to_alternative() {
        // Don't set CC_REVERSE_PROXY_IPS, only alternative
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::TRUSTED_PROXY_IPS_VAR, "COMPANY_PROXY_LIST");
        env_vars.insert("COMPANY_PROXY_LIST", "10.1.1.1,10.1.1.2,10.1.1.3");
        let env_fn = create_mock_env(env_vars);
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
        assert!(result.is_some());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "10.1.1.1");
        assert_eq!(ips[1], "10.1.1.2");
        assert_eq!(ips[2], "10.1.1.3");
    }

    #[test]
    fn test_get_allowed_proxy_ips_none_when_no_vars() {
        // No relevant env vars set
        let env_vars = HashMap::new();
        let env_fn = create_mock_env(env_vars);
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
        assert!(result.is_none());
    }

    #[test]
    fn test_get_allowed_proxy_ips_handles_whitespace() {
        // Test with whitespace around IPs
        let mut env_vars = HashMap::new();
        env_vars.insert(env_vars::ALLOWED_PROXY_IPS, " 192.168.1.1 , 10.0.0.1 ");
        let env_fn = create_mock_env(env_vars);
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
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
        
        let result = get_allowed_proxy_ips_internal(env_fn);
        
        assert!(result.is_none());
    }
}
