pub const ALLOWED_PROXY_IPS: &str = "CC_REVERSE_PROXY_IPS";
pub const TRUSTED_PROXY_IPS_VAR: &str = "TRUSTED_PROXY_IPS_VAR";

/// Try to get proxy IPs from CC_REVERSE_PROXY_IPS first, then from user-defined alternative
pub fn get_proxy_ips_env() -> Option<String> {
    use std::env;
    
    // Try primary variable first
    if let Ok(ips) = env::var(ALLOWED_PROXY_IPS) {
        if !ips.trim().is_empty() {
            return Some(ips);
        }
    }
    
    // Try user-defined alternative variable if set
    if let Ok(alt_var_name) = env::var(TRUSTED_PROXY_IPS_VAR) {
        if let Ok(ips) = env::var(&alt_var_name) {
            if !ips.trim().is_empty() {
                return Some(ips);
            }
        }
    }
    
    None
}
pub const BLOCKED_IPS: &str = "BLOCKED_IPS";
pub const BLOCKED_METHODS: &str = "BLOCKED_METHODS";
pub const BLOCKED_PATTERNS: &str = "BLOCKED_PATTERNS";
pub const ENABLE_STREAMING: &str = "ENABLE_STREAMING";
pub const MAX_BODY_SIZE_MB: &str = "MAX_BODY_SIZE_MB";
pub const PROXY_TIMEOUT_SECS: &str = "PROXY_TIMEOUT_SECS";
pub const RATE_LIMIT_REQUESTS: &str = "RATE_LIMIT_REQUESTS";
pub const RATE_LIMIT_WINDOW_SECS: &str = "RATE_LIMIT_WINDOW_SECS";
