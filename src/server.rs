//! Server startup and information display.
//!
//! This module handles the startup banner and configuration display
//! for the WiseGate reverse proxy.

use crate::env_vars;
use std::env;
use tracing::{debug, info, warn};
use wisegate_core::ConfigProvider;

/// Configuration for startup display.
///
/// Decouples the startup info display from CLI argument parsing,
/// allowing the server module to be used independently.
#[derive(Clone, Debug)]
pub struct StartupConfig {
    /// Port to listen on
    pub listen_port: u16,
    /// Port to forward to
    pub forward_port: u16,
    /// Bind address
    pub bind_address: String,
    /// Whether to show verbose output
    pub verbose: bool,
    /// Whether to suppress output
    pub quiet: bool,
}

/// Prints the startup banner with current configuration.
///
/// Displays information about the server's configuration including:
/// - Version and binding information
/// - Rate limiting settings
/// - Proxy configuration (timeout, max body size)
/// - Security settings (IP filtering, blocked methods/patterns)
///
/// In verbose mode, also displays all environment variable configurations.
///
/// # Arguments
///
/// * `startup_config` - The startup display configuration
/// * `config` - Configuration provider for all settings
///
/// # Example
///
/// ```no_run
/// use wisegate::server::{print_startup_info, StartupConfig};
/// use wisegate::config::EnvVarConfig;
///
/// let startup = StartupConfig {
///     listen_port: 8080,
///     forward_port: 9000,
///     bind_address: "0.0.0.0".to_string(),
///     verbose: false,
///     quiet: false,
/// };
/// let config = EnvVarConfig::new();
/// print_startup_info(&startup, &config);
/// ```
pub fn print_startup_info(startup_config: &StartupConfig, config: &impl ConfigProvider) {
    if startup_config.quiet {
        return;
    }

    let rate_config = config.rate_limit_config();
    let proxy_config = config.proxy_config();
    let allowed_proxy_ips = config.allowed_proxy_ips();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        listen_port = startup_config.listen_port,
        forward_port = startup_config.forward_port,
        bind_address = %startup_config.bind_address,
        "WiseGate starting"
    );

    info!(
        max_requests = rate_config.max_requests,
        window_secs = rate_config.window_duration.as_secs(),
        "Rate limiting configured"
    );

    info!(
        timeout_secs = proxy_config.timeout.as_secs(),
        max_body_mb = proxy_config.max_body_size_mb(),
        "Proxy configured"
    );

    let mode = if allowed_proxy_ips.is_some() {
        "strict"
    } else {
        "permissive"
    };
    let trusted_proxies = allowed_proxy_ips.map(|ips| ips.len()).unwrap_or(0);

    info!(
        mode = mode,
        trusted_proxies = trusted_proxies,
        blocked_ips = config.blocked_ips().len(),
        blocked_methods = config.blocked_methods().len(),
        blocked_patterns = config.blocked_patterns().len(),
        "Security configured"
    );

    // Display authentication status
    let basic_auth_enabled = config.is_basic_auth_enabled();
    let bearer_auth_enabled = config.is_bearer_auth_enabled();

    if basic_auth_enabled || bearer_auth_enabled {
        info!(
            basic_auth = basic_auth_enabled,
            basic_auth_users = config.auth_credentials().len(),
            bearer_token = bearer_auth_enabled,
            realm = config.auth_realm(),
            "Authentication configured"
        );
    } else {
        debug!("Authentication disabled (no credentials or bearer token configured)");
    }

    warn_on_suspicious_config(startup_config, config);

    // Show environment configuration in verbose mode
    if startup_config.verbose {
        print_env_config();
    }
}

/// Warns at startup when the configuration looks like a common misconfiguration.
///
/// These are surfaced even in non-verbose mode (but not in quiet mode) because
/// they often produce silent "all requests are 400" symptoms that beginners
/// struggle to diagnose.
fn warn_on_suspicious_config(startup_config: &StartupConfig, config: &impl ConfigProvider) {
    if let Some(proxy_ips) = config.allowed_proxy_ips() {
        // 0.0.0.0 is a bind-only sentinel — it never appears in a Forwarded `by=` field.
        if proxy_ips.iter().any(|ip| ip == "0.0.0.0") {
            warn!(
                "CC_REVERSE_PROXY_IPS contains 0.0.0.0 — this is the bind sentinel, \
                 not a real proxy IP. Strict mode will reject every request."
            );
        }
        // Listening on a public interface with strict mode but no auth is OK,
        // but listening on a public interface with NO proxy IPs and NO auth
        // exposes the upstream to anyone who can reach the port.
    } else if startup_config.bind_address == "0.0.0.0"
        && !config.is_auth_enabled()
        && config.blocked_ips().is_empty()
    {
        warn!(
            "Listening on 0.0.0.0 in permissive mode with no authentication and no IP \
             blocklist — this proxy is openly reachable. Set CC_REVERSE_PROXY_IPS, \
             CC_HTTP_BASIC_AUTH, or BLOCKED_IPS, or bind to 127.0.0.1 for local testing."
        );
    }
}

/// Print environment variable configuration status (used in verbose mode)
fn print_env_config() {
    for &var_name in env_vars::all_env_vars() {
        match env::var(var_name) {
            Ok(value) => {
                let display_value = mask_sensitive_value(var_name, &value);
                debug!(name = var_name, value = %display_value, "Environment variable");
            }
            Err(_) => {
                debug!(name = var_name, value = "[NOT SET]", "Environment variable");
            }
        }
    }
}

/// Masks sensitive values in environment variable display.
///
/// Returns "[CONFIGURED]" for variables containing sensitive keywords
/// like "IP", "PROXY", "AUTH", "TOKEN", "BEARER", or "PASSWORD".
fn mask_sensitive_value(var_name: &str, value: &str) -> String {
    let upper = var_name.to_uppercase();
    if upper.contains("IP")
        || upper.contains("PROXY")
        || upper.contains("AUTH")
        || upper.contains("TOKEN")
        || upper.contains("BEARER")
        || upper.contains("PASSWORD")
        || upper.contains("SECRET")
    {
        "[CONFIGURED]".to_string()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===========================================
    // mask_sensitive_value tests
    // ===========================================

    #[test]
    fn test_mask_sensitive_value_with_ip() {
        assert_eq!(
            mask_sensitive_value("BLOCKED_IPS", "192.168.1.1"),
            "[CONFIGURED]"
        );
        assert_eq!(
            mask_sensitive_value("TRUSTED_PROXY_IPS", "10.0.0.1"),
            "[CONFIGURED]"
        );
        assert_eq!(
            mask_sensitive_value("CC_REVERSE_PROXY_IPS", "172.16.0.1"),
            "[CONFIGURED]"
        );
    }

    #[test]
    fn test_mask_sensitive_value_with_proxy() {
        assert_eq!(
            mask_sensitive_value("PROXY_ALLOWLIST", "10.0.0.1"),
            "[CONFIGURED]"
        );
        assert_eq!(
            mask_sensitive_value("TRUSTED_PROXY_IPS_VAR", "CUSTOM_VAR"),
            "[CONFIGURED]"
        );
    }

    #[test]
    fn test_mask_sensitive_value_with_auth() {
        assert_eq!(
            mask_sensitive_value("CC_HTTP_BASIC_AUTH", "admin:secret"),
            "[CONFIGURED]"
        );
        assert_eq!(
            mask_sensitive_value("CC_HTTP_BASIC_AUTH_REALM", "MyRealm"),
            "[CONFIGURED]"
        );
    }

    #[test]
    fn test_mask_sensitive_value_with_token() {
        assert_eq!(
            mask_sensitive_value("CC_BEARER_TOKEN", "my-secret-token"),
            "[CONFIGURED]"
        );
    }

    #[test]
    fn test_mask_sensitive_value_non_sensitive() {
        assert_eq!(mask_sensitive_value("RATE_LIMIT_REQUESTS", "100"), "100");
        assert_eq!(mask_sensitive_value("MAX_BODY_SIZE_MB", "50"), "50");
        assert_eq!(
            mask_sensitive_value("BLOCKED_METHODS", "TRACE,CONNECT"),
            "TRACE,CONNECT"
        );
        assert_eq!(
            mask_sensitive_value("BLOCKED_PATTERNS", ".php,.env"),
            ".php,.env"
        );
    }
}
