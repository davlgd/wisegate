//! Server startup and information display.
//!
//! This module handles the startup banner and configuration display
//! for the WiseGate reverse proxy.

use crate::{config, env_vars};
use std::env;
use tracing::{debug, info};

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
/// * `config` - The startup configuration
///
/// # Example
///
/// ```no_run
/// use wisegate::server::{print_startup_info, StartupConfig};
///
/// let config = StartupConfig {
///     listen_port: 8080,
///     forward_port: 9000,
///     bind_address: "0.0.0.0".to_string(),
///     verbose: false,
///     quiet: false,
/// };
/// print_startup_info(&config);
/// ```
pub fn print_startup_info(startup_config: &StartupConfig) {
    if startup_config.quiet {
        return;
    }

    let rate_config = config::get_rate_limit_config();
    let proxy_config = config::get_proxy_config();
    let allowed_proxy_ips = config::get_allowed_proxy_ips();
    let blocked_ips = config::get_blocked_ips();
    let blocked_methods = config::get_blocked_methods();
    let blocked_patterns = config::get_blocked_patterns();

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
        blocked_ips = blocked_ips.len(),
        blocked_methods = blocked_methods.len(),
        blocked_patterns = blocked_patterns.len(),
        "Security configured"
    );

    // Show environment configuration in verbose mode
    if startup_config.verbose {
        print_env_config();
    }
}

/// Print environment variable configuration status (used in verbose mode)
fn print_env_config() {
    for &var_name in env_vars::all_env_vars() {
        match env::var(var_name) {
            Ok(value) => {
                // Mask sensitive values
                let display_value = if var_name.contains("IP") || var_name.contains("PROXY") {
                    "[CONFIGURED]".to_string()
                } else {
                    value
                };
                debug!(name = var_name, value = %display_value, "Environment variable");
            }
            Err(_) => {
                debug!(name = var_name, value = "[NOT SET]", "Environment variable");
            }
        }
    }
}
