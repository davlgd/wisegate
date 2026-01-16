//! Server startup and information display.
//!
//! This module handles the startup banner and configuration display
//! for the WiseGate reverse proxy.

use crate::{args::Args, config, env_vars};
use std::env;
use tracing::{debug, info};

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
/// * `args` - The parsed command line arguments
///
/// # Example
///
/// ```no_run
/// use wisegate::args::Args;
/// use wisegate::server::print_startup_info;
/// use clap::Parser;
///
/// let args = Args::parse();
/// print_startup_info(&args);
/// ```
pub fn print_startup_info(args: &Args) {
    if args.quiet {
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
        listen_port = args.listen,
        forward_port = args.forward,
        bind_address = %args.bind,
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
    if args.verbose {
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
