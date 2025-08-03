use crate::{args::Args, config, env_vars};
use std::env;

/// Print startup banner with configuration
pub fn print_startup_info(args: &Args) {
    if args.quiet {
        // Quiet mode: only essential information
        println!("🚀 WiseGate v{} starting on port {}", env!("CARGO_PKG_VERSION"), args.listen);
        return;
    }

    // Normal/verbose mode: full configuration display
    println!("🛡️  {} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    println!("   {}", env!("CARGO_PKG_DESCRIPTION"));
    println!();
    println!("📡 Network Configuration:");
    println!("   Listen Port:    {}", args.listen);
    println!("   Forward Port:   {}", args.forward);
    println!();

    let rate_config = config::get_rate_limit_config();
    println!("⚡ Rate Limiting:");
    println!("   Max Requests:   {} per {} seconds",
             rate_config.max_requests,
             rate_config.window_duration.as_secs());

    let proxy_config = config::get_proxy_config();
    println!("🔧 Proxy Configuration:");
    println!("   Timeout:        {} seconds", proxy_config.timeout.as_secs());
    println!("   Max Body Size:  {} MB", proxy_config.max_body_size_mb());
    println!("   Streaming:      {}", if proxy_config.enable_streaming { "enabled" } else { "disabled" });

    // Show security configuration
    print_security_config();

    // Show environment configuration in verbose mode
    if args.verbose {
        print_env_config();
    }

    println!();
    println!("🚀 Server starting...");
}

/// Print security configuration summary
fn print_security_config() {
    let allowed_proxy_ips = config::get_allowed_proxy_ips();
    let blocked_ips = config::get_blocked_ips();
    let blocked_methods = config::get_blocked_methods();
    let blocked_patterns = config::get_blocked_patterns();

    println!("🔒 Security Configuration:");

    // Proxy mode
    match allowed_proxy_ips {
        Some(ref ips) => println!("   Mode:           Strict (trusted proxies: {})", ips.len()),
        None => println!("   Mode:           Permissive (no proxy validation)"),
    }

    // IP filtering
    if !blocked_ips.is_empty() {
        println!("   Blocked IPs:    {} configured", blocked_ips.len());
    }

    // Method filtering
    if !blocked_methods.is_empty() {
        println!("   Blocked Methods: {}", blocked_methods.join(", "));
    }

    // Pattern filtering
    if !blocked_patterns.is_empty() {
        println!("   Blocked Patterns: {} configured", blocked_patterns.len());
    }

    // If no filtering is configured
    if blocked_ips.is_empty() && blocked_methods.is_empty() && blocked_patterns.is_empty() {
        println!("   Filtering:      None configured");
    }
}

/// Print environment variable configuration status (used in verbose mode)
fn print_env_config() {
    println!();
    println!("🔧 Environment Variables:");

    for &var_name in env_vars::all_env_vars() {
        match env::var(var_name) {
            Ok(value) => {
                // Mask sensitive values
                let display_value = if var_name.contains("IP") || var_name.contains("PROXY") {
                    "[CONFIGURED]".to_string()
                } else {
                    value
                };
                println!("   {:<25} = {}", var_name, display_value);
            }
            Err(_) => {
                println!("   {:<25} = [NOT SET]", var_name);
            }
        }
    }
}
