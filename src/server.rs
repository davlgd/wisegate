use crate::{args::Args, config, env_vars};
use std::env;

/// Print startup banner with configuration
pub fn print_startup_info(args: &Args) {
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
    println!("   Max Body Size:  {} MB",
             if proxy_config.max_body_size == 0 { "unlimited".to_string() }
             else { (proxy_config.max_body_size / 1024 / 1024).to_string() });
    println!("   Streaming:      {}", if proxy_config.enable_streaming { "enabled" } else { "disabled" });

    let blocked_count = config::get_blocked_ips().len();
    if blocked_count > 0 {
        println!("🚫 IP Filtering:");
        println!("   Blocked IPs:    {blocked_count} configured");
    }

    // Show environment configuration in verbose mode
    if args.verbose {
        print_env_config();
    }

    println!();
    println!("🚀 Server starting...");
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
