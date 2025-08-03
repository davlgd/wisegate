use clap::Parser;

/// Command line arguments for WiseGate
#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(
    long_about = "🧙‍ \"You shall not pass!\" - A wise guardian for your network gates\nAn efficient, secure reverse proxy with built-in rate limiting and IP filtering\n\nExample usage:\n  wisegate --listen 8080 --forward 9000\n  wisegate -l 8080 -f 9000 --verbose"
)]
#[command(
    after_help = "Environment variables:\n  CC_REVERSE_PROXY_IPS   Trusted proxy IPs (enables strict mode)\n  BLOCKED_IPS            Comma-separated blocked client IPs\n  BLOCKED_METHODS        HTTP methods to block (e.g., PUT,DELETE)\n  BLOCKED_PATTERNS       URL patterns to block (e.g., .php,.yaml)\n  RATE_LIMIT_REQUESTS    Max requests per window (default: 100)\n  RATE_LIMIT_WINDOW_SECS Rate limit window seconds (default: 60)\n\nFor more configuration options, see https://crates.io/crates/wisegate"
)]
pub struct Args {
    /// Port to listen on for incoming requests
    #[arg(
        long,
        short = 'l',
        help = "Listen port for incoming connections",
        value_name = "PORT"
    )]
    pub listen: u16,

    /// Port to forward requests to
    #[arg(
        long,
        short = 'f',
        help = "Destination port for forwarded requests",
        value_name = "PORT"
    )]
    pub forward: u16,

    /// Enable verbose output
    #[arg(
        long,
        short = 'v',
        help = "Show detailed configuration and startup information"
    )]
    pub verbose: bool,

    /// Enable quiet mode (minimal output)
    #[arg(
        long,
        short = 'q',
        help = "Suppress configuration output, show only essential messages",
        conflicts_with = "verbose"
    )]
    pub quiet: bool,
}

impl Args {
    /// Validate the parsed arguments
    pub fn validate(&self) -> Result<(), String> {
        if self.listen == self.forward {
            return Err("Listen and forward ports cannot be the same".to_string());
        }

        if self.listen == 0 || self.forward == 0 {
            return Err("Ports must be greater than 0".to_string());
        }

        Ok(())
    }
}
