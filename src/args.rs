//! Command line argument parsing for WiseGate.
//!
//! This module defines the CLI interface using [`clap`] for argument parsing.
//! It provides configuration for binding addresses, ports, and output verbosity.
//!
//! # Example
//!
//! ```no_run
//! use wisegate::args::Args;
//! use clap::Parser;
//!
//! let args = Args::parse();
//! if let Err(e) = args.validate() {
//!     eprintln!("Configuration error: {}", e);
//!     std::process::exit(1);
//! }
//! ```

use std::net::IpAddr;

use clap::Parser;

/// Command line arguments for WiseGate.
///
/// This struct defines all CLI options available for configuring the reverse proxy.
/// Arguments can be provided via command line flags or environment variables.
///
/// # Fields
///
/// * `bind` - Address to bind for listening and forwarding (default: "0.0.0.0")
/// * `listen` - Port to listen on for incoming requests
/// * `forward` - Port to forward requests to
/// * `verbose` - Enable detailed configuration output
/// * `quiet` - Suppress non-essential output (conflicts with verbose)
/// * `json_logs` - Output logs in JSON format for structured logging
///
/// # Example
///
/// ```no_run
/// use wisegate::args::Args;
/// use clap::Parser;
///
/// // Parse from command line
/// let args = Args::parse();
///
/// println!("Listening on {}:{}", args.bind, args.listen);
/// println!("Forwarding to {}:{}", args.bind, args.forward);
/// ```
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
    /// Address to bind to (for both listening and forwarding)
    #[arg(
        long,
        short = 'b',
        help = "Bind address for listening and forwarding",
        value_name = "ADDRESS",
        default_value = "0.0.0.0"
    )]
    pub bind: String,

    /// Port to listen on for incoming requests
    #[arg(
        long,
        short = 'l',
        help = "Listen port for incoming connections",
        value_name = "PORT",
        default_value = "8080"
    )]
    pub listen: u16,

    /// Port to forward requests to
    #[arg(
        long,
        short = 'f',
        help = "Destination port for forwarded requests",
        value_name = "PORT",
        default_value = "9000"
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

    /// Output logs in JSON format (for structured logging)
    #[arg(long, help = "Output logs in JSON format for structured logging")]
    pub json_logs: bool,
}

impl Args {
    /// Validates the parsed command line arguments and returns the parsed bind IP.
    ///
    /// Performs the following validations:
    /// - Listen and forward ports must be different
    /// - Both ports must be greater than 0
    /// - Bind address must be a valid IP address
    ///
    /// # Returns
    ///
    /// * `Ok(IpAddr)` - The validated and parsed bind IP address
    /// * `Err(String)` - A descriptive error message if validation fails
    ///
    /// # Example
    ///
    /// ```
    /// use wisegate::args::Args;
    /// use clap::Parser;
    ///
    /// // Simulating args with same listen and forward ports
    /// let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "8080"]).unwrap();
    /// assert!(args.validate().is_err());
    ///
    /// // Valid configuration
    /// let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "9000"]).unwrap();
    /// assert!(args.validate().is_ok());
    /// ```
    pub fn validate(&self) -> Result<IpAddr, String> {
        if self.listen == self.forward {
            return Err("Listen and forward ports cannot be the same".to_string());
        }

        if self.listen == 0 || self.forward == 0 {
            return Err("Ports must be greater than 0".to_string());
        }

        // Validate and parse bind address
        self.bind
            .parse::<IpAddr>()
            .map_err(|_| format!("Invalid bind address: '{}'", self.bind))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    // ===========================================
    // Args::validate() tests
    // ===========================================

    #[test]
    fn test_validate_valid_configuration() {
        let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "9000"]).unwrap();
        let result = args.validate();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "0.0.0.0");
    }

    #[test]
    fn test_validate_same_ports_error() {
        let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "8080"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Listen and forward ports cannot be the same"
        );
    }

    #[test]
    fn test_validate_listen_port_zero_error() {
        let args = Args::try_parse_from(["wisegate", "-l", "0", "-f", "9000"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Ports must be greater than 0");
    }

    #[test]
    fn test_validate_forward_port_zero_error() {
        let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "0"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Ports must be greater than 0");
    }

    #[test]
    fn test_validate_both_ports_zero_error() {
        let args = Args::try_parse_from(["wisegate", "-l", "0", "-f", "0"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        // Same ports check happens first
        assert_eq!(
            result.unwrap_err(),
            "Listen and forward ports cannot be the same"
        );
    }

    #[test]
    fn test_validate_invalid_bind_address() {
        let args = Args::try_parse_from(["wisegate", "-l", "8080", "-f", "9000", "-b", "invalid"])
            .unwrap();
        let result = args.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid bind address"));
    }

    #[test]
    fn test_validate_valid_ipv4_bind() {
        let args =
            Args::try_parse_from(["wisegate", "-l", "8080", "-f", "9000", "-b", "127.0.0.1"])
                .unwrap();
        let result = args.validate();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "127.0.0.1");
    }

    #[test]
    fn test_validate_valid_ipv6_bind() {
        let args =
            Args::try_parse_from(["wisegate", "-l", "8080", "-f", "9000", "-b", "::1"]).unwrap();
        let result = args.validate();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), "::1");
    }

    // ===========================================
    // Default values tests
    // ===========================================

    #[test]
    fn test_default_values() {
        let args = Args::try_parse_from(["wisegate"]).unwrap();
        assert_eq!(args.bind, "0.0.0.0");
        assert_eq!(args.listen, 8080);
        assert_eq!(args.forward, 9000);
        assert!(!args.verbose);
        assert!(!args.quiet);
        assert!(!args.json_logs);
    }

    #[test]
    fn test_verbose_flag() {
        let args = Args::try_parse_from(["wisegate", "--verbose"]).unwrap();
        assert!(args.verbose);
        assert!(!args.quiet);
    }

    #[test]
    fn test_quiet_flag() {
        let args = Args::try_parse_from(["wisegate", "--quiet"]).unwrap();
        assert!(!args.verbose);
        assert!(args.quiet);
    }

    #[test]
    fn test_json_logs_flag() {
        let args = Args::try_parse_from(["wisegate", "--json-logs"]).unwrap();
        assert!(args.json_logs);
    }

    #[test]
    fn test_verbose_and_quiet_conflict() {
        let result = Args::try_parse_from(["wisegate", "--verbose", "--quiet"]);
        assert!(result.is_err());
    }

    // ===========================================
    // Short flags tests
    // ===========================================

    #[test]
    fn test_short_flags() {
        let args = Args::try_parse_from([
            "wisegate",
            "-l",
            "3000",
            "-f",
            "4000",
            "-b",
            "127.0.0.1",
            "-v",
        ])
        .unwrap();
        assert_eq!(args.listen, 3000);
        assert_eq!(args.forward, 4000);
        assert_eq!(args.bind, "127.0.0.1");
        assert!(args.verbose);
    }

    // ===========================================
    // Edge cases tests
    // ===========================================

    #[test]
    fn test_max_port_value() {
        let args = Args::try_parse_from(["wisegate", "-l", "65535", "-f", "65534"]).unwrap();
        let result = args.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_port_1() {
        let args = Args::try_parse_from(["wisegate", "-l", "1", "-f", "2"]).unwrap();
        let result = args.validate();
        assert!(result.is_ok());
    }
}
