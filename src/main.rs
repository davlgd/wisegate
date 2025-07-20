use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full};
use std::collections::HashMap;
use std::convert::Infallible;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use clap::Parser;
use tokio::net::TcpListener;

/// Command line arguments for Clever GateKeeper
#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
struct Args {
    /// Port to listen on for incoming requests
    #[arg(long, help = "Listen port for incoming connections")]
    listen: u16,

    /// Port to forward requests to
    #[arg(long, help = "Destination port for forwarded requests")]
    forward: u16,
}

/// Configuration for rate limiting per IP address
#[derive(Clone)]
struct RateLimitConfig {
    max_requests: u32,
    window_duration: Duration,
}

/// Rate limiter state: tracks request counts per IP with timestamps
type RateLimiter = Arc<Mutex<HashMap<String, (Instant, u32)>>>;

/// Environment variable names for configuration
mod env_vars {
    pub const ALLOWED_PROXY_IPS: &str = "CC_REVERSE_PROXY_IPS";
    pub const BLOCKED_IPS: &str = "BLOCKED_IPS";
    pub const RATE_LIMIT_REQUESTS: &str = "RATE_LIMIT_REQUESTS";
    pub const RATE_LIMIT_WINDOW_SECS: &str = "RATE_LIMIT_WINDOW_SECS";
}

/// Configuration management module
mod config {
    use super::*;

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
}

/// IP validation and blocking module
mod ip_filter {
    use super::*;

    /// Check if an IP address is in the blocked list
    pub fn is_ip_blocked(ip: &str) -> bool {
        let blocked_ips = config::get_blocked_ips();
        blocked_ips.iter().any(|blocked_ip| blocked_ip == ip)
    }

    /// Extract real client IP from load balancer headers
    ///
    /// This function implements the security model:
    /// 1. Requires both x-forwarded-for and forwarded headers
    /// 2. Validates that the proxy IP (from 'by=' field) is in allowlist
    /// 3. Extracts the real client IP (last valid IP in x-forwarded-for chain)
    pub fn extract_and_validate_real_ip(headers: &hyper::HeaderMap) -> Option<String> {
        // 1. x-forwarded-for header is mandatory
        let xff = headers.get("x-forwarded-for")?.to_str().ok()?;

        // 2. forwarded header is mandatory for proxy validation
        let forwarded = headers.get("forwarded")?.to_str().ok()?;

        // 3. Extract proxy IP from 'by=' field in forwarded header
        let proxy_ip = extract_proxy_ip_from_forwarded(forwarded)?;

        // 4. Validate proxy IP is in allowlist
        if !is_proxy_ip_allowed(&proxy_ip) {
            return None;
        }

        // 5. Extract real client IP (last valid IP in forwarded chain)
        extract_client_ip_from_xff(xff)
    }

    /// Extract proxy IP from forwarded header 'by=' field
    fn extract_proxy_ip_from_forwarded(forwarded: &str) -> Option<String> {
        forwarded
            .split(';')
            .find_map(|part| part.trim().strip_prefix("by="))
            .map(|ip| ip.trim().to_string())
    }

    /// Check if proxy IP is in the allowed list
    fn is_proxy_ip_allowed(proxy_ip: &str) -> bool {
        config::get_allowed_proxy_ips()
            .map(|allowed_ips| allowed_ips.iter().any(|ip| ip == proxy_ip))
            .unwrap_or(false)
    }

    /// Extract client IP from x-forwarded-for header (last valid IP)
    fn extract_client_ip_from_xff(xff: &str) -> Option<String> {
        xff.split(',')
            .map(|ip| ip.trim())
            .filter(|ip| is_valid_ip_format(ip))
            .last()
            .map(|ip| ip.to_string())
    }

    /// Basic IP format validation (contains . for IPv4 or : for IPv6)
    fn is_valid_ip_format(ip: &str) -> bool {
        ip.contains('.') || ip.contains(':')
    }
}

/// Rate limiting module
mod rate_limiter {
    use super::*;

    /// Check if a request from the given IP should be rate limited
    ///
    /// Uses a sliding window approach:
    /// - If window has expired, reset counter
    /// - If under limit, increment counter and allow
    /// - If over limit, deny request
    pub fn check_rate_limit(limiter: &RateLimiter, ip: &str) -> bool {
        let config = config::get_rate_limit_config();
        let mut rate_map = limiter.lock().unwrap();
        let now = Instant::now();

        match rate_map.get_mut(ip) {
            Some((last_request_time, request_count)) => {
                // Check if we're in a new time window
                if now.duration_since(*last_request_time) >= config.window_duration {
                    // Reset window
                    *last_request_time = now;
                    *request_count = 1;
                    true
                } else if *request_count < config.max_requests {
                    // Within limit, increment counter
                    *request_count += 1;
                    true
                } else {
                    // Rate limit exceeded
                    false
                }
            }
            None => {
                // First request from this IP
                rate_map.insert(ip.to_string(), (now, 1));
                true
            }
        }
    }
}

/// HTTP request handler
async fn handle_request(
    mut req: Request<Incoming>,
    forward_port: u16,
    limiter: RateLimiter,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {

    // Step 1: Extract and validate real client IP
    let real_client_ip = match ip_filter::extract_and_validate_real_ip(req.headers()) {
        Some(ip) => ip,
        None => {
            return Ok(create_error_response(
                StatusCode::FORBIDDEN,
                "Invalid request: missing or invalid proxy headers"
            ));
        }
    };

    // Step 2: Check if IP is blocked
    if ip_filter::is_ip_blocked(&real_client_ip) {
        return Ok(create_error_response(
            StatusCode::FORBIDDEN,
            "IP address is blocked"
        ));
    }

    // Step 3: Apply rate limiting
    if !rate_limiter::check_rate_limit(&limiter, &real_client_ip) {
        return Ok(create_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "Rate limit exceeded"
        ));
    }

    // Step 4: Add X-Real-IP header for upstream service
    req.headers_mut().insert(
        "x-real-ip",
        real_client_ip.parse().unwrap()
    );

    // Step 5: Forward request to destination service
    forward_request(req, forward_port).await
}

/// Forward the request to the destination service
async fn forward_request(
    req: Request<Incoming>,
    port: u16,
) -> Result<Response<Full<bytes::Bytes>>, Infallible> {
    // Collect the body
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(bytes) => bytes.to_bytes(),
        Err(_) => {
            return Ok(create_error_response(
                StatusCode::BAD_REQUEST,
                "Failed to read request body"
            ));
        }
    };

    // Construct destination URI
    let destination_uri = format!(
        "http://localhost:{}{}",
        port,
        parts.uri.path_and_query().map_or("", |pq| pq.as_str())
    );

    // Create reqwest client
    let client = reqwest::Client::new();

    // Build the request
    let mut req_builder = match parts.method.as_str() {
        "GET" => client.get(&destination_uri),
        "POST" => client.post(&destination_uri),
        "PUT" => client.put(&destination_uri),
        "DELETE" => client.delete(&destination_uri),
        "HEAD" => client.head(&destination_uri),
        "PATCH" => client.patch(&destination_uri),
        _ => return Ok(create_error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Method not supported"
        )),
    };

    // Add headers (excluding host and content-length)
    for (name, value) in parts.headers.iter() {
        if name != "host" && name != "content-length" {
            if let Ok(header_value) = value.to_str() {
                req_builder = req_builder.header(name.as_str(), header_value);
            }
        }
    }

    // Add body if not empty
    if !body_bytes.is_empty() {
        req_builder = req_builder.body(body_bytes.to_vec());
    }

    // Send request
    match req_builder.send().await {
        Ok(response) => {
            let status = response.status();
            let headers = response.headers().clone();

            match response.bytes().await {
                Ok(body_bytes) => {
                    let mut hyper_response = Response::builder()
                        .status(status.as_u16())
                        .body(Full::new(bytes::Bytes::from(body_bytes)))
                        .unwrap();

                    // Copy headers
                    for (name, value) in headers.iter() {
                        if let (Ok(header_name), Ok(header_value)) = (
                            hyper::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                            hyper::header::HeaderValue::from_bytes(value.as_bytes())
                        ) {
                            hyper_response.headers_mut().insert(header_name, header_value);
                        }
                    }

                    Ok(hyper_response)
                }
                Err(_) => Ok(create_error_response(
                    StatusCode::BAD_GATEWAY,
                    "Failed to read response body"
                ))
            }
        }
        Err(_) => Ok(create_error_response(
            StatusCode::BAD_GATEWAY,
            "Destination service unavailable"
        ))
    }
}

/// Create standardized error responses
fn create_error_response(status: StatusCode, message: &str) -> Response<Full<bytes::Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Full::new(bytes::Bytes::from(message.to_string())))
        .unwrap()
}

/// Print startup banner with configuration
fn print_startup_info(args: &Args) {
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

    let blocked_count = config::get_blocked_ips().len();
    if blocked_count > 0 {
        println!("🚫 IP Filtering:");
        println!("   Blocked IPs:    {} configured", blocked_count);
    }

    println!();
    println!("🚀 Server starting...");
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Validate required configuration
    if config::get_allowed_proxy_ips().is_none() {
        eprintln!("❌ Error: {} environment variable is required", env_vars::ALLOWED_PROXY_IPS);
        eprintln!("   Example: export {}=\"192.168.1.1,10.0.0.1\"", env_vars::ALLOWED_PROXY_IPS);
        std::process::exit(1);
    }

    print_startup_info(&args);

    // Initialize rate limiter
    let rate_limiter = Arc::new(Mutex::new(HashMap::new()));

    // Bind to address
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], args.listen));
    let listener = TcpListener::bind(bind_addr).await.unwrap();

    println!("✅ Clever GateKeeper is running on port {}", args.listen);

    // Accept connections
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);

        let limiter = rate_limiter.clone();
        let forward_port = args.forward;

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                handle_request(req, forward_port, limiter.clone())
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

