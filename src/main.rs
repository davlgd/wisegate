use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

mod args;
mod config;
mod env_vars;
mod ip_filter;
mod rate_limiter;
mod request_handler;
mod server;
mod types;

use args::Args;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Validate required configuration
    if config::get_allowed_proxy_ips().is_none() {
        eprintln!("❌ Error: {} environment variable is required", env_vars::ALLOWED_PROXY_IPS);
        eprintln!("   Example: export {}=\"192.168.1.1,10.0.0.1\"", env_vars::ALLOWED_PROXY_IPS);
        std::process::exit(1);
    }

    server::print_startup_info(&args);

    // Initialize rate limiter
    let rate_limiter = Arc::new(Mutex::new(HashMap::new()));

    // Bind to address
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], args.listen));
    let listener = TcpListener::bind(bind_addr).await.unwrap();

    println!("✅ WiseGate is running on port {}", args.listen);

    // Accept connections
    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);

        let limiter = rate_limiter.clone();
        let forward_port = args.forward;

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                request_handler::handle_request(req, forward_port, limiter.clone())
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Error serving connection: {err:?}");
            }
        });
    }
}
