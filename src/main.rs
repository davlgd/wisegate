//! WiseGate - A wise guardian for your network gates
//!
//! An efficient, secure reverse proxy with built-in rate limiting and IP filtering.

#![forbid(unsafe_code)]

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

mod args;
mod config;
mod env_vars;
mod ip_filter;
mod rate_limiter;
mod request_handler;
mod server;
mod types;

use args::Args;

/// Graceful shutdown timeout in seconds
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Validate arguments
    if let Err(err) = args.validate() {
        eprintln!("❌ Configuration error: {err}");
        std::process::exit(1);
    }

    server::print_startup_info(&args);

    // Initialize rate limiter
    let rate_limiter = Arc::new(Mutex::new(HashMap::new()));

    // Bind to address (already validated in args.validate())
    let bind_ip: std::net::IpAddr = match args.bind.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("❌ Invalid bind address: {}", args.bind);
            std::process::exit(1);
        }
    };
    let bind_addr = SocketAddr::from((bind_ip, args.listen));
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("❌ Failed to bind to port {}: {}", args.listen, err);
            std::process::exit(1);
        }
    };

    println!("✅ WiseGate is running on port {}", args.listen);

    // Track active connections for graceful shutdown
    let active_connections = Arc::new(AtomicUsize::new(0));

    // Accept connections until shutdown signal
    loop {
        tokio::select! {
            // Wait for new connection
            accept_result = listener.accept() => {
                let (stream, addr) = match accept_result {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!("⚠️  Failed to accept connection: {err}");
                        continue;
                    }
                };

                if args.verbose && !args.quiet {
                    println!("📡 New connection from {addr}");
                }

                let io = TokioIo::new(stream);
                let limiter = rate_limiter.clone();
                let forward_host = args.bind.clone();
                let forward_port = args.forward;
                let verbose = args.verbose;
                let quiet = args.quiet;
                let connections = active_connections.clone();

                // Increment active connection count
                connections.fetch_add(1, Ordering::SeqCst);

                tokio::task::spawn(async move {
                    let service = service_fn(move |req| {
                        request_handler::handle_request(req, forward_host.clone(), forward_port, limiter.clone())
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await
                        && !quiet
                    {
                        if verbose {
                            eprintln!("⚠️  Connection error from {addr}: {err}");
                        } else {
                            eprintln!("⚠️  Connection error: {err}");
                        }
                    }

                    // Decrement active connection count
                    connections.fetch_sub(1, Ordering::SeqCst);
                });
            }

            // Wait for shutdown signal (Ctrl+C or SIGTERM)
            _ = shutdown_signal() => {
                println!("\n🛑 Shutdown signal received, stopping gracefully...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active connections to finish
    let active = active_connections.load(Ordering::SeqCst);
    if active > 0 {
        println!("⏳ Waiting for {active} active connection(s) to finish...");

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(SHUTDOWN_TIMEOUT_SECS);

        while active_connections.load(Ordering::SeqCst) > 0 {
            if start.elapsed() >= timeout {
                let remaining = active_connections.load(Ordering::SeqCst);
                eprintln!("⚠️  Timeout reached, forcing shutdown with {remaining} connection(s) still active");
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    println!("✅ WiseGate stopped cleanly.");
}

/// Wait for shutdown signal (SIGINT or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
