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

    // Validate arguments
    if let Err(err) = args.validate() {
        eprintln!("❌ Configuration error: {err}");
        std::process::exit(1);
    }

    server::print_startup_info(&args);

    // Initialize rate limiter
    let rate_limiter = Arc::new(Mutex::new(HashMap::new()));

    // Bind to address
    let bind_ip: std::net::IpAddr = args.bind.parse().expect("Invalid bind address");
    let bind_addr = SocketAddr::from((bind_ip, args.listen));
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("❌ Failed to bind to port {}: {}", args.listen, err);
            std::process::exit(1);
        }
    };

    println!("✅ WiseGate is running on port {}", args.listen);

    // Accept connections
    loop {
        let (stream, addr) = match listener.accept().await {
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

        tokio::task::spawn(async move {
            let service = service_fn(move |req| {
                request_handler::handle_request(req, forward_host.clone(), forward_port, limiter.clone())
            });

            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                if !quiet {
                    if verbose {
                        eprintln!("⚠️  Connection error from {addr}: {err}");
                    } else {
                        eprintln!("⚠️  Connection error: {err}");
                    }
                }
            }
        });
    }
}
