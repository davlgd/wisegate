//! WiseGate binary entry point

#![forbid(unsafe_code)]

use clap::Parser;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

use wisegate::args::Args;
use wisegate::config::EnvVarConfig;
use wisegate::server::StartupConfig;
use wisegate::types::RateLimiter;
use wisegate::{config, request_handler, server};

/// Graceful shutdown timeout in seconds
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Initialize the tracing subscriber for structured logging
fn init_tracing(verbose: bool, quiet: bool, json_logs: bool) {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if quiet {
            EnvFilter::new("error")
        } else if verbose {
            EnvFilter::new("debug")
        } else {
            EnvFilter::new("info")
        }
    });

    if json_logs {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().with_target(false))
            .init();
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Validate arguments and get parsed bind IP
    let bind_ip = match args.validate() {
        Ok(ip) => ip,
        Err(err) => {
            eprintln!("Configuration error: {err}");
            std::process::exit(1);
        }
    };

    // Initialize tracing before any logging
    init_tracing(args.verbose, args.quiet, args.json_logs);

    let startup_config = StartupConfig {
        listen_port: args.listen,
        forward_port: args.forward,
        bind_address: args.bind.clone(),
        verbose: args.verbose,
        quiet: args.quiet,
    };
    server::print_startup_info(&startup_config);

    // Initialize rate limiter and config provider
    let rate_limiter = RateLimiter::new();
    let env_config = Arc::new(EnvVarConfig::new());

    // Create socket address (IP already validated)
    let bind_addr = SocketAddr::from((bind_ip, args.listen));
    let listener = match TcpListener::bind(bind_addr).await {
        Ok(listener) => listener,
        Err(err) => {
            error!(port = args.listen, error = %err, "Failed to bind to port");
            std::process::exit(1);
        }
    };

    // Create connection limiter semaphore (0 = unlimited)
    let max_connections = config::get_max_connections();
    let connection_semaphore = if max_connections > 0 {
        info!(
            max_connections = max_connections,
            "Connection limit configured"
        );
        Some(Arc::new(Semaphore::new(max_connections)))
    } else {
        warn!("No connection limit configured (MAX_CONNECTIONS=0)");
        None
    };

    info!(port = args.listen, bind = %args.bind, "WiseGate is running");

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
                        warn!(error = %err, "Failed to accept connection");
                        continue;
                    }
                };

                // Check connection limit before accepting
                let permit = if let Some(ref semaphore) = connection_semaphore {
                    match semaphore.clone().try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            warn!(client = %addr, max = max_connections, "Connection rejected: server at capacity");
                            drop(stream);
                            continue;
                        }
                    }
                } else {
                    None
                };

                debug!(client = %addr, "New connection");

                let io = TokioIo::new(stream);
                let limiter = rate_limiter.clone();
                let forward_host = args.bind.clone();
                let forward_port = args.forward;
                let connections = active_connections.clone();
                let config = env_config.clone();

                // Increment active connection count
                connections.fetch_add(1, Ordering::SeqCst);

                tokio::task::spawn(async move {
                    // Keep permit alive for the duration of the connection
                    let _permit = permit;

                    let service = service_fn(move |req| {
                        request_handler::handle_request(req, forward_host.clone(), forward_port, limiter.clone(), config.clone())
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        warn!(client = %addr, error = %err, "Connection error");
                    }

                    // Decrement active connection count
                    connections.fetch_sub(1, Ordering::SeqCst);
                });
            }

            // Wait for shutdown signal (Ctrl+C or SIGTERM)
            _ = shutdown_signal() => {
                info!("Shutdown signal received, stopping gracefully...");
                break;
            }
        }
    }

    // Graceful shutdown: wait for active connections to finish
    let active = active_connections.load(Ordering::SeqCst);
    if active > 0 {
        info!(
            active_connections = active,
            "Waiting for connections to finish..."
        );

        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(SHUTDOWN_TIMEOUT_SECS);

        while active_connections.load(Ordering::SeqCst) > 0 {
            if start.elapsed() >= timeout {
                let remaining = active_connections.load(Ordering::SeqCst);
                warn!(
                    remaining_connections = remaining,
                    "Timeout reached, forcing shutdown"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    info!("WiseGate stopped cleanly");
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
