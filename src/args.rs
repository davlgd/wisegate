use clap::Parser;

/// Command line arguments for WiseGate
#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"))]
#[command(about = env!("CARGO_PKG_DESCRIPTION"))]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
pub struct Args {
    /// Port to listen on for incoming requests
    #[arg(long, help = "Listen port for incoming connections")]
    pub listen: u16,

    /// Port to forward requests to
    #[arg(long, help = "Destination port for forwarded requests")]
    pub forward: u16,
}
