//! kraken-redirector — deployment tooling for Kraken C2 redirector infrastructure.
//!
//! Generates nginx configs, mTLS certificates, and docker-compose manifests
//! that operators deploy in front of the Kraken teamserver to provide traffic
//! filtering and deniability.
//!
//! # Subcommands
//! ```text
//! kraken-redirector nginx-config   --profile http  --backend-host 10.0.0.1 --backend-port 8443
//! kraken-redirector gen-certs      --ca-path ./ca  --output ./redirector-certs
//! kraken-redirector docker-compose --output ./deploy
//! ```

use anyhow::Result;
use clap::{Parser, Subcommand};

mod certs;
mod cloudflare;
mod nginx;

/// Kraken redirector deployment toolkit.
///
/// Generates nginx reverse-proxy configs, mTLS certificate bundles, and
/// docker-compose manifests for standing up C2 redirectors.
#[derive(Debug, Parser)]
#[command(name = "kraken-redirector", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Generate an nginx reverse-proxy config for a Kraken redirector.
    ///
    /// Matched URIs are proxied to the backend teamserver; all other traffic
    /// receives a plausible decoy response.
    NginxConfig(nginx::NginxConfigArgs),

    /// Generate mTLS certificate bundles (CA + server + client leaf certs).
    ///
    /// Produces a CA keypair and signed leaf certificates suitable for
    /// mutual-TLS between the redirector and teamserver, and between the
    /// operator client and the operator gRPC channel.
    GenCerts(certs::GenCertsArgs),

    /// Generate a docker-compose manifest for a complete redirector deployment.
    ///
    /// Emits a docker-compose.yml and nginx.conf pair under the chosen output
    /// directory, ready to be `docker compose up`-d on the redirector host.
    DockerCompose(nginx::DockerComposeArgs),

    /// Generate CloudFlare Workers CDN redirector deployment files.
    ///
    /// Creates a Wrangler project with TypeScript worker code that acts as a
    /// CDN-based traffic relay, enabling domain fronting through CloudFlare.
    CloudflareWorker(cloudflare::CloudflareWorkerArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::NginxConfig(args) => nginx::generate_nginx_config(args),
        Commands::GenCerts(args) => certs::generate_certs(args),
        Commands::DockerCompose(args) => nginx::generate_docker_compose(args),
        Commands::CloudflareWorker(args) => cloudflare::generate_cloudflare_worker(args),
    }
}
