//! Kraken server binary entry point

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use tonic::transport::Server as TonicServer;
use tracing_subscriber::{fmt, EnvFilter};

use crypto::{types::SymmetricKey, ServerCrypto};
use module_store::{ModuleStore, ModuleSigner};
use protocol::{
    job_service_server::JobServiceServer, CollabServiceServer, ImplantServiceServer,
    ListenerServiceServer, LootServiceServer, MeshServiceServer, ModuleServiceServer,
    OperatorServiceServer, PayloadServiceServer, ReportServiceServer, TaskServiceServer,
};
use server::{
    auth::{AuthConfig, require_client_cert},
    grpc::{CollabServiceImpl, ImplantServiceImpl, JobServiceImpl, ListenerServiceImpl,
           LootServiceImpl, MeshServiceImpl, ModuleServiceImpl, OperatorServiceImpl,
           PayloadServiceImpl, ReportServiceImpl, TaskServiceImpl},
    http::build_router,
    ServerState,
};

#[derive(Parser)]
#[command(name = "kraken-server", about = "Kraken C2 server")]
struct Args {
    /// gRPC operator interface port
    #[arg(long, default_value = "50051")]
    grpc_port: u16,

    /// HTTP implant listener port
    #[arg(long, default_value = "8080")]
    http_port: u16,

    /// Path to SQLite database file
    #[arg(long, default_value = "kraken.db")]
    db_path: String,

    /// Master encryption key (hex-encoded 32 bytes). Generated randomly if not provided.
    #[arg(long, env = "KRAKEN_MASTER_KEY")]
    master_key: Option<String>,

    /// Allow plaintext (non-TLS) operator connections. FOR DEVELOPMENT ONLY.
    /// In production, set KRAKEN_TLS_CA, KRAKEN_TLS_CERT, and KRAKEN_TLS_KEY instead.
    #[arg(long, default_value_t = false)]
    insecure: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialise tracing
    fmt().with_env_filter(EnvFilter::from_default_env()).init();

    // Connect to / create the SQLite database and run migrations
    tracing::info!(db_path = %args.db_path, "connecting to database");
    let db = db::Database::connect(&args.db_path).await?;
    db.migrate().await?;
    tracing::info!("database migrations applied");

    // Build master key — decode from hex if provided, otherwise generate randomly
    let master_key: SymmetricKey = if let Some(hex) = args.master_key {
        let bytes = hex::decode(hex).map_err(|e| format!("invalid master key hex: {}", e))?;
        SymmetricKey::from_bytes(&bytes).map_err(|e| format!("invalid master key length: {}", e))?
    } else {
        tracing::warn!("no master key provided — generating ephemeral key (data will not persist across restarts)");
        ServerCrypto::generate_master_key()?
    };

    // Derive audit HMAC key from master key (using a domain-separated hash)
    // In production, consider using a separate KRAKEN_AUDIT_KEY env var
    let audit_key = {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"kraken-audit-hmac-key:");
        hasher.update(master_key.0);
        hasher.finalize().to_vec()
    };

    // Initialize JWT manager for WebSocket authentication (before moving master_key)
    let jwt_manager = server::auth::jwt::JwtManager::from_env_or_master_key(&master_key.0)
        .map_err(|e| format!("failed to initialize JWT manager: {e}"))?;
    tracing::info!("JWT manager initialized for WebSocket authentication");

    let crypto = ServerCrypto::new(master_key);

    // Load or generate the Ed25519 signing key for module blobs.
    //
    // Resolution order:
    //   1. KRAKEN_MODULE_KEY_FILE — path to a PKCS#8 binary file
    //   2. KRAKEN_MODULE_KEY      — base64-encoded PKCS#8 bytes
    //   3. ephemeral (warn)       — current behaviour, not suitable for production
    //
    // When loaded from file or env the derived public key is written to
    // `module_signing.pub` so implant builds can embed it.
    let module_signing_key: Vec<u8> = if let Ok(path) = std::env::var("KRAKEN_MODULE_KEY_FILE") {
        tracing::info!(path = %path, "loading module signing key from file");
        std::fs::read(&path)
            .map_err(|e| format!("failed to read KRAKEN_MODULE_KEY_FILE '{path}': {e}"))?
    } else if let Ok(b64) = std::env::var("KRAKEN_MODULE_KEY") {
        tracing::info!("loading module signing key from KRAKEN_MODULE_KEY env var");
        base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            b64.trim(),
        )
        .map_err(|e| format!("invalid base64 in KRAKEN_MODULE_KEY: {e}"))?
    } else {
        tracing::warn!(
            "no persistent module signing key configured \
             (set KRAKEN_MODULE_KEY_FILE or KRAKEN_MODULE_KEY) — \
             generating ephemeral key; previously-signed blobs will not \
             verify after restart"
        );
        ModuleSigner::generate_pkcs8()
            .map_err(|e| format!("failed to generate module signing key: {e}"))?
    };

    // When a persistent key is in use, export the public key so implant
    // builds can embed it without needing access to the private key.
    if std::env::var("KRAKEN_MODULE_KEY_FILE").is_ok()
        || std::env::var("KRAKEN_MODULE_KEY").is_ok()
    {
        let signer = ModuleSigner::new(&module_signing_key)
            .map_err(|e| format!("failed to parse module signing key: {e}"))?;
        let pubkey = signer.public_key();
        std::fs::write("module_signing.pub", pubkey)
            .map_err(|e| format!("failed to write module_signing.pub: {e}"))?;
        tracing::info!("module signing public key written to module_signing.pub");
    }

    let module_store = std::sync::Arc::new(
        ModuleStore::new(std::sync::Arc::new(db.clone()), &module_signing_key)
            .map_err(|e| format!("failed to create module store: {e}"))?,
    );

    let state: Arc<ServerState> = ServerState::new(db, crypto, module_store, audit_key, jwt_manager);

    // Spawn background health-checker to detect lost implants
    server::services::health_checker::spawn(Arc::clone(&state));
    tracing::info!("health-checker spawned (scans every 30s for stale implants)");

    // Build bind addresses
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", args.grpc_port).parse()?;
    let http_addr: SocketAddr = format!("0.0.0.0:{}", args.http_port).parse()?;

    tracing::info!(addr = %grpc_addr, "starting gRPC server");
    tracing::info!(addr = %http_addr, "starting HTTP listener");

    // mTLS is REQUIRED for operator gRPC connections.
    // Set KRAKEN_TLS_CA, KRAKEN_TLS_CERT, and KRAKEN_TLS_KEY to provide certificates.
    // Pass --insecure to allow plaintext connections (development only).
    let tls_ca   = std::env::var("KRAKEN_TLS_CA").ok();
    let tls_cert = std::env::var("KRAKEN_TLS_CERT").ok();
    let tls_key  = std::env::var("KRAKEN_TLS_KEY").ok();

    let tls_config = match (tls_ca, tls_cert, tls_key) {
        (Some(ca), Some(cert), Some(key)) => {
            tracing::info!("mTLS enabled (CA={ca}, cert={cert}, key={key})");
            let auth = AuthConfig::load(&ca, &cert, &key)
                .map_err(|e| format!("failed to load TLS certificates: {e}"))?;
            let cfg = auth.server_tls_config()
                .map_err(|e| format!("failed to build TLS config: {e}"))?;
            Some(cfg)
        }
        _ if args.insecure => {
            tracing::warn!(
                "WARNING: running in INSECURE mode — operator gRPC connections are NOT encrypted \
                and client certificates are NOT required. Do not use in production. \
                Set KRAKEN_TLS_CA, KRAKEN_TLS_CERT, KRAKEN_TLS_KEY to enable mTLS."
            );
            None
        }
        _ => {
            return Err(
                "mTLS certificates are required. Set KRAKEN_TLS_CA, KRAKEN_TLS_CERT, and \
                KRAKEN_TLS_KEY environment variables, or pass --insecure for development \
                (plaintext, not suitable for production)."
                    .into(),
            );
        }
    };

    // When mTLS is active, wrap every service with the client-cert interceptor.
    // The interceptor rejects any request that arrives without a valid peer certificate,
    // ensuring the TLS handshake alone is not sufficient to reach the service layer.
    let grpc_state = Arc::clone(&state);
    let mut builder = TonicServer::builder();
    let mtls_active = tls_config.is_some();
    if let Some(cfg) = tls_config {
        builder = builder.tls_config(cfg)
            .map_err(|e| format!("failed to apply TLS config to gRPC server: {e}"))?;
    }

    let grpc_future = if mtls_active {
        tracing::info!("mTLS client certificate enforcement active on all gRPC services");
        builder
            .add_service(ImplantServiceServer::with_interceptor(
                ImplantServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(TaskServiceServer::with_interceptor(
                TaskServiceImpl::new_with_db_init(Arc::clone(&grpc_state)).await?,
                require_client_cert,
            ))
            .add_service(ListenerServiceServer::with_interceptor(
                ListenerServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(OperatorServiceServer::with_interceptor(
                OperatorServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(LootServiceServer::with_interceptor(
                LootServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(ModuleServiceServer::with_interceptor(
                ModuleServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(MeshServiceServer::with_interceptor(
                MeshServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(CollabServiceServer::with_interceptor(
                CollabServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(PayloadServiceServer::with_interceptor(
                PayloadServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(ReportServiceServer::with_interceptor(
                ReportServiceImpl::new(Arc::clone(&grpc_state)),
                require_client_cert,
            ))
            .add_service(JobServiceServer::with_interceptor(
                JobServiceImpl::new(Arc::new(grpc_state.db.jobs())),
                require_client_cert,
            ))
            .serve(grpc_addr)
    } else {
        builder
            .add_service(ImplantServiceServer::new(ImplantServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(TaskServiceServer::new(
                TaskServiceImpl::new_with_db_init(Arc::clone(&grpc_state)).await?,
            ))
            .add_service(ListenerServiceServer::new(ListenerServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(OperatorServiceServer::new(OperatorServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(LootServiceServer::new(LootServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(ModuleServiceServer::new(ModuleServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(MeshServiceServer::new(MeshServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(CollabServiceServer::new(CollabServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(PayloadServiceServer::new(PayloadServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(ReportServiceServer::new(ReportServiceImpl::new(
                Arc::clone(&grpc_state),
            )))
            .add_service(JobServiceServer::new(JobServiceImpl::new(
                Arc::new(grpc_state.db.jobs()),
            )))
            .serve(grpc_addr)
    };

    // Build HTTP router
    let http_state = Arc::clone(&state);
    let router = build_router(http_state);
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    let http_future = axum::serve(http_listener, router);

    // Run both servers, handle Ctrl+C / SIGTERM
    tokio::select! {
        result = grpc_future => {
            if let Err(e) = result {
                tracing::error!(error = %e, "gRPC server error");
            }
        }
        result = http_future => {
            if let Err(e) = result {
                tracing::error!(error = %e, "HTTP server error");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received shutdown signal (Ctrl+C), shutting down");
        }
    }

    tracing::info!("kraken-server stopped");
    Ok(())
}
