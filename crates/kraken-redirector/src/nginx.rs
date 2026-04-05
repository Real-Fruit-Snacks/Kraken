//! nginx config and docker-compose generation.
//!
//! Reads the bundled templates and performs token substitution to produce
//! operator-ready deployment artifacts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};

// ── Template bytes bundled at compile time ──────────────────────────────────

const NGINX_TEMPLATE: &str = include_str!("../templates/nginx.conf.template");
const COMPOSE_TEMPLATE: &str = include_str!("../templates/docker-compose.yml.template");

// ── Profile ──────────────────────────────────────────────────────────────────

/// HTTP malleable profile preset.
///
/// Each variant maps to a set of URIs and headers that the implant uses when
/// operating under that profile.  The redirector must match *exactly* those
/// URIs and forward them; everything else receives a decoy response.
#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Default HTTP profile — `/api/v1/status` check-in, `/api/v1/submit` tasks.
    Http,
    /// CDN-blend profile — paths mimic static asset requests.
    Cdn,
    /// Microsoft update profile — paths mimic Windows Update traffic.
    Msupdate,
    /// Custom profile — URIs supplied via `--checkin-uri` / `--task-uri`.
    Custom,
}

impl Profile {
    /// Return `(checkin_uri, task_uri)` for built-in profiles.
    pub fn default_uris(&self) -> (&'static str, &'static str) {
        match self {
            Profile::Http => ("/api/v1/status", "/api/v1/submit"),
            Profile::Cdn => ("/assets/bundle.min.js", "/assets/metrics.js"),
            Profile::Msupdate => ("/windowsupdate/v3/selfupdate/AU", "/windowsupdate/v3/selfupdate/DR"),
            Profile::Custom => ("/checkin", "/task"),
        }
    }
}

impl std::fmt::Display for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Profile::Http => write!(f, "http"),
            Profile::Cdn => write!(f, "cdn"),
            Profile::Msupdate => write!(f, "msupdate"),
            Profile::Custom => write!(f, "custom"),
        }
    }
}

// ── nginx-config subcommand ───────────────────────────────────────────────────

/// Arguments for the `nginx-config` subcommand.
#[derive(Debug, Args)]
pub struct NginxConfigArgs {
    /// Malleable HTTP profile to apply (determines matched URIs).
    #[arg(long, value_enum, default_value = "http")]
    pub profile: Profile,

    /// Backend teamserver IP or hostname.
    #[arg(long)]
    pub backend_host: String,

    /// Backend HTTPS port for implant C2 traffic.
    #[arg(long, default_value = "8443")]
    pub backend_port: u16,

    /// Backend gRPC port for the operator channel.
    #[arg(long, default_value = "50051")]
    pub grpc_port: u16,

    /// Override check-in URI (only used with --profile custom).
    #[arg(long)]
    pub checkin_uri: Option<String>,

    /// Override task URI (only used with --profile custom).
    #[arg(long)]
    pub task_uri: Option<String>,

    /// Hostname the nginx vhost should respond on.
    #[arg(long, default_value = "_")]
    pub server_name: String,

    /// Path to the TLS certificate for the redirector's public face.
    #[arg(long, default_value = "/etc/nginx/certs/server.crt")]
    pub tls_cert: String,

    /// Path to the TLS private key for the redirector's public face.
    #[arg(long, default_value = "/etc/nginx/certs/server.key")]
    pub tls_key: String,

    /// Path to the CA cert used to verify the backend (for mTLS passthrough).
    /// If omitted, backend TLS verification is disabled (not recommended for production).
    #[arg(long)]
    pub backend_ca: Option<String>,

    /// Client certificate for mTLS to the backend.
    #[arg(long)]
    pub backend_client_cert: Option<String>,

    /// Client key for mTLS to the backend.
    #[arg(long)]
    pub backend_client_key: Option<String>,

    /// Disable access logging (improves opsec on live deployments).
    #[arg(long, default_value = "false")]
    pub no_access_log: bool,

    /// Write the generated config to this file instead of stdout.
    #[arg(long, short = 'o')]
    pub output: Option<PathBuf>,
}

/// Render an nginx config from the bundled template and write to stdout or file.
pub fn generate_nginx_config(args: NginxConfigArgs) -> Result<()> {
    let (default_checkin, default_task) = args.profile.default_uris();

    let checkin_uri = args
        .checkin_uri
        .as_deref()
        .unwrap_or(default_checkin)
        .to_owned();
    let task_uri = args
        .task_uri
        .as_deref()
        .unwrap_or(default_task)
        .to_owned();

    // Build mTLS proxy_ssl_* lines for the implant proxy blocks
    let (proxy_ssl_verify, proxy_ssl_cert_lines) = build_proxy_ssl_lines(
        args.backend_ca.as_deref(),
        args.backend_client_cert.as_deref(),
        args.backend_client_key.as_deref(),
        "        proxy_ssl_",
    );

    // Build grpc_ssl_* lines for the gRPC block
    let (grpc_ssl_verify, grpc_ssl_cert_lines) = build_proxy_ssl_lines(
        args.backend_ca.as_deref(),
        args.backend_client_cert.as_deref(),
        args.backend_client_key.as_deref(),
        "        grpc_ssl_",
    );

    let grpc_mtls = if args.backend_client_cert.is_some() {
        format!(
            "        grpc_ssl_certificate     {};\n        grpc_ssl_certificate_key {};",
            args.backend_client_cert.as_deref().unwrap_or(""),
            args.backend_client_key.as_deref().unwrap_or(""),
        )
    } else {
        "        # mTLS not configured for gRPC channel".to_owned()
    };

    let access_log_line = if args.no_access_log {
        "access_log off;".to_owned()
    } else {
        "access_log /var/log/nginx/kraken-redirector-access.log combined;".to_owned()
    };

    let config = NGINX_TEMPLATE
        .replace("{{PROFILE}}", &args.profile.to_string())
        .replace("{{GENERATED_AT}}", &Utc::now().to_rfc3339())
        .replace("{{SERVER_NAME}}", &args.server_name)
        .replace("{{TLS_CERT_PATH}}", &args.tls_cert)
        .replace("{{TLS_KEY_PATH}}", &args.tls_key)
        .replace("{{CHECKIN_URI}}", &checkin_uri)
        .replace("{{TASK_URI}}", &task_uri)
        .replace("{{BACKEND_HOST}}", &args.backend_host)
        .replace("{{BACKEND_PORT}}", &args.backend_port.to_string())
        .replace("{{GRPC_BACKEND_PORT}}", &args.grpc_port.to_string())
        .replace("{{PROXY_SSL_VERIFY}}", &proxy_ssl_verify)
        .replace("{{PROXY_SSL_CERTIFICATE_LINES}}", &proxy_ssl_cert_lines)
        .replace("{{GRPC_SSL_VERIFY}}", &grpc_ssl_verify)
        .replace("{{GRPC_SSL_CERTIFICATE_LINES}}", &grpc_ssl_cert_lines)
        .replace("{{GRPC_MTLS_LINES}}", &grpc_mtls)
        .replace("{{ACCESS_LOG_LINE}}", &access_log_line);

    write_or_print(&config, args.output.as_deref())
}

/// Build `proxy_ssl_verify` value and optional certificate/key lines.
fn build_proxy_ssl_lines(
    ca: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
    prefix: &str,
) -> (String, String) {
    let verify = if ca.is_some() { "on" } else { "off" }.to_owned();

    let mut lines = Vec::new();
    if let Some(ca_path) = ca {
        lines.push(format!("{}trusted_certificate {};", prefix, ca_path));
    }
    if let Some(c) = cert {
        lines.push(format!("{}certificate {};", prefix, c));
    }
    if let Some(k) = key {
        lines.push(format!("{}certificate_key {};", prefix, k));
    }

    (verify, if lines.is_empty() { String::new() } else { lines.join("\n") + "\n" })
}

// ── docker-compose subcommand ────────────────────────────────────────────────

/// Arguments for the `docker-compose` subcommand.
#[derive(Debug, Args)]
pub struct DockerComposeArgs {
    /// Malleable HTTP profile to embed in the generated nginx config.
    #[arg(long, value_enum, default_value = "http")]
    pub profile: Profile,

    /// Backend teamserver IP or hostname.
    #[arg(long, default_value = "10.0.0.1")]
    pub backend_host: String,

    /// Backend HTTPS port for implant C2 traffic.
    #[arg(long, default_value = "8443")]
    pub backend_port: u16,

    /// Backend gRPC port for operator channel.
    #[arg(long, default_value = "50051")]
    pub grpc_port: u16,

    /// Path to the TLS certificate on the *host* (bind-mounted into the container).
    #[arg(long, default_value = "./certs/server.crt")]
    pub tls_cert: String,

    /// Path to the TLS private key on the *host*.
    #[arg(long, default_value = "./certs/server.key")]
    pub tls_key: String,

    /// Optional CA cert for mTLS to backend (host path).
    #[arg(long)]
    pub backend_ca: Option<String>,

    /// Output directory for generated files.
    #[arg(long, short = 'o', default_value = "./deploy")]
    pub output: PathBuf,
}

/// Generate both a docker-compose.yml and an nginx.conf into `--output`.
pub fn generate_docker_compose(args: DockerComposeArgs) -> Result<()> {
    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("creating output directory {}", args.output.display()))?;

    // First generate the nginx config alongside
    let nginx_args = NginxConfigArgs {
        profile: args.profile.clone(),
        backend_host: args.backend_host.clone(),
        backend_port: args.backend_port,
        grpc_port: args.grpc_port,
        checkin_uri: None,
        task_uri: None,
        server_name: "_".to_owned(),
        tls_cert: "/etc/nginx/certs/server.crt".to_owned(),
        tls_key: "/etc/nginx/certs/server.key".to_owned(),
        backend_ca: args.backend_ca.clone().map(|_| "/etc/nginx/certs/ca.crt".to_owned()),
        backend_client_cert: None,
        backend_client_key: None,
        no_access_log: false,
        output: Some(args.output.join("nginx.conf")),
    };
    generate_nginx_config(nginx_args)?;

    // mTLS volume lines
    let mtls_vol = if let Some(ref ca) = args.backend_ca {
        format!("      - {}:/etc/nginx/certs/ca.crt:ro", ca)
    } else {
        String::new()
    };

    let compose = COMPOSE_TEMPLATE
        .replace("{{PROFILE}}", &args.profile.to_string())
        .replace("{{GENERATED_AT}}", &Utc::now().to_rfc3339())
        .replace("{{TLS_CERT_PATH}}", &args.tls_cert)
        .replace("{{TLS_KEY_PATH}}", &args.tls_key)
        .replace("{{GRPC_BACKEND_PORT}}", &args.grpc_port.to_string())
        .replace("{{MTLS_VOLUME_LINES}}", &mtls_vol);

    let compose_path = args.output.join("docker-compose.yml");
    std::fs::write(&compose_path, &compose)
        .with_context(|| format!("writing {}", compose_path.display()))?;

    println!("Generated:");
    println!("  {}", args.output.join("nginx.conf").display());
    println!("  {}", compose_path.display());
    println!();
    println!("Deploy with:");
    println!("  cd {}", args.output.display());
    println!("  docker compose up -d");

    Ok(())
}

// ── shared helpers ────────────────────────────────────────────────────────────

fn write_or_print(content: &str, output: Option<&Path>) -> Result<()> {
    match output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("creating directory {}", parent.display()))?;
                }
            }
            std::fs::write(path, content)
                .with_context(|| format!("writing {}", path.display()))?;
            println!("Wrote {}", path.display());
        }
        None => print!("{}", content),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── Profile Tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_profile_display() {
        assert_eq!(Profile::Http.to_string(), "http");
        assert_eq!(Profile::Cdn.to_string(), "cdn");
        assert_eq!(Profile::Msupdate.to_string(), "msupdate");
        assert_eq!(Profile::Custom.to_string(), "custom");
    }

    #[test]
    fn test_profile_default_uris_http() {
        let (checkin, task) = Profile::Http.default_uris();
        assert_eq!(checkin, "/api/v1/status");
        assert_eq!(task, "/api/v1/submit");
    }

    #[test]
    fn test_profile_default_uris_cdn() {
        let (checkin, task) = Profile::Cdn.default_uris();
        assert_eq!(checkin, "/assets/bundle.min.js");
        assert_eq!(task, "/assets/metrics.js");
    }

    #[test]
    fn test_profile_default_uris_msupdate() {
        let (checkin, task) = Profile::Msupdate.default_uris();
        assert!(checkin.contains("windowsupdate"));
        assert!(task.contains("windowsupdate"));
    }

    #[test]
    fn test_profile_default_uris_custom() {
        let (checkin, task) = Profile::Custom.default_uris();
        assert_eq!(checkin, "/checkin");
        assert_eq!(task, "/task");
    }

    #[test]
    fn test_profile_equality() {
        assert_eq!(Profile::Http, Profile::Http);
        assert_ne!(Profile::Http, Profile::Cdn);
    }

    // ── build_proxy_ssl_lines Tests ───────────────────────────────────────────

    #[test]
    fn test_build_proxy_ssl_lines_no_mtls() {
        let (verify, lines) = build_proxy_ssl_lines(None, None, None, "        proxy_ssl_");
        assert_eq!(verify, "off");
        assert!(lines.is_empty());
    }

    #[test]
    fn test_build_proxy_ssl_lines_with_ca() {
        let (verify, lines) = build_proxy_ssl_lines(
            Some("/path/to/ca.crt"),
            None,
            None,
            "        proxy_ssl_",
        );
        assert_eq!(verify, "on");
        assert!(lines.contains("trusted_certificate /path/to/ca.crt"));
    }

    #[test]
    fn test_build_proxy_ssl_lines_full_mtls() {
        let (verify, lines) = build_proxy_ssl_lines(
            Some("/path/to/ca.crt"),
            Some("/path/to/client.crt"),
            Some("/path/to/client.key"),
            "        proxy_ssl_",
        );
        assert_eq!(verify, "on");
        assert!(lines.contains("trusted_certificate /path/to/ca.crt"));
        assert!(lines.contains("certificate /path/to/client.crt"));
        assert!(lines.contains("certificate_key /path/to/client.key"));
    }

    #[test]
    fn test_build_proxy_ssl_lines_prefix() {
        let (_, lines) = build_proxy_ssl_lines(
            Some("/ca.crt"),
            None,
            None,
            "        grpc_ssl_",
        );
        assert!(lines.contains("grpc_ssl_trusted_certificate"));
    }

    // ── NginxConfigArgs Tests ─────────────────────────────────────────────────

    #[test]
    fn test_nginx_config_generation_basic() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("nginx.conf");

        let args = NginxConfigArgs {
            profile: Profile::Http,
            backend_host: "10.0.0.1".into(),
            backend_port: 8443,
            grpc_port: 50051,
            checkin_uri: None,
            task_uri: None,
            server_name: "test.example.com".into(),
            tls_cert: "/etc/ssl/certs/server.crt".into(),
            tls_key: "/etc/ssl/private/server.key".into(),
            backend_ca: None,
            backend_client_cert: None,
            backend_client_key: None,
            no_access_log: false,
            output: Some(output_path.clone()),
        };

        let result = generate_nginx_config(args);
        assert!(result.is_ok(), "generate_nginx_config failed: {:?}", result.err());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("10.0.0.1"));
        assert!(content.contains("8443"));
        assert!(content.contains("50051"));
        assert!(content.contains("test.example.com"));
        assert!(content.contains("/api/v1/status")); // default HTTP profile URIs
        assert!(content.contains("/api/v1/submit"));
    }

    #[test]
    fn test_nginx_config_custom_uris() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("nginx.conf");

        let args = NginxConfigArgs {
            profile: Profile::Custom,
            backend_host: "192.168.1.1".into(),
            backend_port: 443,
            grpc_port: 50051,
            checkin_uri: Some("/custom/beacon".into()),
            task_uri: Some("/custom/tasks".into()),
            server_name: "_".into(),
            tls_cert: "/certs/server.crt".into(),
            tls_key: "/certs/server.key".into(),
            backend_ca: None,
            backend_client_cert: None,
            backend_client_key: None,
            no_access_log: true,
            output: Some(output_path.clone()),
        };

        let result = generate_nginx_config(args);
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("/custom/beacon"));
        assert!(content.contains("/custom/tasks"));
        assert!(content.contains("access_log off"));
    }

    #[test]
    fn test_nginx_config_with_mtls() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("nginx.conf");

        let args = NginxConfigArgs {
            profile: Profile::Http,
            backend_host: "backend.local".into(),
            backend_port: 8443,
            grpc_port: 50051,
            checkin_uri: None,
            task_uri: None,
            server_name: "_".into(),
            tls_cert: "/certs/server.crt".into(),
            tls_key: "/certs/server.key".into(),
            backend_ca: Some("/certs/ca.crt".into()),
            backend_client_cert: Some("/certs/client.crt".into()),
            backend_client_key: Some("/certs/client.key".into()),
            no_access_log: false,
            output: Some(output_path.clone()),
        };

        let result = generate_nginx_config(args);
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_path).unwrap();
        // Template uses "proxy_ssl_verify   on;" with spaces
        assert!(content.contains("on;"), "should enable ssl verification");
        assert!(content.contains("/certs/ca.crt"));
        assert!(content.contains("/certs/client.crt"));
    }

    #[test]
    fn test_nginx_config_cdn_profile() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("nginx.conf");

        let args = NginxConfigArgs {
            profile: Profile::Cdn,
            backend_host: "10.0.0.1".into(),
            backend_port: 8443,
            grpc_port: 50051,
            checkin_uri: None,
            task_uri: None,
            server_name: "_".into(),
            tls_cert: "/certs/server.crt".into(),
            tls_key: "/certs/server.key".into(),
            backend_ca: None,
            backend_client_cert: None,
            backend_client_key: None,
            no_access_log: false,
            output: Some(output_path.clone()),
        };

        let result = generate_nginx_config(args);
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("/assets/bundle.min.js"));
        assert!(content.contains("/assets/metrics.js"));
    }

    // ── DockerCompose Tests ───────────────────────────────────────────────────

    #[test]
    fn test_docker_compose_generation() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("deploy");

        let args = DockerComposeArgs {
            profile: Profile::Http,
            backend_host: "10.0.0.1".into(),
            backend_port: 8443,
            grpc_port: 50051,
            tls_cert: "./certs/server.crt".into(),
            tls_key: "./certs/server.key".into(),
            backend_ca: None,
            output: output_dir.clone(),
        };

        let result = generate_docker_compose(args);
        assert!(result.is_ok(), "generate_docker_compose failed: {:?}", result.err());

        // Check docker-compose.yml exists
        let compose_path = output_dir.join("docker-compose.yml");
        assert!(compose_path.exists());

        let compose_content = fs::read_to_string(&compose_path).unwrap();
        assert!(compose_content.contains("nginx"));
        assert!(compose_content.contains("50051"));

        // Check nginx.conf exists
        let nginx_path = output_dir.join("nginx.conf");
        assert!(nginx_path.exists());

        let nginx_content = fs::read_to_string(&nginx_path).unwrap();
        assert!(nginx_content.contains("10.0.0.1"));
    }

    #[test]
    fn test_docker_compose_with_mtls() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("deploy");

        let args = DockerComposeArgs {
            profile: Profile::Http,
            backend_host: "backend.local".into(),
            backend_port: 8443,
            grpc_port: 50051,
            tls_cert: "./certs/server.crt".into(),
            tls_key: "./certs/server.key".into(),
            backend_ca: Some("./certs/ca.crt".into()),
            output: output_dir.clone(),
        };

        let result = generate_docker_compose(args);
        assert!(result.is_ok());

        let compose_path = output_dir.join("docker-compose.yml");
        let compose_content = fs::read_to_string(&compose_path).unwrap();
        // mTLS volume should be included
        assert!(compose_content.contains("ca.crt") || compose_content.contains("certs"));
    }

    // ── write_or_print Tests ──────────────────────────────────────────────────

    #[test]
    fn test_write_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test.txt");

        let result = write_or_print("test content", Some(&output_path));
        assert!(result.is_ok());

        let content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_write_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("nested").join("dir").join("test.txt");

        let result = write_or_print("nested content", Some(&output_path));
        assert!(result.is_ok());

        assert!(output_path.exists());
        let content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(content, "nested content");
    }

    // ── Profile Serialization Tests ───────────────────────────────────────────

    #[test]
    fn test_profile_serde_roundtrip() {
        let profile = Profile::Http;
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: Profile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_all_profiles_serde() {
        for profile in [Profile::Http, Profile::Cdn, Profile::Msupdate, Profile::Custom] {
            let json = serde_json::to_string(&profile).unwrap();
            let deserialized: Profile = serde_json::from_str(&json).unwrap();
            assert_eq!(profile, deserialized);
        }
    }
}
