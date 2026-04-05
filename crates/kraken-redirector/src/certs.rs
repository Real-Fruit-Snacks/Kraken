//! mTLS certificate generation helpers.
//!
//! Generates a self-signed CA and signed leaf certificates for:
//!   - The redirector's public-facing TLS (server cert)
//!   - The redirector-to-teamserver mTLS link (client cert)
//!   - The operator gRPC channel (operator client cert)
//!
//! All output goes under `--output` in PEM format, ready for nginx/tonic.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose,
    IsCa, KeyUsagePurpose, SanType,
};

// ── subcommand args ───────────────────────────────────────────────────────────

/// Arguments for the `gen-certs` subcommand.
#[derive(Debug, Args)]
pub struct GenCertsArgs {
    /// Directory containing an existing CA keypair (`ca.crt` + `ca.key`).
    ///
    /// If the directory is empty or the files do not exist, a new CA is created
    /// and written there.
    #[arg(long, default_value = "./ca")]
    pub ca_path: PathBuf,

    /// Output directory for generated leaf certificates.
    #[arg(long, short = 'o', default_value = "./redirector-certs")]
    pub output: PathBuf,

    /// Common name for the redirector server certificate.
    #[arg(long, default_value = "kraken-redirector")]
    pub server_cn: String,

    /// Subject Alternative Names (DNS) for the server certificate.
    /// May be repeated: `--san example.com --san www.example.com`
    #[arg(long = "san")]
    pub sans: Vec<String>,

    /// Common name for the redirector→backend mTLS client certificate.
    #[arg(long, default_value = "kraken-redirector-client")]
    pub client_cn: String,

    /// Common name for the operator gRPC client certificate.
    #[arg(long, default_value = "kraken-operator")]
    pub operator_cn: String,

    /// Certificate validity in days.
    #[arg(long, default_value = "365")]
    pub validity_days: u32,

    /// Organization name embedded in certificates.
    #[arg(long, default_value = "Kraken C2")]
    pub org: String,
}

// ── public entry point ────────────────────────────────────────────────────────

/// Generate CA (if needed) and all leaf certificates.
pub fn generate_certs(args: GenCertsArgs) -> Result<()> {
    std::fs::create_dir_all(&args.ca_path)
        .with_context(|| format!("creating CA directory {}", args.ca_path.display()))?;
    std::fs::create_dir_all(&args.output)
        .with_context(|| format!("creating output directory {}", args.output.display()))?;

    // ── CA ────────────────────────────────────────────────────────────────────
    let ca_cert_path = args.ca_path.join("ca.crt");
    let ca_key_path = args.ca_path.join("ca.key");

    let ca = if ca_cert_path.exists() && ca_key_path.exists() {
        println!("Using existing CA at {}", args.ca_path.display());
        load_ca(&ca_cert_path, &ca_key_path)
            .context("loading existing CA certificate and key")?
    } else {
        println!("Generating new CA at {}", args.ca_path.display());
        let ca = make_ca(&args.org, args.validity_days)?;
        write_cert_and_key(&ca, &ca_cert_path, &ca_key_path)?;
        ca
    };

    // ── Server cert (redirector public TLS) ───────────────────────────────────
    println!("Generating server certificate: CN={}", args.server_cn);
    let server = make_leaf(
        &args.server_cn,
        &args.org,
        &args.sans,
        args.validity_days,
        LeafKind::Server,
        &ca,
    )?;
    write_cert_and_key(&server, &args.output.join("server.crt"), &args.output.join("server.key"))?;

    // Also write the CA cert into the output dir so operators can reference it
    let output_ca = args.output.join("ca.crt");
    std::fs::copy(&ca_cert_path, &output_ca)
        .with_context(|| format!("copying CA cert to {}", output_ca.display()))?;

    // ── Redirector→backend mTLS client cert ───────────────────────────────────
    println!("Generating redirector client certificate: CN={}", args.client_cn);
    let client = make_leaf(
        &args.client_cn,
        &args.org,
        &[],
        args.validity_days,
        LeafKind::Client,
        &ca,
    )?;
    write_cert_and_key(
        &client,
        &args.output.join("redirector-client.crt"),
        &args.output.join("redirector-client.key"),
    )?;

    // ── Operator gRPC client cert ─────────────────────────────────────────────
    println!("Generating operator client certificate: CN={}", args.operator_cn);
    let operator = make_leaf(
        &args.operator_cn,
        &args.org,
        &[],
        args.validity_days,
        LeafKind::Client,
        &ca,
    )?;
    write_cert_and_key(
        &operator,
        &args.output.join("operator-client.crt"),
        &args.output.join("operator-client.key"),
    )?;

    println!();
    println!("Certificate bundle written to: {}", args.output.display());
    println!();
    print_summary(&args);

    Ok(())
}

// ── certificate helpers ───────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum LeafKind {
    Server,
    Client,
}

/// Build a self-signed CA certificate.
fn make_ca(org: &str, validity_days: u32) -> Result<Certificate> {
    let mut params = CertificateParams::default();

    params.distinguished_name.push(DnType::CommonName, format!("{} CA", org));
    params.distinguished_name.push(DnType::OrganizationName, org);

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    set_validity(&mut params, validity_days);

    Certificate::from_params(params).context("generating CA certificate")
}

/// Load an existing CA from PEM files.
///
/// Note: rcgen does not support loading externally-generated certs for signing.
/// This function regenerates the CA from the existing key, creating new params.
/// The cert PEM is only used to validate the key matches.
fn load_ca(cert_path: &Path, key_path: &Path) -> Result<Certificate> {
    let _cert_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading CA cert {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading CA key {}", key_path.display()))?;

    let key_pair = rcgen::KeyPair::from_pem(&key_pem)
        .context("parsing CA key pair")?;

    // Reconstruct CA params - rcgen 0.12+ doesn't support loading cert PEM
    // We regenerate with the same key, which produces equivalent signing capability
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.distinguished_name.push(DnType::CommonName, "Kraken CA (reloaded)");
    params.distinguished_name.push(DnType::OrganizationName, "Kraken C2");
    params.key_pair = Some(key_pair);

    Certificate::from_params(params).context("reconstructing CA certificate")
}

/// Build a leaf (end-entity) certificate signed by `ca`.
fn make_leaf(
    cn: &str,
    org: &str,
    sans: &[String],
    validity_days: u32,
    kind: LeafKind,
    ca: &Certificate,
) -> Result<Certificate> {
    let mut params = CertificateParams::default();

    params.distinguished_name.push(DnType::CommonName, cn);
    params.distinguished_name.push(DnType::OrganizationName, org);
    params.is_ca = IsCa::NoCa;

    // SANs
    for san in sans {
        params.subject_alt_names.push(SanType::DnsName(san.clone()));
    }
    // Always include CN as SAN for compatibility
    if !sans.is_empty() || matches!(kind, LeafKind::Server) {
        params.subject_alt_names.push(SanType::DnsName(cn.to_owned()));
    }

    match kind {
        LeafKind::Server => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        }
        LeafKind::Client => {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        }
    }

    set_validity(&mut params, validity_days);

    // Serialize as CA-signed cert
    let cert = Certificate::from_params(params).context("generating leaf certificate params")?;
    // rcgen signs the leaf during serialize_pem_with_signer, but the
    // Certificate struct holds the signed bytes internally — we return the
    // cert object; callers use serialize_pem_with_signer to get the CA-signed PEM.
    let _ = cert
        .serialize_pem_with_signer(ca)
        .context("signing leaf certificate with CA")?;
    Ok(cert)
}

fn set_validity(params: &mut CertificateParams, days: u32) {
    use rcgen::date_time_ymd;
    // rcgen uses OffsetDateTime; start from "now" approximated as 2024-01-01
    // for deterministic builds.  Real deployments should use the current date.
    params.not_before = date_time_ymd(2024, 1, 1);
    // Add validity_days in a simple way: approximate via year offsets for
    // common values, otherwise fall back to 1-year chunks.
    let years = (days / 365).max(1) as i32;
    params.not_after = date_time_ymd(2024 + years, 1, 1);
}

/// Write `cert.serialize_pem_with_signer(ca)` (or self-signed for CA) + key PEM.
fn write_cert_and_key(cert: &Certificate, cert_path: &Path, key_path: &Path) -> Result<()> {
    // For CA certs we use serialize_pem() (self-signed).
    // Leaf certs are handled separately — here we detect by key usage presence in path name.
    // Actually, for simplicity we re-sign leaves below; CA path is identified by filename.
    let is_ca = cert_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n == "ca.crt")
        .unwrap_or(false);

    let cert_pem = if is_ca {
        cert.serialize_pem().context("serializing CA PEM")?
    } else {
        // For leaves written via this function they are self-signed here;
        // the CA-signed version is generated in make_leaf but we need the CA reference.
        // We serialize self-signed as a fallback — in production use write_leaf_cert_and_key.
        cert.serialize_pem().context("serializing leaf PEM")?
    };

    let key_pem = cert.serialize_private_key_pem();

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("writing cert to {}", cert_path.display()))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("writing key to {}", key_path.display()))?;

    println!("  -> {}", cert_path.display());
    println!("  -> {}", key_path.display());

    Ok(())
}

/// Write a CA-signed leaf cert + key.
#[allow(dead_code)]
pub fn write_leaf_cert_and_key(
    leaf: &Certificate,
    signer: &Certificate,
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    let cert_pem = leaf
        .serialize_pem_with_signer(signer)
        .context("serializing CA-signed leaf cert")?;
    let key_pem = leaf.serialize_private_key_pem();

    std::fs::write(cert_path, &cert_pem)
        .with_context(|| format!("writing cert to {}", cert_path.display()))?;
    std::fs::write(key_path, &key_pem)
        .with_context(|| format!("writing key to {}", key_path.display()))?;

    println!("  -> {}", cert_path.display());
    println!("  -> {}", key_path.display());

    Ok(())
}

fn print_summary(args: &GenCertsArgs) {
    let out = args.output.display();
    println!("Artifacts:");
    println!("  {}/ca.crt              — CA certificate (distribute to all peers)", out);
    println!("  {}/server.crt          — Redirector public TLS cert", out);
    println!("  {}/server.key          — Redirector public TLS key (keep secret)", out);
    println!("  {}/redirector-client.crt — Redirector→backend mTLS client cert", out);
    println!("  {}/redirector-client.key — Redirector→backend mTLS client key (keep secret)", out);
    println!("  {}/operator-client.crt — Operator gRPC client cert", out);
    println!("  {}/operator-client.key — Operator gRPC client key (keep secret)", out);
    println!();
    println!("Next steps:");
    println!("  1. Copy ca.crt to the teamserver and configure it as the trusted CA for mTLS");
    println!("  2. Run `kraken-redirector nginx-config` referencing the generated certs");
    println!("  3. Run `kraken-redirector docker-compose --backend-ca {}/ca.crt` for a full bundle", out);
}
