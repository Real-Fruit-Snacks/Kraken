//! Mutual TLS (mTLS) certificate generation and configuration
//!
//! Provides ECDSA P-256 certificate generation for CA, server, and implant
//! identities, plus rustls ClientConfig/ServerConfig builders that enforce
//! mutual authentication.

use std::sync::Arc;

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use rustls::{
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};

use common::KrakenError;

// ============================================================================
// Certificate generation
// ============================================================================

/// Generate a self-signed CA certificate using ECDSA P-256.
///
/// Returns `(certificate, key_pair)` where `certificate` can be used to sign
/// implant / server leaf certificates.
pub fn generate_ca() -> Result<(Certificate, KeyPair), KrakenError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| KrakenError::Crypto(format!("CA key generation failed: {}", e)))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.distinguished_name.push(DnType::CommonName, "Kraken CA");
    params.distinguished_name.push(DnType::OrganizationName, "Kraken C2");

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| KrakenError::Crypto(format!("CA self-sign failed: {}", e)))?;

    Ok((cert, key_pair))
}

/// Generate a leaf certificate for a server, signed by the supplied CA.
///
/// `san_dns` is added as a DNS SAN entry (e.g. `"c2.example.com"`).
pub fn generate_server_cert(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    san_dns: &str,
) -> Result<(Vec<u8>, Vec<u8>), KrakenError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| KrakenError::Crypto(format!("server key generation failed: {}", e)))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = vec![SanType::DnsName(
        san_dns
            .try_into()
            .map_err(|_| KrakenError::Crypto("invalid SAN DNS name".into()))?,
    )];
    params.distinguished_name.push(DnType::CommonName, san_dns);

    let cert = params
        .signed_by(&key_pair, ca_cert, ca_key)
        .map_err(|e| KrakenError::Crypto(format!("server cert signing failed: {}", e)))?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}

/// Generate a leaf certificate for an implant, signed by the supplied CA.
///
/// The `implant_id` is embedded in the CN and as a URI SAN so the server can
/// identify the implant from the TLS client certificate alone.
///
/// Returns `(cert_pem, key_pem)`.
pub fn generate_implant_cert(
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    implant_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), KrakenError> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| KrakenError::Crypto(format!("implant key generation failed: {}", e)))?;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    // Embed implant ID as a URI SAN for easy extraction
    params.subject_alt_names = vec![SanType::URI(
        format!("kraken://implant/{}", implant_id)
            .try_into()
            .map_err(|_| KrakenError::Crypto("invalid SAN URI".into()))?,
    )];
    params
        .distinguished_name
        .push(DnType::CommonName, implant_id);

    let cert = params
        .signed_by(&key_pair, ca_cert, ca_key)
        .map_err(|e| KrakenError::Crypto(format!("implant cert signing failed: {}", e)))?;

    Ok((
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    ))
}

// ============================================================================
// rustls config builders
// ============================================================================

/// Build a rustls `ClientConfig` that presents `client_cert` / `client_key`
/// and only trusts servers whose certificate chains up to `ca_cert`.
///
/// This is used by the implant to authenticate to the C2 server and to verify
/// the server's identity (certificate pinning against the CA).
pub fn build_mtls_client_config(
    client_cert: &[u8],
    client_key: &[u8],
    ca_cert: &[u8],
) -> Result<ClientConfig, KrakenError> {
    // Parse CA certificate into a root store
    let root_store = parse_root_store(ca_cert)?;

    // Parse client certificate chain
    let cert_chain = parse_cert_chain(client_cert)?;

    // Parse client private key
    let private_key = parse_private_key(client_key)?;

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, private_key)
        .map_err(|e| KrakenError::Crypto(format!("client TLS config error: {}", e)))?;

    Ok(config)
}

/// Build a rustls `ServerConfig` that presents `server_cert` / `server_key`
/// and requires all connecting clients to present a certificate signed by
/// `ca_cert` (i.e. only provisioned implants are accepted).
pub fn build_mtls_server_config(
    server_cert: &[u8],
    server_key: &[u8],
    ca_cert: &[u8],
) -> Result<ServerConfig, KrakenError> {
    // Parse CA certificate into a root store for client verification
    let root_store = Arc::new(parse_root_store(ca_cert)?);

    // Parse server certificate chain
    let cert_chain = parse_cert_chain(server_cert)?;

    // Parse server private key
    let private_key = parse_private_key(server_key)?;

    // Require client certificates (mTLS)
    let client_verifier = WebPkiClientVerifier::builder(root_store)
        .build()
        .map_err(|e| KrakenError::Crypto(format!("client verifier build failed: {}", e)))?;

    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(cert_chain, private_key)
        .map_err(|e| KrakenError::Crypto(format!("server TLS config error: {}", e)))?;

    Ok(config)
}

// ============================================================================
// PEM parsing helpers
// ============================================================================

fn parse_root_store(ca_pem: &[u8]) -> Result<RootCertStore, KrakenError> {
    let mut root_store = RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem);
    let der_certs: Vec<_> = certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KrakenError::Crypto(format!("CA cert parse failed: {}", e)))?;

    if der_certs.is_empty() {
        return Err(KrakenError::Crypto("no certificates found in CA PEM".into()));
    }

    for der in der_certs {
        root_store
            .add(der)
            .map_err(|e| KrakenError::Crypto(format!("CA cert add failed: {}", e)))?;
    }

    Ok(root_store)
}

fn parse_cert_chain(cert_pem: &[u8]) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, KrakenError> {
    let mut cursor = std::io::Cursor::new(cert_pem);
    let chain: Vec<_> = certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KrakenError::Crypto(format!("cert chain parse failed: {}", e)))?;

    if chain.is_empty() {
        return Err(KrakenError::Crypto("no certificates found in PEM".into()));
    }

    Ok(chain)
}

fn parse_private_key(key_pem: &[u8]) -> Result<rustls::pki_types::PrivateKeyDer<'static>, KrakenError> {
    let mut cursor = std::io::Cursor::new(key_pem);
    let keys: Vec<_> = pkcs8_private_keys(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| KrakenError::Crypto(format!("private key parse failed: {}", e)))?;

    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| KrakenError::Crypto("no PKCS8 private key found in PEM".into()))?;

    Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ca_produces_valid_certificate() {
        let (cert, key) = generate_ca().unwrap();
        let pem = cert.pem();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        let key_pem = key.serialize_pem();
        assert!(key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_implant_cert_signed_by_ca() {
        let (ca_cert, ca_key) = generate_ca().unwrap();
        let (cert_pem, key_pem) = generate_implant_cert(&ca_cert, &ca_key, "implant-abc123").unwrap();
        assert!(std::str::from_utf8(&cert_pem).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(std::str::from_utf8(&key_pem).unwrap().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn generate_server_cert_signed_by_ca() {
        let (ca_cert, ca_key) = generate_ca().unwrap();
        let (cert_pem, key_pem) = generate_server_cert(&ca_cert, &ca_key, "localhost").unwrap();
        assert!(std::str::from_utf8(&cert_pem).unwrap().contains("BEGIN CERTIFICATE"));
        assert!(std::str::from_utf8(&key_pem).unwrap().contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn build_mtls_server_config_succeeds() {
        // Install crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (ca_cert, ca_key) = generate_ca().unwrap();
        let ca_pem = ca_cert.pem().into_bytes();
        let (server_cert_pem, server_key_pem) =
            generate_server_cert(&ca_cert, &ca_key, "localhost").unwrap();

        build_mtls_server_config(&server_cert_pem, &server_key_pem, &ca_pem).unwrap();
    }

    #[test]
    fn build_mtls_client_config_succeeds() {
        // Install crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (ca_cert, ca_key) = generate_ca().unwrap();
        let ca_pem = ca_cert.pem().into_bytes();
        let (client_cert_pem, client_key_pem) =
            generate_implant_cert(&ca_cert, &ca_key, "implant-xyz").unwrap();

        build_mtls_client_config(&client_cert_pem, &client_key_pem, &ca_pem).unwrap();
    }

    #[test]
    fn empty_ca_pem_returns_error() {
        let result = build_mtls_server_config(b"not a cert", b"not a key", b"");
        assert!(result.is_err());
    }
}
