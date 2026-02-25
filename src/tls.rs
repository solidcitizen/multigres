//! TLS configuration builders — server (termination) and client (origination).

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use std::fs::File;
use std::io::{self, BufReader};
use std::sync::Arc;

/// Build a `ServerConfig` for TLS termination (client → Pgvpd).
pub fn build_server_config(
    cert_path: &str,
    key_path: &str,
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Arc::new(config))
}

/// Build a `ClientConfig` for TLS origination (Pgvpd → upstream Postgres).
///
/// - `verify`: if false, skip certificate verification (for dev/self-signed)
/// - `ca_path`: optional path to a custom CA certificate
pub fn build_client_config(
    verify: bool,
    ca_path: Option<&str>,
) -> io::Result<Arc<ClientConfig>> {
    let config = if !verify {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    } else if let Some(ca) = ca_path {
        let ca_certs = load_certs(ca)?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// Parse the upstream host into a `ServerName` for the TLS handshake.
/// Handles both DNS names and IP addresses.
pub fn parse_server_name(host: &str) -> io::Result<ServerName<'static>> {
    ServerName::try_from(host.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn load_certs(path: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader).collect()
}

fn load_private_key(path: &str) -> io::Result<PrivateKeyDer<'static>> {
    let file = File::open(path)
        .map_err(|e| io::Error::new(e.kind(), format!("{path}: {e}")))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{path}: no private key found")))
}

// ─── NoVerifier (skip-verify mode) ──────────────────────────────────────────

#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
