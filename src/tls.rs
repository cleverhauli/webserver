//! Turning a certificate and private key into something that can accept
//! HTTPS connections. All the cryptography is done by the rustls library.

use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::crypto::ring::default_provider;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

/// Load a PEM certificate chain and PEM private key, and build an acceptor.
/// Every problem comes back as a message that says what to fix.
pub fn build_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, String> {
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| format!("could not read certificate file '{cert_path}': {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid certificate in '{cert_path}': {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificate found in '{cert_path}'"));
    }

    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|e| format!("could not read private key '{key_path}': {e}"))?;

    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("the certificate and private key do not work together: {e}"))?;

    // We only speak HTTP/1.1, and say so, so browsers do not try HTTP/2.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// A temporary folder, deleted when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let path =
                std::env::temp_dir().join(format!("webserver-tls-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Make a self-signed certificate and key. Returns their file paths.
    fn make_certificate(dir: &Path, name: &str) -> (String, String) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_path = dir.join(format!("{name}-cert.pem"));
        let key_path = dir.join(format!("{name}-key.pem"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
        (
            cert_path.to_str().unwrap().to_string(),
            key_path.to_str().unwrap().to_string(),
        )
    }

    fn error_of(result: Result<TlsAcceptor, String>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(message) => message,
        }
    }

    #[test]
    fn a_matching_certificate_and_key_load() {
        let dir = TempDir::new("valid");
        let (cert, key) = make_certificate(dir.path(), "a");
        assert!(build_acceptor(&cert, &key).is_ok());
    }

    #[test]
    fn a_missing_certificate_file_is_reported() {
        let dir = TempDir::new("no-cert");
        let (_, key) = make_certificate(dir.path(), "a");
        let message = error_of(build_acceptor("does-not-exist.pem", &key));
        assert!(
            message.contains("could not read certificate file"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_key_file_is_reported() {
        let dir = TempDir::new("no-key");
        let (cert, _) = make_certificate(dir.path(), "a");
        let message = error_of(build_acceptor(&cert, "does-not-exist.pem"));
        assert!(message.contains("private key"), "{message}");
    }

    #[test]
    fn a_file_without_a_certificate_is_reported() {
        let dir = TempDir::new("garbage");
        let (_, key) = make_certificate(dir.path(), "a");
        let garbage = dir.path().join("garbage.pem");
        std::fs::write(&garbage, "this is not a certificate").unwrap();

        let message = error_of(build_acceptor(garbage.to_str().unwrap(), &key));
        assert!(message.contains("no certificate found"), "{message}");
    }

    #[test]
    fn a_certificate_in_place_of_the_key_is_reported() {
        let dir = TempDir::new("swapped");
        let (cert, _) = make_certificate(dir.path(), "a");
        let message = error_of(build_acceptor(&cert, &cert));
        assert!(message.contains("private key"), "{message}");
    }

    #[test]
    fn a_key_that_belongs_to_another_certificate_is_rejected() {
        let dir = TempDir::new("mismatch");
        let (cert_a, _) = make_certificate(dir.path(), "a");
        let (_, key_b) = make_certificate(dir.path(), "b");
        assert!(build_acceptor(&cert_a, &key_b).is_err());
    }
}
