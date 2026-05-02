//! User-supplied cert-bundle override and download-URL override.
//!
//! The WoW Classic family ships cert bundles in two delivery modes:
//!
//! - **Embedded** (1.14.0/.1/.2, 2.5.3): a complete signed bundle in
//!   `.rdata`, located by the `{"Created":` JSON envelope start.
//!   ~32 KB slot.
//! - **Downloaded** (1.13.2, plus implicitly any client whose embedded
//!   bundle was not yet served when launched): the client fetches a
//!   bundle from a URL embedded in `.rdata`. The default URL is
//!   `http://nydus.battle.net/Bnet/zxx/client/bgs-key-fingerprint`
//!   (59-byte slot in the binary).
//!
//! Both modes pin the bundle to an RSA-2048 signing modulus also stored
//! in `.rdata`. Any user-supplied bundle MUST be signed by a key whose
//! public modulus matches the modulus rewritten into the binary by
//! the existing `--rsa-file` / `--rsa-hex` patches.
//!
//! This module owns the validation of the two user-facing flags:
//! `--cert-bundle FILE` and `--cert-bundle-url URL`. Both are
//! independent: a user can override the download URL without supplying
//! a bundle (delegating bundle preparation to whoever runs the
//! download endpoint), or supply a bundle without changing the URL
//! (relevant for embedded-mode clients).

use crate::errors::{ErrorCategory, WowPatcherError};
use std::fs;
use std::path::Path;

/// Maximum embedded-bundle slot size (bytes).
///
/// All builds with an embedded bundle (1.14.0, 1.14.1, 1.14.2, 2.5.3)
/// allocate exactly this many bytes. The total slot including
/// alignment NUL padding is 32768; we cap at 32761 to match the
/// shipping bundle size and leave the alignment padding alone.
pub const MAX_EMBEDDED_BUNDLE_SIZE: usize = 32761;

/// Maximum cert-bundle URL slot size (bytes).
///
/// The original URL `http://nydus.battle.net/Bnet/zxx/client/bgs-key-fingerprint`
/// is 59 bytes. Replacement URLs must fit within this slot and are
/// NUL-padded.
pub const MAX_CERT_BUNDLE_URL_LEN: usize = 59;

/// Optional cert-bundle overrides parsed from CLI / library input.
#[derive(Debug, Clone, Default)]
pub struct CertBundleConfig {
    bundle_bytes: Option<Vec<u8>>,
    download_url: Option<String>,
}

impl CertBundleConfig {
    /// Load a signed cert bundle from a file.
    ///
    /// The file's bytes are passed through verbatim; the patcher
    /// neither parses the JSON nor verifies the embedded signature.
    /// The user is responsible for producing a bundle whose signature
    /// validates against the public modulus rewritten into the binary.
    /// (Bundle generation tools live elsewhere -- e.g.
    /// `wow-classic-1132-poc/scripts/gen-cert-bundle.py`.)
    pub fn with_bundle_from_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, WowPatcherError> {
        let bytes = fs::read(path.as_ref()).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::FileOperationError,
                format!(
                    "Failed to read cert-bundle file at {}",
                    path.as_ref().display()
                ),
                e,
            )
        })?;
        if bytes.is_empty() {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "cert-bundle file is empty",
            ));
        }
        if bytes.len() > MAX_EMBEDDED_BUNDLE_SIZE {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "cert-bundle is {} bytes; max is {} (the embedded slot size in 1.14.0+ binaries)",
                    bytes.len(),
                    MAX_EMBEDDED_BUNDLE_SIZE
                ),
            ));
        }
        // Surface a basic structural sanity check: bundle must start
        // with the envelope marker so we don't silently inject junk
        // that the client immediately rejects.
        if !bytes.starts_with(b"{\"Created\":") {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "cert-bundle does not start with the expected '{\"Created\":' envelope (file may not be a valid signed bundle)",
            ));
        }
        self.bundle_bytes = Some(bytes);
        Ok(self)
    }

    /// Set the cert-bundle download URL (validated for length + scheme).
    ///
    /// The URL replaces the verbatim 59-byte literal in the binary. It
    /// must be ≤ 59 bytes and start with `http://` or `https://`.
    pub fn with_download_url<S: AsRef<str>>(mut self, url: S) -> Result<Self, WowPatcherError> {
        let url = url.as_ref();
        if url.is_empty() {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "cert-bundle URL is empty",
            ));
        }
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "cert-bundle URL must start with http:// or https://",
            ));
        }
        if url.len() > MAX_CERT_BUNDLE_URL_LEN {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "cert-bundle URL is {} bytes; max is {} (the slot size of the original URL)",
                    url.len(),
                    MAX_CERT_BUNDLE_URL_LEN
                ),
            ));
        }
        if !url.is_ascii() {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "cert-bundle URL must be ASCII",
            ));
        }
        self.download_url = Some(url.to_string());
        Ok(self)
    }

    /// Bundle bytes to inject (if user supplied one).
    pub fn bundle_bytes(&self) -> Option<&[u8]> {
        self.bundle_bytes.as_deref()
    }

    /// Download URL to rewrite in the binary (if user supplied one).
    pub fn download_url(&self) -> Option<&str> {
        self.download_url.as_deref()
    }

    /// Return true if either override is configured.
    pub fn is_active(&self) -> bool {
        self.bundle_bytes.is_some() || self.download_url.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(bytes: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f
    }

    #[test]
    fn default_is_empty_and_inactive() {
        let cfg = CertBundleConfig::default();
        assert!(!cfg.is_active());
        assert!(cfg.bundle_bytes().is_none());
        assert!(cfg.download_url().is_none());
    }

    #[test]
    fn loads_valid_bundle() {
        // Minimal valid-looking envelope start (rest is fake content).
        let mut content = b"{\"Created\":1612222344,\"Certificates\":[]}".to_vec();
        // Pad to a non-trivial size to exercise the read path.
        content.resize(1024, 0);
        let f = write_temp(&content);
        let cfg = CertBundleConfig::default()
            .with_bundle_from_file(f.path())
            .unwrap();
        assert_eq!(cfg.bundle_bytes().unwrap().len(), 1024);
        assert!(cfg.is_active());
    }

    #[test]
    fn rejects_empty_bundle_file() {
        let f = write_temp(b"");
        let err = CertBundleConfig::default()
            .with_bundle_from_file(f.path())
            .unwrap_err();
        assert!(format!("{}", err).contains("empty"));
    }

    #[test]
    fn rejects_oversize_bundle() {
        let content = vec![0u8; MAX_EMBEDDED_BUNDLE_SIZE + 1];
        let f = write_temp(&content);
        let err = CertBundleConfig::default()
            .with_bundle_from_file(f.path())
            .unwrap_err();
        assert!(format!("{}", err).contains("max is"));
    }

    #[test]
    fn rejects_bundle_with_wrong_envelope() {
        let f = write_temp(b"not a bundle");
        let err = CertBundleConfig::default()
            .with_bundle_from_file(f.path())
            .unwrap_err();
        assert!(format!("{}", err).contains("envelope"));
    }

    #[test]
    fn accepts_valid_url() {
        let cfg = CertBundleConfig::default()
            .with_download_url("https://example.com/bundle")
            .unwrap();
        assert_eq!(cfg.download_url().unwrap(), "https://example.com/bundle");
        assert!(cfg.is_active());
    }

    #[test]
    fn rejects_url_without_scheme() {
        let err = CertBundleConfig::default()
            .with_download_url("example.com/bundle")
            .unwrap_err();
        assert!(format!("{}", err).contains("http://"));
    }

    #[test]
    fn rejects_oversize_url() {
        let huge = format!("https://{}", "a".repeat(60));
        let err = CertBundleConfig::default()
            .with_download_url(&huge)
            .unwrap_err();
        assert!(format!("{}", err).contains("max is 59"));
    }

    #[test]
    fn rejects_empty_url() {
        let err = CertBundleConfig::default()
            .with_download_url("")
            .unwrap_err();
        assert!(format!("{}", err).contains("empty"));
    }

    #[test]
    fn url_at_slot_max_size_accepted() {
        // Exactly 59 bytes
        let url = "http://0123456789012345678901234567890123456789012345678.io";
        assert_eq!(url.len(), MAX_CERT_BUNDLE_URL_LEN);
        let cfg = CertBundleConfig::default()
            .with_download_url(url)
            .unwrap();
        assert_eq!(cfg.download_url().unwrap().len(), MAX_CERT_BUNDLE_URL_LEN);
    }
}
