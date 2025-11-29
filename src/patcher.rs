//! High-level API for patching World of Warcraft executables.
//!
//! This module provides a builder-style API for patching WoW clients to work with
//! TrinityCore private servers.
//!
//! # Examples
//!
//! Basic usage with TrinityCore defaults:
//!
//! ```no_run
//! use wow_patcher::Patcher;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! Patcher::new("Wow.exe")
//!     .output("Wow-patched.exe")
//!     .trinity_core_keys()
//!     .patch()?;
//! # Ok(())
//! # }
//! ```
//!
//! Advanced usage with custom configuration:
//!
//! ```no_run
//! use wow_patcher::Patcher;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let patcher = Patcher::new("Wow.exe")
//!     .output("Wow-patched.exe")
//!     .custom_keys_from_hex(
//!         "91D59BB7D4E183A5...", // 512 hex chars for RSA
//!         "15D618BD7DB577BD..."  // 64 hex chars for Ed25519
//!     )?;
//!
//! patcher
//!     .custom_cdn("http://my-cdn.local")
//!     .verbose(true)
//!     .strip_codesign(true)
//!     .patch()?;
//! # Ok(())
//! # }
//! ```

use crate::cmd::execute::execute_patch;
use crate::errors::WowPatcherError;
use crate::keys::KeyConfig;
use std::path::{Path, PathBuf};

/// A builder for patching World of Warcraft executables.
///
/// This provides a high-level, ergonomic API for configuring and executing
/// binary patches on WoW clients.
#[derive(Debug, Clone)]
pub struct Patcher {
    /// Path to input WoW executable
    input: PathBuf,
    /// Path to output patched executable (optional, defaults to input + "-patched")
    output: Option<PathBuf>,
    /// Key configuration (RSA + Ed25519)
    key_config: Option<KeyConfig>,
    /// Custom version URL
    version_url: Option<String>,
    /// Custom CDNs URL
    cdns_url: Option<String>,
    /// Dry run mode (preview changes without modifying files)
    dry_run: bool,
    /// Strip macOS code signing
    strip_codesign: bool,
    /// Verbose output
    verbose: bool,
}

impl Patcher {
    /// Create a new `Patcher` for the given WoW executable.
    ///
    /// # Arguments
    ///
    /// * `input` - Path to the WoW executable to patch
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// let patcher = Patcher::new("Wow.exe");
    /// ```
    pub fn new<P: AsRef<Path>>(input: P) -> Self {
        Self {
            input: input.as_ref().to_path_buf(),
            output: None,
            key_config: None,
            version_url: None,
            cdns_url: None,
            dry_run: false,
            strip_codesign: false,
            verbose: false,
        }
    }

    /// Set the output path for the patched executable.
    ///
    /// If not specified, defaults to the input filename with "-patched" appended.
    ///
    /// # Arguments
    ///
    /// * `output` - Path where the patched executable will be written
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// let patcher = Patcher::new("Wow.exe")
    ///     .output("Wow-tc.exe");
    /// ```
    pub fn output<P: AsRef<Path>>(mut self, output: P) -> Self {
        self.output = Some(output.as_ref().to_path_buf());
        self
    }

    /// Use TrinityCore's default RSA and Ed25519 keys.
    ///
    /// This is the most common configuration for TrinityCore private servers.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .trinity_core_keys()
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn trinity_core_keys(mut self) -> Self {
        self.key_config = Some(KeyConfig::trinity_core());
        self
    }

    /// Use custom RSA and Ed25519 keys from byte slices.
    ///
    /// # Arguments
    ///
    /// * `rsa_modulus` - 256-byte RSA modulus
    /// * `ed25519_public_key` - 32-byte Ed25519 public key
    ///
    /// # Errors
    ///
    /// Returns an error if the key sizes are invalid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let rsa_key = vec![0u8; 256];
    /// let ed25519_key = vec![0u8; 32];
    ///
    /// Patcher::new("Wow.exe")
    ///     .custom_keys(&rsa_key, &ed25519_key)?
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_keys(
        mut self,
        rsa_modulus: &[u8],
        ed25519_public_key: &[u8],
    ) -> Result<Self, WowPatcherError> {
        self.key_config = Some(KeyConfig::new(rsa_modulus, ed25519_public_key)?);
        Ok(self)
    }

    /// Use custom keys from hex strings.
    ///
    /// # Arguments
    ///
    /// * `rsa_hex` - 512 hex characters (256 bytes) for RSA modulus
    /// * `ed25519_hex` - 64 hex characters (32 bytes) for Ed25519 public key
    ///
    /// # Errors
    ///
    /// Returns an error if the hex strings are invalid or have wrong lengths.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .custom_keys_from_hex(
    ///         "91D59BB7D4E183A5...",
    ///         "15D618BD7DB577BD..."
    ///     )?
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_keys_from_hex(
        mut self,
        rsa_hex: &str,
        ed25519_hex: &str,
    ) -> Result<Self, WowPatcherError> {
        self.key_config = Some(KeyConfig::from_hex(rsa_hex, ed25519_hex)?);
        Ok(self)
    }

    /// Use custom keys from files.
    ///
    /// # Arguments
    ///
    /// * `rsa_file` - Path to 256-byte RSA modulus file
    /// * `ed25519_file` - Path to 32-byte Ed25519 public key file
    ///
    /// # Errors
    ///
    /// Returns an error if files cannot be read or have invalid sizes.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .custom_keys_from_files("rsa.bin", "ed25519.bin")?
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_keys_from_files<P: AsRef<Path>>(
        mut self,
        rsa_file: P,
        ed25519_file: P,
    ) -> Result<Self, WowPatcherError> {
        self.key_config = Some(KeyConfig::from_files(
            rsa_file.as_ref(),
            ed25519_file.as_ref(),
        )?);
        Ok(self)
    }

    /// Set a custom CDN URL for version and CDNs endpoints.
    ///
    /// This sets both version and CDNs URLs to the same base.
    ///
    /// # Arguments
    ///
    /// * `cdn_url` - Base URL for the CDN (e.g., "http://my-cdn.local")
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .custom_cdn("http://my-cdn.local")
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn custom_cdn<S: Into<String>>(mut self, cdn_url: S) -> Self {
        let url = cdn_url.into();
        self.version_url = Some(format!("{}/{{region}}/{{product}}/versions", url));
        self.cdns_url = Some(format!("{}/{{region}}/{{product}}/cdns", url));
        self
    }

    /// Set a custom version URL.
    ///
    /// # Arguments
    ///
    /// * `url` - Custom version URL
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .version_url("http://my-cdn.local/{region}/{product}/versions")
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn version_url<S: Into<String>>(mut self, url: S) -> Self {
        self.version_url = Some(url.into());
        self
    }

    /// Set a custom CDNs URL.
    ///
    /// # Arguments
    ///
    /// * `url` - Custom CDNs URL
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .cdns_url("http://my-cdn.local/{region}/{product}/cdns")
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn cdns_url<S: Into<String>>(mut self, url: S) -> Self {
        self.cdns_url = Some(url.into());
        self
    }

    /// Enable dry run mode (preview changes without modifying files).
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable dry run mode
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .dry_run(true)
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Enable stripping of macOS code signing.
    ///
    /// This is required on macOS for patched executables to run.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to strip code signing
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.app/Contents/MacOS/World of Warcraft")
    ///     .strip_codesign(true)
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn strip_codesign(mut self, enabled: bool) -> Self {
        self.strip_codesign = enabled;
        self
    }

    /// Enable verbose output.
    ///
    /// # Arguments
    ///
    /// * `enabled` - Whether to enable verbose logging
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .verbose(true)
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn verbose(mut self, enabled: bool) -> Self {
        self.verbose = enabled;
        self
    }

    /// Execute the patching operation.
    ///
    /// This applies all configured patches to the WoW executable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The input file doesn't exist or is invalid
    /// - No key configuration was set
    /// - Pattern matching fails
    /// - File operations fail
    /// - Patterns are found in non-patchable sections
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use wow_patcher::Patcher;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// Patcher::new("Wow.exe")
    ///     .output("Wow-patched.exe")
    ///     .trinity_core_keys()
    ///     .patch()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn patch(self) -> Result<(), WowPatcherError> {
        // Determine output path
        let output = self.output.unwrap_or_else(|| {
            let input_str = self.input.to_string_lossy();
            let output_str = if input_str.ends_with(".exe") {
                input_str.replace(".exe", "-patched.exe")
            } else {
                format!("{}-patched", input_str)
            };
            PathBuf::from(output_str)
        });

        // Use TrinityCore keys if no custom keys specified
        let key_config = self.key_config.unwrap_or_else(KeyConfig::trinity_core);

        // Execute the patch
        execute_patch(
            &self.input,
            &output,
            key_config,
            self.version_url.as_deref(),
            self.cdns_url.as_deref(),
            self.dry_run,
            self.strip_codesign,
            self.verbose,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patcher_new() {
        let patcher = Patcher::new("Wow.exe");
        assert_eq!(patcher.input, PathBuf::from("Wow.exe"));
        assert!(patcher.output.is_none());
        assert!(patcher.key_config.is_none());
        assert!(!patcher.dry_run);
        assert!(!patcher.verbose);
    }

    #[test]
    fn test_patcher_output() {
        let patcher = Patcher::new("Wow.exe").output("custom-out.exe");
        assert_eq!(patcher.output, Some(PathBuf::from("custom-out.exe")));
    }

    #[test]
    fn test_patcher_trinity_core_keys() {
        let patcher = Patcher::new("Wow.exe").trinity_core_keys();
        assert!(patcher.key_config.is_some());
        assert!(patcher.key_config.unwrap().is_trinity_core());
    }

    #[test]
    fn test_patcher_custom_keys() {
        // Create test keys with variation to pass entropy validation
        let mut rsa = vec![0x42u8; 256];
        rsa[0] = 0x43;
        rsa[255] = 0x44;
        let mut ed25519 = vec![0x37u8; 32];
        ed25519[0] = 0x38;
        ed25519[31] = 0x39;

        let patcher = Patcher::new("Wow.exe").custom_keys(&rsa, &ed25519).unwrap();
        assert!(patcher.key_config.is_some());
        assert!(!patcher.key_config.unwrap().is_trinity_core());
    }

    #[test]
    fn test_patcher_custom_keys_invalid_size() {
        let mut rsa = vec![0x42u8; 100]; // Wrong size
        rsa[0] = 0x43;
        let mut ed25519 = vec![0x37u8; 32];
        ed25519[0] = 0x38;
        let result = Patcher::new("Wow.exe").custom_keys(&rsa, &ed25519);
        assert!(result.is_err());
    }

    #[test]
    fn test_patcher_custom_cdn() {
        let patcher = Patcher::new("Wow.exe").custom_cdn("http://test.local");
        assert!(patcher.version_url.is_some());
        assert!(patcher.cdns_url.is_some());
        assert!(patcher.version_url.unwrap().contains("http://test.local"));
    }

    #[test]
    fn test_patcher_version_url() {
        let patcher = Patcher::new("Wow.exe").version_url("http://custom/versions");
        assert_eq!(
            patcher.version_url,
            Some("http://custom/versions".to_string())
        );
    }

    #[test]
    fn test_patcher_cdns_url() {
        let patcher = Patcher::new("Wow.exe").cdns_url("http://custom/cdns");
        assert_eq!(patcher.cdns_url, Some("http://custom/cdns".to_string()));
    }

    #[test]
    fn test_patcher_dry_run() {
        let patcher = Patcher::new("Wow.exe").dry_run(true);
        assert!(patcher.dry_run);
    }

    #[test]
    fn test_patcher_strip_codesign() {
        let patcher = Patcher::new("Wow.exe").strip_codesign(true);
        assert!(patcher.strip_codesign);
    }

    #[test]
    fn test_patcher_verbose() {
        let patcher = Patcher::new("Wow.exe").verbose(true);
        assert!(patcher.verbose);
    }

    #[test]
    fn test_patcher_builder_chain() {
        let patcher = Patcher::new("Wow.exe")
            .output("out.exe")
            .trinity_core_keys()
            .custom_cdn("http://test.local")
            .verbose(true)
            .dry_run(true)
            .strip_codesign(true);

        assert_eq!(patcher.output, Some(PathBuf::from("out.exe")));
        assert!(patcher.key_config.is_some());
        assert!(patcher.version_url.is_some());
        assert!(patcher.cdns_url.is_some());
        assert!(patcher.verbose);
        assert!(patcher.dry_run);
        assert!(patcher.strip_codesign);
    }

    #[test]
    fn test_patcher_default_output_exe() {
        let patcher = Patcher::new("Wow.exe");
        // We can't test patch() directly without a real file, but we can test the logic
        let input_str = patcher.input.to_string_lossy();
        let expected = input_str.replace(".exe", "-patched.exe");
        assert_eq!(expected, "Wow-patched.exe");
    }

    #[test]
    fn test_patcher_default_output_no_extension() {
        let patcher = Patcher::new("/path/to/WorldOfWarcraft");
        let input_str = patcher.input.to_string_lossy();
        let expected = format!("{}-patched", input_str);
        assert_eq!(expected, "/path/to/WorldOfWarcraft-patched");
    }
}
