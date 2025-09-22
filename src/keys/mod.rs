use crate::errors::{ErrorCategory, WowPatcherError};
use crate::trinity::{CRYPTO_ED25519_PUBLIC_KEY, RSA_MODULUS};
use std::fs;
use std::path::Path;

/// Configuration for cryptographic keys used in patching
#[derive(Debug, Clone)]
pub struct KeyConfig {
    /// RSA modulus (256 bytes) for authentication
    pub rsa_modulus: Vec<u8>,
    /// Ed25519 public key (32 bytes) for modern authentication
    pub ed25519_public_key: Vec<u8>,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self::trinity_core()
    }
}

impl KeyConfig {
    /// Create a new KeyConfig with TrinityCore default keys
    pub fn trinity_core() -> Self {
        Self {
            rsa_modulus: RSA_MODULUS.to_vec(),
            ed25519_public_key: CRYPTO_ED25519_PUBLIC_KEY.to_vec(),
        }
    }

    /// Create a new KeyConfig with custom keys
    pub fn custom(
        rsa_modulus: Vec<u8>,
        ed25519_public_key: Vec<u8>,
    ) -> Result<Self, WowPatcherError> {
        let config = Self {
            rsa_modulus,
            ed25519_public_key,
        };
        config.validate()?;
        Ok(config)
    }

    /// Load RSA modulus from a binary file
    pub fn with_rsa_from_file<P: AsRef<Path>>(mut self, path: P) -> Result<Self, WowPatcherError> {
        let rsa_data = fs::read(&path).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::FileOperationError,
                format!("Failed to read RSA modulus file: {:?}", path.as_ref()),
                e,
            )
        })?;

        if rsa_data.len() != 256 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "RSA modulus must be exactly 256 bytes, got {} bytes",
                    rsa_data.len()
                ),
            ));
        }

        self.rsa_modulus = rsa_data;
        self.validate()?;
        Ok(self)
    }

    /// Load Ed25519 public key from a binary file
    pub fn with_ed25519_from_file<P: AsRef<Path>>(
        mut self,
        path: P,
    ) -> Result<Self, WowPatcherError> {
        let ed25519_data = fs::read(&path).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::FileOperationError,
                format!(
                    "Failed to read Ed25519 public key file: {:?}",
                    path.as_ref()
                ),
                e,
            )
        })?;

        if ed25519_data.len() != 32 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "Ed25519 public key must be exactly 32 bytes, got {} bytes",
                    ed25519_data.len()
                ),
            ));
        }

        self.ed25519_public_key = ed25519_data;
        self.validate()?;
        Ok(self)
    }

    /// Load RSA modulus from a hex string
    pub fn with_rsa_from_hex(mut self, hex_str: &str) -> Result<Self, WowPatcherError> {
        let cleaned_hex = hex_str
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();

        if cleaned_hex.len() != 512 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "RSA modulus hex string must be exactly 512 hex characters (256 bytes), got {} characters",
                    cleaned_hex.len()
                ),
            ));
        }

        let rsa_data = hex::decode(&cleaned_hex).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::ValidationError,
                "Invalid hex format for RSA modulus",
                e,
            )
        })?;

        self.rsa_modulus = rsa_data;
        self.validate()?;
        Ok(self)
    }

    /// Load Ed25519 public key from a hex string
    pub fn with_ed25519_from_hex(mut self, hex_str: &str) -> Result<Self, WowPatcherError> {
        let cleaned_hex = hex_str
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>();

        if cleaned_hex.len() != 64 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "Ed25519 public key hex string must be exactly 64 hex characters (32 bytes), got {} characters",
                    cleaned_hex.len()
                ),
            ));
        }

        let ed25519_data = hex::decode(&cleaned_hex).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::ValidationError,
                "Invalid hex format for Ed25519 public key",
                e,
            )
        })?;

        self.ed25519_public_key = ed25519_data;
        self.validate()?;
        Ok(self)
    }

    /// Get the RSA modulus as a byte slice
    pub fn rsa_modulus(&self) -> &[u8] {
        &self.rsa_modulus
    }

    /// Get the Ed25519 public key as a byte slice
    pub fn ed25519_public_key(&self) -> &[u8] {
        &self.ed25519_public_key
    }

    /// Validate that the keys meet cryptographic requirements
    pub fn validate(&self) -> Result<(), WowPatcherError> {
        // Validate RSA modulus
        if self.rsa_modulus.len() != 256 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "RSA modulus must be exactly 256 bytes, got {}",
                    self.rsa_modulus.len()
                ),
            ));
        }

        // Check that RSA modulus is not all zeros
        if self.rsa_modulus.iter().all(|&b| b == 0) {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "RSA modulus cannot be all zeros",
            ));
        }

        // Check that RSA modulus has reasonable entropy
        let first_byte = self.rsa_modulus[0];
        if self.rsa_modulus.iter().all(|&b| b == first_byte) {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "RSA modulus cannot contain all identical bytes",
            ));
        }

        // Validate Ed25519 public key
        if self.ed25519_public_key.len() != 32 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "Ed25519 public key must be exactly 32 bytes, got {}",
                    self.ed25519_public_key.len()
                ),
            ));
        }

        // Check that Ed25519 key is not all zeros
        if self.ed25519_public_key.iter().all(|&b| b == 0) {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "Ed25519 public key cannot be all zeros",
            ));
        }

        // Check that Ed25519 key has reasonable entropy
        let first_byte = self.ed25519_public_key[0];
        if self.ed25519_public_key.iter().all(|&b| b == first_byte) {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "Ed25519 public key cannot contain all identical bytes",
            ));
        }

        Ok(())
    }

    /// Check if this configuration uses the default TrinityCore keys
    pub fn is_trinity_core(&self) -> bool {
        self.rsa_modulus == RSA_MODULUS && self.ed25519_public_key == CRYPTO_ED25519_PUBLIC_KEY
    }

    /// Display information about the keys (first 8 bytes for identification)
    pub fn display_info(&self) -> String {
        format!(
            "RSA modulus: {}... ({} bytes), Ed25519 key: {}... ({} bytes)",
            hex::encode(&self.rsa_modulus[..8]),
            self.rsa_modulus.len(),
            hex::encode(&self.ed25519_public_key[..8]),
            self.ed25519_public_key.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_trinity_core_keys() {
        let config = KeyConfig::default();
        assert!(config.is_trinity_core());
        assert_eq!(config.rsa_modulus().len(), 256);
        assert_eq!(config.ed25519_public_key().len(), 32);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_custom_keys() {
        // Create test keys with some variation to pass entropy validation
        let mut custom_rsa = vec![0x42; 256];
        custom_rsa[0] = 0x43; // Make first byte different
        custom_rsa[255] = 0x44; // Make last byte different

        let mut custom_ed25519 = vec![0x37; 32];
        custom_ed25519[0] = 0x38; // Make first byte different
        custom_ed25519[31] = 0x39; // Make last byte different

        let config = KeyConfig::custom(custom_rsa.clone(), custom_ed25519.clone()).unwrap();
        assert!(!config.is_trinity_core());
        assert_eq!(config.rsa_modulus(), &custom_rsa);
        assert_eq!(config.ed25519_public_key(), &custom_ed25519);
    }

    #[test]
    fn test_invalid_key_sizes() {
        // Invalid RSA size
        let result = KeyConfig::custom(vec![0x42; 255], vec![0x37; 32]);
        assert!(result.is_err());

        // Invalid Ed25519 size
        let result = KeyConfig::custom(vec![0x42; 256], vec![0x37; 31]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_zero_keys() {
        let result = KeyConfig::custom(vec![0x00; 256], vec![0x37; 32]);
        assert!(result.is_err());

        let result = KeyConfig::custom(vec![0x42; 256], vec![0x00; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_identical_byte_keys() {
        // Test that keys with all identical bytes are rejected
        let result = KeyConfig::custom(vec![0x42; 256], vec![0x37; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("identical bytes"));
    }

    #[test]
    fn test_hex_loading() {
        // Create hex strings with variation to pass entropy validation
        let mut rsa_hex = String::new();
        for i in 0..256 {
            if i == 0 {
                rsa_hex.push_str("43");
            } else if i == 255 {
                rsa_hex.push_str("44");
            } else {
                rsa_hex.push_str("42");
            }
        }

        let mut ed25519_hex = String::new();
        for i in 0..32 {
            if i == 0 {
                ed25519_hex.push_str("38");
            } else if i == 31 {
                ed25519_hex.push_str("39");
            } else {
                ed25519_hex.push_str("37");
            }
        }

        let config = KeyConfig::trinity_core()
            .with_rsa_from_hex(&rsa_hex)
            .unwrap()
            .with_ed25519_from_hex(&ed25519_hex)
            .unwrap();

        assert_eq!(config.rsa_modulus()[0], 0x43);
        assert_eq!(config.rsa_modulus()[1], 0x42);
        assert_eq!(config.rsa_modulus()[255], 0x44);
        assert_eq!(config.ed25519_public_key()[0], 0x38);
        assert_eq!(config.ed25519_public_key()[1], 0x37);
        assert_eq!(config.ed25519_public_key()[31], 0x39);
    }

    #[test]
    fn test_file_loading() -> Result<(), Box<dyn std::error::Error>> {
        // Create temporary files
        let mut rsa_file = NamedTempFile::new()?;
        let mut ed25519_file = NamedTempFile::new()?;

        // Create test keys with variation to pass entropy validation
        let mut custom_rsa = vec![0x42; 256];
        custom_rsa[0] = 0x43;
        custom_rsa[255] = 0x44;

        let mut custom_ed25519 = vec![0x37; 32];
        custom_ed25519[0] = 0x38;
        custom_ed25519[31] = 0x39;

        rsa_file.write_all(&custom_rsa)?;
        ed25519_file.write_all(&custom_ed25519)?;

        let config = KeyConfig::trinity_core()
            .with_rsa_from_file(rsa_file.path())?
            .with_ed25519_from_file(ed25519_file.path())?;

        assert_eq!(config.rsa_modulus(), &custom_rsa);
        assert_eq!(config.ed25519_public_key(), &custom_ed25519);

        Ok(())
    }

    #[test]
    fn test_display_info() {
        let config = KeyConfig::trinity_core();
        let info = config.display_info();
        assert!(info.contains("RSA modulus: 5fd6800b"));
        assert!(info.contains("Ed25519 key: 02596f0d"));
        assert!(info.contains("256 bytes"));
        assert!(info.contains("32 bytes"));
    }
}
