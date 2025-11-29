//! World of Warcraft client patcher for TrinityCore private servers.
//!
//! This library provides functionality to patch WoW retail clients to work with
//! TrinityCore-based private servers by modifying authentication keys, portal connections,
//! and CDN endpoints.
//!
//! # Library Usage
//!
//! The primary API is the [`Patcher`] builder which provides an ergonomic interface:
//!
//! ```no_run
//! use wow_patcher::Patcher;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Simple usage with TrinityCore defaults
//! Patcher::new("Wow.exe")
//!     .output("Wow-patched.exe")
//!     .trinity_core_keys()
//!     .patch()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Advanced Configuration
//!
//! ```no_run
//! use wow_patcher::Patcher;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let patcher = Patcher::new("Wow.exe")
//!     .output("Wow-custom.exe")
//!     .custom_keys_from_files("rsa.bin", "ed25519.bin")?;
//!
//! patcher
//!     .custom_cdn("http://my-cdn.local")
//!     .verbose(true)
//!     .strip_codesign(true)  // macOS only
//!     .patch()?;
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! - **RSA Key Replacement**: Patches RSA modulus (multiple patterns: ConnectTo, Signature, Crypto)
//! - **Ed25519 Key Replacement**: Patches Ed25519 public key for modern clients
//! - **Portal Patching**: Removes Battle.net portal connections
//! - **CDN Redirection**: Custom version and CDN URLs
//! - **Section Validation**: Ensures patches only target safe data sections (.rdata/.data)
//! - **Cross-Platform**: Windows PE and macOS Mach-O support
//! - **Code Signing Removal**: Automatic macOS code signature stripping
//!
//! # Low-Level API
//!
//! For advanced use cases, you can use the lower-level modules directly:
//!
//! - [`binary`] - Binary patching primitives and section validation
//! - [`keys`] - Cryptographic key management
//! - [`patterns`] - Pattern definitions for binary search
//! - [`errors`] - Error types
//!
//! # CLI Feature
//!
//! The library includes an optional CLI binary. To use only the library without CLI dependencies:
//!
//! ```toml
//! [dependencies]
//! wow-patcher = { version = "0.1", default-features = false }
//! ```

pub mod binary;
#[cfg(feature = "cli")]
pub mod cli;
pub mod cmd;
pub mod errors;
pub mod keys;
pub mod patcher;
pub mod patterns;
pub mod platform;
pub mod trinity;
pub mod version;

// Re-export the main API
pub use errors::WowPatcherError;
pub use keys::KeyConfig;
pub use patcher::Patcher;
