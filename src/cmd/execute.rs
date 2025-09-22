use crate::binary::{PatternExt, patch};
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patterns::{
    cdns_url_pattern, connect_to_modulus_pattern, crypto_ed_public_key_pattern, portal_pattern,
    version_url_pattern,
};
use crate::platform::{detect_client_type, remove_codesigning_signature};
use crate::trinity::{create_url_replacement, get_cdns_url, get_version_url};
use std::fs;
use std::path::Path;

pub fn execute_patch(
    input_path: &Path,
    output_path: &Path,
    key_config: KeyConfig,
    version_url: Option<&str>,
    cdns_url: Option<&str>,
    dry_run: bool,
    strip_codesign: bool,
    verbose: bool,
) -> Result<(), WowPatcherError> {
    // Validate input file
    if !input_path.exists() {
        return Err(WowPatcherError::new(
            ErrorCategory::FileOperationError,
            "WoW executable file not found at specified location",
        ));
    }

    let metadata = fs::metadata(input_path).map_err(|e| {
        WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "Unable to access WoW executable file",
            e,
        )
    })?;

    // Validate file size
    const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
    if metadata.len() > MAX_FILE_SIZE {
        return Err(WowPatcherError::new(
            ErrorCategory::ValidationError,
            format!(
                "File size {:.2} MB exceeds maximum allowed size of {:.0} MB",
                metadata.len() as f64 / (1024.0 * 1024.0),
                MAX_FILE_SIZE as f64 / (1024.0 * 1024.0)
            ),
        ));
    }

    if metadata.len() == 0 {
        return Err(WowPatcherError::new(
            ErrorCategory::ValidationError,
            "File is empty - not a valid WoW executable",
        ));
    }

    if metadata.len() < 1024 {
        return Err(WowPatcherError::new(
            ErrorCategory::ValidationError,
            format!(
                "File too small ({} bytes) to be a valid executable",
                metadata.len()
            ),
        ));
    }

    // Detect client type
    let client_type = detect_client_type(input_path.to_str().unwrap_or(""));

    // Read the file
    let mut data = fs::read(input_path).map_err(|e| {
        WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "Failed to read WoW executable file",
            e,
        )
    })?;

    if dry_run {
        println!("🔍 Dry Run Mode - No files will be modified");
        println!();
        println!("Input file:  {:?}", input_path);
        println!("Output file: {:?}", output_path);
        println!(
            "File size:   {:.2} MB",
            metadata.len() as f64 / (1024.0 * 1024.0)
        );
        println!("Client type: {}", client_type);
        println!();
        println!("Patches that would be applied:");

        // Check each pattern
        let mut temp_data = data.clone();

        if patch(&mut temp_data, portal_pattern(), &portal_pattern().empty()).is_ok() {
            println!("  ✓ Portal pattern (.actual.battle.net → empty)");
        } else {
            println!("  ✗ Portal pattern not found");
        }

        temp_data = data.clone();
        if patch(
            &mut temp_data,
            connect_to_modulus_pattern(),
            key_config.rsa_modulus(),
        )
        .is_ok()
        {
            if key_config.is_trinity_core() {
                println!("  ✓ RSA modulus → TrinityCore RSA key (256 bytes)");
            } else {
                println!("  ✓ RSA modulus → Custom RSA key (256 bytes)");
            }
        } else {
            println!("  ✗ RSA modulus pattern not found");
        }

        temp_data = data.clone();
        if client_type.uses_ed25519() {
            if patch(
                &mut temp_data,
                crypto_ed_public_key_pattern(),
                key_config.ed25519_public_key(),
            )
            .is_ok()
            {
                if key_config.is_trinity_core() {
                    println!("  ✓ Ed25519 public key → TrinityCore Ed25519 key (32 bytes)");
                } else {
                    println!("  ✓ Ed25519 public key → Custom Ed25519 key (32 bytes)");
                }
            } else {
                println!("  ✗ Ed25519 public key pattern not found");
            }
        } else {
            println!("  ⚠ Ed25519 public key not used by {} clients", client_type);
        }

        temp_data = data.clone();
        let version_url_replacement = create_url_replacement(
            version_url.unwrap_or(&get_version_url(None, None, None)),
            version_url_pattern().len(),
        );
        if patch(
            &mut temp_data,
            version_url_pattern(),
            &version_url_replacement,
        )
        .is_ok()
        {
            if let Some(custom_url) = version_url {
                println!("  ✓ Version URL → Custom CDN ({})", custom_url);
            } else {
                println!("  ✓ Version URL → Arctium CDN (http://ngdp.arctium.io/...)");
            }
        } else {
            println!("  ✗ Version URL pattern not found");
        }

        temp_data = data.clone();
        let cdns_url_replacement = create_url_replacement(
            cdns_url.unwrap_or(&get_cdns_url()),
            cdns_url_pattern().len(),
        );
        if patch(&mut temp_data, cdns_url_pattern(), &cdns_url_replacement).is_ok() {
            if let Some(custom_url) = cdns_url {
                println!("  ✓ CDNs URL → Custom CDN ({})", custom_url);
            } else {
                println!("  ✓ CDNs URL → Arctium CDN (http://ngdp.arctium.io/customs/wow/cdns)");
            }
        } else {
            println!("  ✗ CDNs URL pattern not found");
        }

        if strip_codesign && cfg!(target_os = "macos") {
            println!("  ✓ Remove macOS code signing");
        }

        println!();
        println!("No changes were made. Remove --dry-run to apply patches.");
        return Ok(());
    }

    // Apply patches
    let mut patch_count = 0;

    if verbose {
        println!("Applying patches...");
    }

    // Portal pattern
    if let Err(e) = patch(&mut data, portal_pattern(), &portal_pattern().empty()) {
        if verbose {
            println!("  ✗ Portal pattern not found: {}", e);
        }
        return Err(WowPatcherError::wrap(
            ErrorCategory::PatchingError,
            "Failed to patch portal pattern - unsupported WoW version",
            e,
        ));
    } else {
        patch_count += 1;
        if verbose {
            println!("  ✓ Portal pattern patched");
        }
    }

    // RSA modulus
    if let Err(e) = patch(
        &mut data,
        connect_to_modulus_pattern(),
        key_config.rsa_modulus(),
    ) {
        if verbose {
            println!("  ✗ RSA modulus pattern not found: {}", e);
        }
        return Err(WowPatcherError::wrap(
            ErrorCategory::PatchingError,
            "Failed to patch RSA modulus - unsupported WoW version",
            e,
        ));
    } else {
        patch_count += 1;
        if verbose {
            if key_config.is_trinity_core() {
                println!("  ✓ RSA modulus patched (TrinityCore key)");
            } else {
                println!("  ✓ RSA modulus patched (custom key)");
            }
        }
    }

    // Ed25519 (optional based on client type)
    if client_type.uses_ed25519() {
        if let Err(e) = patch(
            &mut data,
            crypto_ed_public_key_pattern(),
            key_config.ed25519_public_key(),
        ) {
            if verbose {
                println!(
                    "  ⚠ Ed25519 pattern not found (may be unsupported version): {}",
                    e
                );
            }
        } else {
            patch_count += 1;
            if verbose {
                if key_config.is_trinity_core() {
                    println!("  ✓ Ed25519 public key patched (TrinityCore key)");
                } else {
                    println!("  ✓ Ed25519 public key patched (custom key)");
                }
            }
        }
    } else if verbose {
        println!("  ℹ {} clients use RSA-based authentication", client_type);
    }

    // Version URL patching
    let version_url_replacement = create_url_replacement(
        version_url.unwrap_or(&get_version_url(None, None, None)),
        version_url_pattern().len(),
    );
    if let Err(e) = patch(&mut data, version_url_pattern(), &version_url_replacement) {
        if verbose {
            println!(
                "  ⚠ Version URL pattern not found (may be custom build): {}",
                e
            );
        }
    } else {
        patch_count += 1;
        if verbose {
            if let Some(custom_url) = version_url {
                println!("  ✓ Version URL patched → Custom CDN ({})", custom_url);
            } else {
                println!("  ✓ Version URL patched → Arctium CDN");
            }
        }
    }

    // CDNs URL patching
    let cdns_url_replacement = create_url_replacement(
        cdns_url.unwrap_or(&get_cdns_url()),
        cdns_url_pattern().len(),
    );
    if let Err(e) = patch(&mut data, cdns_url_pattern(), &cdns_url_replacement) {
        if verbose {
            println!(
                "  ⚠ CDNs URL pattern not found (may be custom build): {}",
                e
            );
        }
    } else {
        patch_count += 1;
        if verbose {
            if let Some(custom_url) = cdns_url {
                println!("  ✓ CDNs URL patched → Custom CDN ({})", custom_url);
            } else {
                println!("  ✓ CDNs URL patched → Arctium CDN");
            }
        }
    }

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            return Err(WowPatcherError::new(
                ErrorCategory::FileOperationError,
                format!("Output directory does not exist: {:?}", parent),
            ));
        }
    }

    // Write patched file
    fs::write(output_path, data).map_err(|e| {
        WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "Failed to write patched executable",
            e,
        )
    })?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(output_path)
            .map_err(|e| {
                WowPatcherError::wrap(
                    ErrorCategory::FileOperationError,
                    "Failed to get file metadata",
                    e,
                )
            })?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(output_path, perms).map_err(|e| {
            WowPatcherError::wrap(
                ErrorCategory::FileOperationError,
                "Failed to set file permissions",
                e,
            )
        })?;
    }

    // Remove code signing on macOS
    if strip_codesign && cfg!(target_os = "macos") {
        if let Err(e) = remove_codesigning_signature(output_path.to_str().unwrap_or("")) {
            return Err(WowPatcherError::wrap(
                ErrorCategory::PlatformError,
                "Failed to remove code signing",
                e,
            ));
        }
    }

    println!(
        "✅ Successfully applied {} patches and saved to {:?}",
        patch_count, output_path
    );
    println!();
    println!("The patched client can now connect to TrinityCore private servers.");

    Ok(())
}
