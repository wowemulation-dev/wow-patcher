use crate::binary::{DataExt, PatternExt, check_offset_section, patch};
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patterns::{
    auth_seed_pattern, cdns_url_pattern, connect_to_modulus_pattern, crypto_ed_public_key_pattern,
    portal_pattern, version_url_pattern,
};
use crate::platform::{
    detect_client_type, extract_version, extract_version_fallback, remove_codesigning_signature,
};
use crate::trinity::{
    create_auth_seed_patch, create_url_replacement, get_cdns_url, get_version_url,
};
use std::fs;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
pub fn execute_patch(
    input_path: &Path,
    output_path: &Path,
    key_config: KeyConfig,
    version_url: Option<&str>,
    cdns_url: Option<&str>,
    use_static_seed: bool,
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

    // Extract version information
    let version = extract_version(input_path).or_else(|| extract_version_fallback(input_path));

    if let Some(ref v) = version {
        if verbose {
            println!("Detected client version: {}", v);
        }
    } else if verbose {
        println!("Unable to extract version from executable, using fallback URL");
    }

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
        let build_num = version.as_ref().map(|v| v.build as u32);
        let version_url_replacement = create_url_replacement(
            version_url.unwrap_or(&get_version_url(build_num, None, None)),
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
            } else if let Some(build_num) = build_num {
                println!(
                    "  ✓ Version URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/{}/versions)",
                    build_num
                );
            } else {
                println!(
                    "  ✓ Version URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/latest/versions)"
                );
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

        if use_static_seed {
            temp_data = data.clone();
            if let Some(auth_seed_offset) = temp_data.find_pattern(auth_seed_pattern()) {
                // Check section to warn if it's in .text
                if let Some(section) = check_offset_section(&temp_data, auth_seed_offset) {
                    if !section.is_patchable {
                        println!(
                            "  ⚠ Auth seed function in {} section (not patchable via binary patching)",
                            section.name
                        );
                    } else {
                        println!(
                            "  ✓ Auth seed function → static seed (179D3DC3235629D07113A9B3867F97A7)"
                        );
                    }
                } else {
                    println!("  ? Auth seed pattern found but section unknown");
                }
            } else {
                println!("  ✗ Auth seed pattern not found");
            }
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
    let build_num = version.as_ref().map(|v| v.build as u32);
    let version_url_replacement = create_url_replacement(
        version_url.unwrap_or(&get_version_url(build_num, None, None)),
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

    // Auth seed patching
    if use_static_seed {
        if let Some(auth_seed_offset) = data.find_pattern(auth_seed_pattern()) {
            // Check which section the auth seed pattern is in
            if let Some(section) = check_offset_section(&data, auth_seed_offset) {
                if !section.is_patchable {
                    // Auth seed is in .text section - warn the user
                    println!(
                        "⚠️  Warning: Auth seed function found in {} section at offset 0x{:x}",
                        section.name, auth_seed_offset
                    );
                    println!(
                        "   This section is executable code that will be overwritten at runtime."
                    );
                    println!(
                        "   The static auth seed patch cannot be applied reliably via binary patching."
                    );
                    println!(
                        "   Consider using the Arctium runtime patcher for this feature instead."
                    );

                    if verbose {
                        println!(
                            "   Technical details: Binary patching only works reliably in .rdata or .data sections."
                        );
                    }
                } else {
                    // This should rarely happen as auth seed is usually in .text
                    // But if it's in a patchable section, we can proceed
                    if let Some(modulus_offset) = data.find_pattern(connect_to_modulus_pattern()) {
                        let auth_seed_patch =
                            create_auth_seed_patch(auth_seed_offset, modulus_offset)?;

                        // Apply the auth seed patch at the function location
                        let function_offset = auth_seed_offset + 4 + 5; // Skip "WoW\0" and call instruction
                        if function_offset + auth_seed_patch.len() <= data.len() {
                            data[function_offset..function_offset + auth_seed_patch.len()]
                                .copy_from_slice(&auth_seed_patch);
                            patch_count += 1;
                            if verbose {
                                println!(
                                    "  ✓ Auth seed function patched → static seed (in {} section)",
                                    section.name
                                );
                            }
                        } else if verbose {
                            println!("  ✗ Auth seed function offset out of bounds");
                        }
                    } else if verbose {
                        println!("  ✗ Cannot patch auth seed without RSA modulus location");
                    }
                }
            } else if verbose {
                println!("  ⚠ Unable to determine section for auth seed pattern");
            }
        } else if verbose {
            println!("  ⚠ Auth seed pattern not found (may not be required for this version)");
        }
    }

    // Create output directory if needed
    if let Some(parent) = output_path.parent() {
        // Only check if parent exists if it's not empty or current directory
        if !parent.as_os_str().is_empty() && !parent.exists() {
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
