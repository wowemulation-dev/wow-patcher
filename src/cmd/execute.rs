use crate::binary::{DataExt, PatternExt, check_offset_section, patch, validate_patch_offsets};
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patterns::{
    cdns_url_pattern, connect_to_modulus_pattern, crypto_ed_public_key_pattern,
    crypto_rsa_modulus_pattern, portal_pattern, signature_modulus_pattern, version_url_pattern,
    version_url_v2_pattern, version_url_v3_pattern,
};
use crate::platform::{
    detect_client_type, extract_version, extract_version_fallback, remove_codesigning_signature,
};
use crate::trinity::{create_url_replacement, get_cdns_url, get_unified_api_url, get_version_url};
use std::fs;
use std::path::Path;

#[allow(clippy::too_many_arguments)]
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

    // Validate that all patterns are in patchable sections before proceeding
    let mut offsets_to_validate = Vec::new();

    // Check portal pattern
    if let Some(offset) = data.find_pattern(portal_pattern()) {
        offsets_to_validate.push((offset, "Portal (.actual.battle.net)"));
    }

    // Check RSA modulus patterns (multiple patterns for different client versions)
    if let Some(offset) = data.find_pattern(connect_to_modulus_pattern()) {
        offsets_to_validate.push((offset, "RSA Modulus (ConnectTo)"));
    }
    if let Some(offset) = data.find_pattern(signature_modulus_pattern()) {
        offsets_to_validate.push((offset, "RSA Modulus (Signature)"));
    }
    if let Some(offset) = data.find_pattern(crypto_rsa_modulus_pattern()) {
        offsets_to_validate.push((offset, "RSA Modulus (Crypto)"));
    }

    // Check Ed25519 pattern (only for clients that use it)
    if client_type.uses_ed25519()
        && let Some(offset) = data.find_pattern(crypto_ed_public_key_pattern())
    {
        offsets_to_validate.push((offset, "Ed25519 Public Key"));
    }

    // Check version URL patterns (v1, v2, and v3)
    if let Some(offset) = data.find_pattern(version_url_pattern()) {
        offsets_to_validate.push((offset, "Version URL"));
    }
    if let Some(offset) = data.find_pattern(version_url_v2_pattern()) {
        offsets_to_validate.push((offset, "Version URL v2"));
    }
    if let Some(offset) = data.find_pattern(version_url_v3_pattern()) {
        offsets_to_validate.push((offset, "Version URL v3"));
    }

    // Check CDNs URL pattern
    if let Some(offset) = data.find_pattern(cdns_url_pattern()) {
        offsets_to_validate.push((offset, "CDNs URL"));
    }

    // Validate all found patterns are in patchable sections
    if let Err(validation_error) = validate_patch_offsets(&data, &offsets_to_validate) {
        if verbose {
            println!("⚠️  Section validation warnings:");
            for line in validation_error.lines() {
                println!("  {}", line);
            }
            println!();
            println!("Binary file patching only works reliably in data sections (.rdata, .data).");
            println!("Code sections (.text) are protected and changes will be lost at runtime.");
            println!("Consider using Arctium's in-memory patcher for these patterns.");
            println!();
        }
        return Err(WowPatcherError::new(
            ErrorCategory::ValidationError,
            format!("Pattern validation failed:\n{}", validation_error),
        ));
    }

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
        println!("Section Validation:");
        for (offset, pattern_name) in &offsets_to_validate {
            if let Some(section) = check_offset_section(&data, *offset) {
                if section.is_patchable {
                    println!(
                        "  ✓ {} at 0x{:x} in '{}' (patchable)",
                        pattern_name, offset, section.name
                    );
                } else {
                    println!(
                        "  ⚠ {} at 0x{:x} in '{}' (NOT patchable - code section)",
                        pattern_name, offset, section.name
                    );
                }
            }
        }
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
        let mut rsa_found = false;
        let mut rsa_pattern = "";

        if patch(
            &mut temp_data,
            connect_to_modulus_pattern(),
            key_config.rsa_modulus(),
        )
        .is_ok()
        {
            rsa_found = true;
            rsa_pattern = "ConnectTo";
        } else if patch(
            &mut temp_data,
            signature_modulus_pattern(),
            key_config.rsa_modulus(),
        )
        .is_ok()
        {
            rsa_found = true;
            rsa_pattern = "Signature";
        } else if patch(
            &mut temp_data,
            crypto_rsa_modulus_pattern(),
            key_config.rsa_modulus(),
        )
        .is_ok()
        {
            rsa_found = true;
            rsa_pattern = "Crypto";
        }

        if rsa_found {
            if key_config.is_trinity_core() {
                println!(
                    "  ✓ RSA modulus → TrinityCore RSA key (256 bytes, {} pattern)",
                    rsa_pattern
                );
            } else {
                println!(
                    "  ✓ RSA modulus → Custom RSA key (256 bytes, {} pattern)",
                    rsa_pattern
                );
            }
        } else {
            println!("  ✗ RSA modulus pattern not found (tried ConnectTo, Signature, Crypto)");
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
        let mut version_url_found = false;
        let mut version_url_pattern_name = "";

        // Try v1 pattern first
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
            version_url_found = true;
            version_url_pattern_name = "v1";
        } else {
            // Try v2 pattern
            temp_data = data.clone();
            let version_url_v2_replacement = create_url_replacement(
                version_url.unwrap_or(&get_version_url(build_num, None, None)),
                version_url_v2_pattern().len(),
            );
            if patch(
                &mut temp_data,
                version_url_v2_pattern(),
                &version_url_v2_replacement,
            )
            .is_ok()
            {
                version_url_found = true;
                version_url_pattern_name = "v2";
            } else {
                // Try v3 pattern (WoW Classic 1.15.8+ unified API)
                temp_data = data.clone();
                let version_url_v3_replacement = create_url_replacement(
                    version_url.unwrap_or(&get_unified_api_url(build_num)),
                    version_url_v3_pattern().len(),
                );
                if patch(
                    &mut temp_data,
                    version_url_v3_pattern(),
                    &version_url_v3_replacement,
                )
                .is_ok()
                {
                    version_url_found = true;
                    version_url_pattern_name = "v3 (unified API)";
                }
            }
        }

        if version_url_found {
            if let Some(custom_url) = version_url {
                println!(
                    "  ✓ Version URL → Custom CDN ({}, {} pattern)",
                    custom_url, version_url_pattern_name
                );
            } else if version_url_pattern_name.contains("v3") {
                // v3 unified API handles both versions and cdns
                if let Some(build_num) = build_num {
                    println!(
                        "  ✓ API URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/{}/{{endpoint}}, {} pattern)",
                        build_num, version_url_pattern_name
                    );
                } else {
                    println!(
                        "  ✓ API URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/{{endpoint}}, {} pattern)",
                        version_url_pattern_name
                    );
                }
            } else if let Some(build_num) = build_num {
                println!(
                    "  ✓ Version URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/{}/versions, {} pattern)",
                    build_num, version_url_pattern_name
                );
            } else {
                println!(
                    "  ✓ Version URL → Arctium CDN (http://ngdp.arctium.io/%s/%s/latest/versions, {} pattern)",
                    version_url_pattern_name
                );
            }
        } else {
            println!("  ✗ Version URL pattern not found (tried v1, v2, and v3)");
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

    // RSA modulus - try all three patterns (different client versions use different patterns)
    let mut rsa_patched = false;
    let mut rsa_pattern_name = "";

    if patch(
        &mut data,
        connect_to_modulus_pattern(),
        key_config.rsa_modulus(),
    )
    .is_ok()
    {
        rsa_patched = true;
        rsa_pattern_name = "ConnectTo";
    } else if patch(
        &mut data,
        signature_modulus_pattern(),
        key_config.rsa_modulus(),
    )
    .is_ok()
    {
        rsa_patched = true;
        rsa_pattern_name = "Signature";
    } else if patch(
        &mut data,
        crypto_rsa_modulus_pattern(),
        key_config.rsa_modulus(),
    )
    .is_ok()
    {
        rsa_patched = true;
        rsa_pattern_name = "Crypto";
    }

    if !rsa_patched {
        if verbose {
            println!("  ✗ No RSA modulus pattern found (tried ConnectTo, Signature, Crypto)");
        }
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "Failed to patch RSA modulus - no known pattern found (unsupported WoW version)",
        ));
    } else {
        patch_count += 1;
        if verbose {
            if key_config.is_trinity_core() {
                println!(
                    "  ✓ RSA modulus patched (TrinityCore key, {} pattern)",
                    rsa_pattern_name
                );
            } else {
                println!(
                    "  ✓ RSA modulus patched (custom key, {} pattern)",
                    rsa_pattern_name
                );
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

    // Version URL patching - try v1 pattern first, then v2, then v3
    let build_num = version.as_ref().map(|v| v.build as u32);
    let mut version_url_patched = false;
    let mut version_url_pattern_name = "";

    // Try v1 pattern
    let version_url_replacement = create_url_replacement(
        version_url.unwrap_or(&get_version_url(build_num, None, None)),
        version_url_pattern().len(),
    );
    if patch(&mut data, version_url_pattern(), &version_url_replacement).is_ok() {
        version_url_patched = true;
        version_url_pattern_name = "v1";
    } else {
        // Try v2 pattern
        let version_url_v2_replacement = create_url_replacement(
            version_url.unwrap_or(&get_version_url(build_num, None, None)),
            version_url_v2_pattern().len(),
        );
        if patch(
            &mut data,
            version_url_v2_pattern(),
            &version_url_v2_replacement,
        )
        .is_ok()
        {
            version_url_patched = true;
            version_url_pattern_name = "v2";
        } else {
            // Try v3 pattern (WoW Classic 1.15.8+ unified API)
            let version_url_v3_replacement = create_url_replacement(
                version_url.unwrap_or(&get_unified_api_url(build_num)),
                version_url_v3_pattern().len(),
            );
            if patch(
                &mut data,
                version_url_v3_pattern(),
                &version_url_v3_replacement,
            )
            .is_ok()
            {
                version_url_patched = true;
                version_url_pattern_name = "v3 (unified API)";
            }
        }
    }

    // Track if we used the unified v3 API (which handles both versions and cdns)
    let used_unified_api = version_url_pattern_name.contains("v3");

    if !version_url_patched {
        if verbose {
            println!(
                "  ⚠ Version URL pattern not found (tried v1, v2, and v3, may be custom build)"
            );
        }
    } else {
        patch_count += 1;
        if verbose {
            if let Some(custom_url) = version_url {
                println!(
                    "  ✓ Version URL patched → Custom CDN ({}, {} pattern)",
                    custom_url, version_url_pattern_name
                );
            } else if used_unified_api {
                println!(
                    "  ✓ API URL patched → Arctium CDN ({} pattern, handles versions+cdns)",
                    version_url_pattern_name
                );
            } else {
                println!(
                    "  ✓ Version URL patched → Arctium CDN ({} pattern)",
                    version_url_pattern_name
                );
            }
        }
    }

    // CDNs URL patching (skip if we used the unified v3 API which handles both)
    if !used_unified_api {
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
    } else if verbose {
        println!("  ℹ CDNs URL handled by unified API pattern");
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
    if strip_codesign
        && cfg!(target_os = "macos")
        && let Err(e) = remove_codesigning_signature(output_path.to_str().unwrap_or(""))
    {
        return Err(WowPatcherError::wrap(
            ErrorCategory::PlatformError,
            "Failed to remove code signing",
            e,
        ));
    }

    println!(
        "✅ Successfully applied {} patches and saved to {:?}",
        patch_count, output_path
    );
    println!();
    println!("The patched client can now connect to TrinityCore private servers.");

    Ok(())
}
