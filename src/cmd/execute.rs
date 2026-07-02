use crate::binary::{
    DataExt, PatternExt, check_offset_section, patch, patch_with_padding, validate_patch_offsets,
};
use crate::cert_bundle::CertBundleConfig;
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patch_group::PatchGroup;
use crate::patterns::{
    cdns_url_pattern, cert_bundle_pattern, cert_bundle_url_pattern, connect_to_modulus_pattern,
    crypto_ed_public_key_pattern, portal_pattern, version_url_pattern, version_url_v2_pattern,
    version_url_v3_pattern,
};
use crate::platform::{detect_client_type, extract_version, remove_codesigning_signature};
use crate::portal_domain::PortalDomain;
use crate::trinity::{create_url_replacement, get_cdns_url, get_unified_api_url, get_version_url};
use std::fs;
use std::path::Path;

/// Slot size of the embedded cert bundle in `.rdata`.
///
/// The bundle is exactly `MAX_EMBEDDED_BUNDLE_SIZE` bytes followed by
/// alignment NUL padding. We zero only the bundle portion; the
/// alignment padding stays untouched.
const EMBEDDED_BUNDLE_SLOT: usize = crate::cert_bundle::MAX_EMBEDDED_BUNDLE_SIZE;

#[allow(clippy::too_many_arguments)]
pub fn execute_patch(
    input_path: &Path,
    output_path: &Path,
    key_config: KeyConfig,
    version_url: Option<&str>,
    cdns_url: Option<&str>,
    portal_domain: PortalDomain,
    cert_bundle: CertBundleConfig,
    patches: PatchGroup,
    dry_run: bool,
    strip_codesign: bool,
    verbose: bool,
) -> Result<(), WowPatcherError> {
    // --- Input validation ---

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
    let version = extract_version(input_path);

    if let Some(ref v) = version {
        if verbose {
            println!("Detected client version: {}", v);
        }
    } else if verbose {
        println!("Unable to extract version from executable, using fallback URL");
    }

    if verbose {
        println!("Patch groups: {}", patches);
    }

    // Read the file
    let mut data = fs::read(input_path).map_err(|e| {
        WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "Failed to read WoW executable file",
            e,
        )
    })?;

    // --- Cross-group dependency checks ---

    // Cert-bundle injection requires RSA: the bundle signature is verified
    // against the modulus. If the user selected cert-bundle without RSA,
    // the injected bundle won't validate at runtime.
    if patches.contains(PatchGroup::CERT_BUNDLE)
        && !patches.contains(PatchGroup::RSA)
        && cert_bundle.bundle_bytes().is_some()
        && verbose
    {
        println!("⚠️  CERT_BUNDLE selected without RSA — the injected bundle will not validate ");
        println!(
            "    against the stock RSA modulus. Add 'rsa' to --patches or provide an RSA key."
        );
    }

    // Cert-bundle-group selected without --cert-bundle input: the flag
    // is in the set but there's nothing to inject. Warn once.
    if patches.contains(PatchGroup::CERT_BUNDLE) && cert_bundle.bundle_bytes().is_none() && verbose
    {
        println!(
            "ℹ️  CERT_BUNDLE is in --patches but no --cert-bundle FILE was provided; skipped."
        );
    }
    if patches.contains(PatchGroup::CERT_BUNDLE_URL)
        && cert_bundle.download_url().is_none()
        && verbose
    {
        println!(
            "ℹ️  CERT_BUNDLE_URL is in --patches but no --cert-bundle-url was provided; skipped."
        );
    }

    // --- Section validation (scoped to selected groups) ---

    let mut offsets_to_validate = Vec::new();

    if patches.contains(PatchGroup::PORTAL)
        && let Some(offset) = data.find_pattern(portal_pattern())
    {
        offsets_to_validate.push((offset, "Portal (.actual.battle.net)"));
    }

    if patches.contains(PatchGroup::CERT_BUNDLE)
        && cert_bundle.bundle_bytes().is_some()
        && let Some(offset) = data.find_pattern(cert_bundle_pattern())
    {
        offsets_to_validate.push((offset, "Cert bundle envelope ({\"Created\":)"));
    }

    if patches.contains(PatchGroup::CERT_BUNDLE_URL)
        && cert_bundle.download_url().is_some()
        && let Some(offset) = data.find_pattern(cert_bundle_url_pattern())
    {
        offsets_to_validate.push((offset, "Cert bundle URL"));
    }

    if patches.contains(PatchGroup::RSA)
        && let Some(offset) = data.find_pattern(connect_to_modulus_pattern())
    {
        offsets_to_validate.push((offset, "RSA Modulus (ConnectTo)"));
    }

    if patches.contains(PatchGroup::ED25519)
        && client_type.uses_ed25519()
        && let Some(offset) = data.find_pattern(crypto_ed_public_key_pattern())
    {
        offsets_to_validate.push((offset, "Ed25519 Public Key"));
    }

    if patches.contains(PatchGroup::VERSION) {
        if let Some(offset) = data.find_pattern(version_url_pattern()) {
            offsets_to_validate.push((offset, "Version URL"));
        }
        if let Some(offset) = data.find_pattern(version_url_v2_pattern()) {
            offsets_to_validate.push((offset, "Version URL v2"));
        }
        if let Some(offset) = data.find_pattern(version_url_v3_pattern()) {
            offsets_to_validate.push((offset, "Version URL v3"));
        }
    }

    if patches.contains(PatchGroup::CDNS)
        && let Some(offset) = data.find_pattern(cdns_url_pattern())
    {
        offsets_to_validate.push((offset, "CDNs URL"));
    }

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

    // --- Dry run ---

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
        println!("Patch groups: {}", patches);
        println!();
        if !offsets_to_validate.is_empty() {
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
        }
        println!("Patches that would be applied:");
        dry_run_preview(
            &data,
            &key_config,
            version_url,
            cdns_url,
            &portal_domain,
            &cert_bundle,
            patches,
            client_type,
            version.as_ref(),
            strip_codesign,
        );
        println!();
        println!("No changes were made. Remove --dry-run to apply patches.");
        return Ok(());
    }

    // --- Apply patches ---

    let mut patch_count = 0;

    if verbose {
        println!("Applying patches...");
    }

    // 1. RSA modulus (ConnectToModulus only)
    if patches.contains(PatchGroup::RSA) {
        if let Err(e) = patch(
            &mut data,
            connect_to_modulus_pattern(),
            key_config.rsa_modulus(),
        ) {
            if verbose {
                println!("  ✗ ConnectToModulus pattern not found: {}", e);
            }
            return Err(WowPatcherError::wrap(
                ErrorCategory::PatchingError,
                "Failed to patch ConnectToModulus -- unsupported WoW version",
                e,
            ));
        }
        patch_count += 1;
        if verbose {
            if key_config.is_trinity_core() {
                println!("  ✓ RSA modulus patched (TrinityCore key, ConnectTo)");
            } else {
                println!("  ✓ RSA modulus patched (custom key, ConnectTo)");
            }
        }
    } else if verbose {
        println!("  ⋯ RSA modulus (skipped — not in --patches)");
    }

    // 2. Ed25519 (optional based on client type)
    if patches.contains(PatchGroup::ED25519) {
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
    } else if verbose {
        println!("  ⋯ Ed25519 (skipped — not in --patches)");
    }

    // 3. Cert-bundle injection (input-gated: requires --cert-bundle)
    if patches.contains(PatchGroup::CERT_BUNDLE) && cert_bundle.bundle_bytes().is_some() {
        let bundle = cert_bundle.bundle_bytes().unwrap();
        match patch_with_padding(
            &mut data,
            cert_bundle_pattern(),
            bundle,
            EMBEDDED_BUNDLE_SLOT,
        ) {
            Ok(()) => {
                patch_count += 1;
                if verbose {
                    println!(
                        "  ✓ Cert bundle injected ({} bytes into {}-byte slot)",
                        bundle.len(),
                        EMBEDDED_BUNDLE_SLOT
                    );
                }
            }
            Err(e) => {
                if verbose {
                    println!(
                        "  ⚠ Cert bundle pattern not found ({}); skipping injection",
                        e
                    );
                    println!(
                        "    (this is expected for clients without an embedded bundle: 1.13.2, 1.15.2, 3.4.3, 4.4.2)"
                    );
                }
            }
        }
    }

    // 4. Cert-bundle download URL (input-gated: requires --cert-bundle-url)
    if patches.contains(PatchGroup::CERT_BUNDLE_URL) && cert_bundle.download_url().is_some() {
        let url = cert_bundle.download_url().unwrap();
        match patch_with_padding(
            &mut data,
            cert_bundle_url_pattern(),
            url.as_bytes(),
            cert_bundle_url_pattern().len(),
        ) {
            Ok(()) => {
                patch_count += 1;
                if verbose {
                    println!("  ✓ Cert bundle URL patched ({} bytes)", url.len());
                }
            }
            Err(e) => {
                if verbose {
                    println!("  ⚠ Cert bundle URL pattern not found ({}); skipping", e);
                    println!(
                        "    (this is expected for builds without the URL as a flat string: 1.15.2, 3.4.3, 4.4.2)"
                    );
                }
            }
        }
    }

    // 5. BGS portal
    if patches.contains(PatchGroup::PORTAL) {
        let portal_replacement = portal_pattern().padded(&portal_domain.portal_replacement());
        if let Err(e) = patch(&mut data, portal_pattern(), &portal_replacement) {
            if verbose {
                println!("  ✗ BGS portal pattern not found: {}", e);
            }
            return Err(WowPatcherError::wrap(
                ErrorCategory::PatchingError,
                "Failed to patch BGS portal pattern - unsupported WoW version",
                e,
            ));
        }
        patch_count += 1;
        if verbose {
            println!(
                "  ✓ BGS portal patched (.actual.battle.net → .actual.{})",
                portal_domain.as_str()
            );
        }
    } else if verbose {
        println!("  ⋯ BGS portal (skipped — not in --patches)");
    }

    // 6/7. Version + CDNs URLs
    let build_num = version.as_ref().map(|v| v.build);
    let mut used_unified_api = false;

    if patches.contains(PatchGroup::VERSION) {
        let mut version_url_patched = false;
        let mut version_url_pattern_name = "";

        // Try v1
        let replacement_v1 = create_url_replacement(
            version_url.unwrap_or(&get_version_url(build_num, None, None)),
            version_url_pattern().len(),
        );
        if patch(&mut data, version_url_pattern(), &replacement_v1).is_ok() {
            version_url_patched = true;
            version_url_pattern_name = "v1";
        } else {
            // Try v2
            let replacement_v2 = create_url_replacement(
                version_url.unwrap_or(&get_version_url(build_num, None, None)),
                version_url_v2_pattern().len(),
            );
            if patch(&mut data, version_url_v2_pattern(), &replacement_v2).is_ok() {
                version_url_patched = true;
                version_url_pattern_name = "v2";
            } else {
                // Try v3 (unified API)
                let replacement_v3 = create_url_replacement(
                    version_url.unwrap_or(&get_unified_api_url(build_num)),
                    version_url_v3_pattern().len(),
                );
                if patch(&mut data, version_url_v3_pattern(), &replacement_v3).is_ok() {
                    version_url_patched = true;
                    version_url_pattern_name = "v3 (unified API)";
                }
            }
        }

        used_unified_api = version_url_pattern_name.contains("v3");

        if version_url_patched {
            patch_count += 1;
            if verbose {
                if let Some(custom_url) = version_url {
                    println!(
                        "  ✓ Version URL patched → {} ({} pattern)",
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
        } else if verbose {
            println!("  ⚠ Version URL pattern not found (tried v1, v2, v3; may be custom build)");
        }
    } else if verbose {
        println!("  ⋯ Version URL (skipped — not in --patches)");
    }

    // CDNs URL (skip if v3 unified API handled both)
    if patches.contains(PatchGroup::CDNS) && !used_unified_api {
        let replacement = create_url_replacement(
            cdns_url.unwrap_or(&get_cdns_url()),
            cdns_url_pattern().len(),
        );
        if let Err(e) = patch(&mut data, cdns_url_pattern(), &replacement) {
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
                    println!("  ✓ CDNs URL patched → {}", custom_url);
                } else {
                    println!("  ✓ CDNs URL patched → Arctium CDN");
                }
            }
        }
    } else if patches.contains(PatchGroup::CDNS) && verbose {
        println!("  ℹ CDNs URL handled by unified API pattern");
    } else if verbose && !patches.contains(PatchGroup::CDNS) {
        println!("  ⋯ CDNs URL (skipped — not in --patches)");
    }

    // --- Write output ---

    if patch_count == 0 {
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "No patches were applied. Check that --patches includes groups whose patterns exist in this binary.",
        ));
    }

    // Create output directory if needed
    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        return Err(WowPatcherError::new(
            ErrorCategory::FileOperationError,
            format!("Output directory does not exist: {:?}", parent),
        ));
    }

    fs::write(output_path, &data).map_err(|e| {
        WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "Failed to write patched executable",
            e,
        )
    })?;

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

    Ok(())
}

// ---------------------------------------------------------------------------
// Dry-run preview helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn dry_run_preview(
    data: &[u8],
    key_config: &KeyConfig,
    version_url: Option<&str>,
    cdns_url: Option<&str>,
    portal_domain: &PortalDomain,
    cert_bundle: &CertBundleConfig,
    patches: PatchGroup,
    client_type: crate::platform::ClientType,
    version: Option<&crate::platform::Version>,
    strip_codesign: bool,
) {
    // RSA
    if patches.contains(PatchGroup::RSA) {
        let mut temp = data.to_vec();
        if patch(
            &mut temp,
            connect_to_modulus_pattern(),
            key_config.rsa_modulus(),
        )
        .is_ok()
        {
            let key_label = if key_config.is_trinity_core() {
                "TrinityCore key"
            } else {
                "custom key"
            };
            println!("  ✓ RSA modulus → {} (ConnectTo)", key_label);
        } else {
            println!("  ✗ ConnectToModulus pattern not found");
        }
    } else {
        println!("  ⋯ RSA modulus (skipped)");
    }

    // Ed25519
    if patches.contains(PatchGroup::ED25519) {
        if client_type.uses_ed25519() {
            let mut temp = data.to_vec();
            if patch(
                &mut temp,
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
            println!("  ℹ Ed25519 public key not used by {} clients", client_type);
        }
    } else {
        println!("  ⋯ Ed25519 (skipped)");
    }

    // Cert bundle injection
    if patches.contains(PatchGroup::CERT_BUNDLE) && cert_bundle.bundle_bytes().is_some() {
        let bundle = cert_bundle.bundle_bytes().unwrap();
        let mut temp = data.to_vec();
        match patch_with_padding(
            &mut temp,
            cert_bundle_pattern(),
            bundle,
            EMBEDDED_BUNDLE_SLOT,
        ) {
            Ok(()) => println!(
                "  ✓ Cert bundle ({} bytes → {}-byte embedded slot)",
                bundle.len(),
                EMBEDDED_BUNDLE_SLOT
            ),
            Err(_) => println!(
                "  ⚠ Cert bundle envelope not found (skipped; expected for 1.13.2 / 1.15.2 / 3.4.3 / 4.4.2)"
            ),
        }
    }

    // Cert bundle URL
    if patches.contains(PatchGroup::CERT_BUNDLE_URL) && cert_bundle.download_url().is_some() {
        let url = cert_bundle.download_url().unwrap();
        let mut temp = data.to_vec();
        match patch_with_padding(
            &mut temp,
            cert_bundle_url_pattern(),
            url.as_bytes(),
            cert_bundle_url_pattern().len(),
        ) {
            Ok(()) => println!("  ✓ Cert bundle URL → {}", url),
            Err(_) => println!(
                "  ⚠ Cert bundle URL not found (skipped; expected for 1.15.2 / 3.4.3 / 4.4.2)"
            ),
        }
    }

    // Portal
    if patches.contains(PatchGroup::PORTAL) {
        let mut temp = data.to_vec();
        if patch(
            &mut temp,
            portal_pattern(),
            &portal_pattern().padded(&portal_domain.portal_replacement()),
        )
        .is_ok()
        {
            println!(
                "  ✓ BGS portal (.actual.battle.net → .actual.{})",
                portal_domain.as_str()
            );
        } else {
            println!("  ✗ BGS portal pattern not found");
        }
    } else {
        println!("  ⋯ BGS portal (skipped)");
    }

    // Version URL
    if patches.contains(PatchGroup::VERSION) {
        let build_num = version.map(|v| v.build);
        let mut version_url_found = false;
        let mut version_url_pattern_name = "";

        let mut temp = data.to_vec();
        let replacement_v1 = create_url_replacement(
            version_url.unwrap_or(&get_version_url(build_num, None, None)),
            version_url_pattern().len(),
        );
        if patch(&mut temp, version_url_pattern(), &replacement_v1).is_ok() {
            version_url_found = true;
            version_url_pattern_name = "v1";
        } else {
            let mut temp = data.to_vec();
            let replacement_v2 = create_url_replacement(
                version_url.unwrap_or(&get_version_url(build_num, None, None)),
                version_url_v2_pattern().len(),
            );
            if patch(&mut temp, version_url_v2_pattern(), &replacement_v2).is_ok() {
                version_url_found = true;
                version_url_pattern_name = "v2";
            } else {
                let mut temp = data.to_vec();
                let replacement_v3 = create_url_replacement(
                    version_url.unwrap_or(&get_unified_api_url(build_num)),
                    version_url_v3_pattern().len(),
                );
                if patch(&mut temp, version_url_v3_pattern(), &replacement_v3).is_ok() {
                    version_url_found = true;
                    version_url_pattern_name = "v3 (unified API)";
                }
            }
        }

        if version_url_found {
            if let Some(custom_url) = version_url {
                println!(
                    "  ✓ Version URL → {} ({} pattern)",
                    custom_url, version_url_pattern_name
                );
            } else if version_url_pattern_name.contains("v3") {
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
    } else {
        println!("  ⋯ Version URL (skipped)");
    }

    // CDNs URL
    if patches.contains(PatchGroup::CDNS) {
        let mut temp = data.to_vec();
        let replacement = create_url_replacement(
            cdns_url.unwrap_or(&get_cdns_url()),
            cdns_url_pattern().len(),
        );
        if patch(&mut temp, cdns_url_pattern(), &replacement).is_ok() {
            if let Some(custom_url) = cdns_url {
                println!("  ✓ CDNs URL → {}", custom_url);
            } else {
                println!("  ✓ CDNs URL → Arctium CDN (http://ngdp.arctium.io/customs/wow/cdns)");
            }
        } else {
            println!("  ✗ CDNs URL pattern not found");
        }
    } else {
        println!("  ⋯ CDNs URL (skipped)");
    }

    if strip_codesign && cfg!(target_os = "macos") {
        println!("  ✓ Remove macOS code signing");
    }
}
