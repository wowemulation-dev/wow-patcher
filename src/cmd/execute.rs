use crate::binary::{
    DataExt, PatternExt, check_offset_section, patch, patch_with_padding, validate_patch_offsets,
};
use crate::cert_bundle::CertBundleConfig;
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patterns::{
    cdns_url_pattern, cert_bundle_pattern, cert_bundle_url_pattern, connect_to_modulus_pattern,
    crypto_ed_public_key_pattern, crypto_rsa_modulus_pattern, portal_pattern,
    signature_modulus_pattern, version_url_pattern, version_url_v2_pattern, version_url_v3_pattern,
};
use crate::platform::{
    detect_client_type, extract_version, extract_version_fallback, remove_codesigning_signature,
};
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

    // Check cert-bundle envelope pattern (only present in 1.14.x / 2.5.3)
    if cert_bundle.bundle_bytes().is_some()
        && let Some(offset) = data.find_pattern(cert_bundle_pattern())
    {
        offsets_to_validate.push((offset, "Cert bundle envelope ({\"Created\":)"));
    }

    // Check cert-bundle URL literal (only present in 1.13.2 / 1.14.x / 2.5.3)
    if cert_bundle.download_url().is_some()
        && let Some(offset) = data.find_pattern(cert_bundle_url_pattern())
    {
        offsets_to_validate.push((offset, "Cert bundle URL"));
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

        // Check each pattern in the same order as the apply path:
        // RSA -> Ed25519 -> Nydus host -> Portal -> Version URL -> CDNs URL.
        let mut temp_data = data.clone();
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

        if let Some(bundle) = cert_bundle.bundle_bytes() {
            temp_data = data.clone();
            match patch_with_padding(
                &mut temp_data,
                cert_bundle_pattern(),
                bundle,
                EMBEDDED_BUNDLE_SLOT,
            ) {
                Ok(()) => println!(
                    "  ✓ Cert bundle ({} bytes -> {}-byte embedded slot)",
                    bundle.len(),
                    EMBEDDED_BUNDLE_SLOT
                ),
                Err(_) => println!(
                    "  ⚠ Cert bundle envelope not found (skipped; expected for 1.13.2 / 1.15.2 / 3.4.3 / 4.4.2)"
                ),
            }
        }

        if let Some(url) = cert_bundle.download_url() {
            temp_data = data.clone();
            match patch_with_padding(
                &mut temp_data,
                cert_bundle_url_pattern(),
                url.as_bytes(),
                cert_bundle_url_pattern().len(),
            ) {
                Ok(()) => println!("  ✓ Cert bundle URL -> {}", url),
                Err(_) => println!(
                    "  ⚠ Cert bundle URL not found (skipped; expected for 1.15.2 / 3.4.3 / 4.4.2)"
                ),
            }
        }

        temp_data = data.clone();
        if patch(
            &mut temp_data,
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

    // Patch order rationale -- follows the runtime dependency chain:
    //   1. RSA modulus       -- defeats the cert-bundle signature pin.
    //   2. Ed25519 key       -- pairs with RSA for clients that use it.
    //   3. Cert bundle bytes -- inject our signed bundle into the embedded
    //      `{"Created":` slot (1.14.x / 2.5.3 only). Validates against the
    //      modulus replaced in step 1.
    //   4. Cert bundle URL   -- rewrite the 59-byte download URL slot so the
    //      client fetches our self-signed bundle from an operator-controlled
    //      host (1.13.2 / 1.14.x / 2.5.3 only).
    //   5. BGS portal host   -- redirect `.actual.battle.net` so the BGS
    //      HTTPS portal + Aurora-RPC TCP land on bgs-server.
    //   6/7. Version + CDNs URLs -- TACT origin redirect for boot/install.
    //
    // Out of scope here (handled by separate future groups):
    //   - 5 cosmetic nydus.battle.net URLs (driver-unsupported, trial
    //     restriction, gametime/transactions UI, checkout, checkoutnav)
    //     -- future `nydus-cosmetic` group
    //   - Phoenix launcher-login registry path
    //     -- future `launcher-login` group
    //   - Runtime cert-validation branch flips (CertBundle JZ-NOP,
    //     CertCommonName, CertChain) and Arxan anti-tamper
    //     -- future `cert-runtime` / `arxan-runtime` groups, runtime-only
    // See `docs/wow-classic/_cross-build/patcher-coverage.md` for the
    // complete group catalog.

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

    // Cert-bundle injection: replace the embedded `{"Created":...}` envelope
    // bytes in the binary with the user-supplied signed bundle. Slot is
    // 32761 bytes; user-supplied bundle is NUL-padded to fill the slot.
    //
    // Only fires for builds that ship with an embedded bundle (1.14.0,
    // 1.14.1, 1.14.2, 2.5.3). For builds without an embedded bundle
    // (1.13.2, 1.15.2, 3.4.3, 4.4.2), the pattern won't match and we
    // skip with a verbose note. For those builds the user should pair
    // `--cert-bundle` with `--cert-bundle-url` to direct the runtime
    // download path at a host they control that serves the bundle.
    //
    // Pairs with the RSA modulus rewrite above: the bundle's signature
    // is verified against the embedded modulus, which we just replaced
    // with the user's key. The user is responsible for ensuring the
    // bundle file was signed by the matching private key.
    if let Some(bundle) = cert_bundle.bundle_bytes() {
        match patch_with_padding(&mut data, cert_bundle_pattern(), bundle, EMBEDDED_BUNDLE_SLOT) {
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

    // Cert-bundle download URL: replace the literal nydus URL with one
    // pointing at a server the operator controls. Slot is 59 bytes;
    // shorter URLs are NUL-padded.
    //
    // Use this when the user wants to decouple "where the bundle lives"
    // from the rest of the namespace rewrites done by `--portal-domain`.
    // For example, hosting the bundle on a separate CDN.
    if let Some(url) = cert_bundle.download_url() {
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
                    println!(
                        "  ⚠ Cert bundle URL pattern not found ({}); skipping",
                        e
                    );
                    println!(
                        "    (this is expected for builds without the URL as a flat string: 1.15.2, 3.4.3, 4.4.2)"
                    );
                }
            }
        }
    }

    // BGS portal: `.actual.battle.net` → `.actual.<domain>`
    // (NUL-padded to 18 bytes if shorter). The 1.13.x-4.4.x clients construct
    // the BGS portal URL via NUL-terminated string concat — `<region> +
    // ".actual.battle.net" + "/path"`. Filling with all-NUL collapses the
    // assembled URL at the embedded NUL and silently drops the path
    // (manifests as `BLZ51901016 ERROR_NETWORK_MODULE_SOCKET_CLOSED`).
    //
    // The default `.actual.wowemu.dev` is byte-identical in length to the
    // original; shorter overrides like `.actual.bgs.corp` get NUL-padded.
    // The chosen domain must be reachable from the patched client's host
    // (typically via `/etc/hosts` or a controlled resolver) and the
    // bgs-server cert must be issued for / cover the resulting hostname.
    //
    // Scope note: this rewrites ONLY the BGS portal suffix. The cert-bundle
    // download URL is handled by the cert-bundle group above; the 5 cosmetic
    // nydus.battle.net URLs (driver-unsupported, trial-restriction, gametime,
    // checkout, checkoutnav) are intentionally left untouched -- they belong
    // to a future `nydus-cosmetic` group, not the auth-flow critical path.
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
    } else {
        patch_count += 1;
        if verbose {
            println!(
                "  ✓ BGS portal patched (.actual.battle.net → .actual.{})",
                portal_domain.as_str()
            );
        }
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
