//! Runtime patcher: launch Wow.exe suspended, wait for Arxan to
//! decrypt the .text section, apply patches via WriteProcessMemory,
//! resume.
//!
//! This is the runtime counterpart to `cmd::execute` (which patches the
//! binary on disk before launch). Static patches that are safe (e.g.
//! ConnectToModulus, BGS portal hostname) work fine on disk; static
//! patches that crash the client at startup on Wine (notably
//! SignatureModulus -- see Serena memory
//! `analysis/wow-1132-signature-modulus-static-patch-crashes`) require
//! this runtime path.
//!
//! Apply order is taken from Arctium-WoW-Launcher's `Launcher.cs`:
//! integrity NOPs first (suppress repair triggers), then RSA modulus
//! triplet + Ed25519 + portal hostname + cert-bundle bytes (when
//! present). The client is held suspended for the entire patch
//! sequence and resumed atomically at the end.
//!
//! Windows-only. Designed to run under Wine for cross-platform use.
//!
//! Reuses pattern catalogues from `crate::patterns` and
//! `crate::patterns::runtime`. Static-mode patches and runtime-mode
//! patches share the same byte sequences for data slots; the runtime
//! catalogue adds code-site patterns (Integrity, CertBundle branch,
//! CertCommonName, CertChain) that have no static analog because they
//! target Arxan-encrypted .text bytes that only exist in memory.

#[cfg(target_os = "windows")]
pub mod win {
    use std::ffi::CString;
    use std::path::Path;
    use std::{io, thread, time};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        VirtualProtectEx, VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, TerminateProcess,
    };

    use crate::binary::Pattern;
    use crate::cert_bundle::CertBundleConfig;
    use crate::keys::KeyConfig;
    use crate::patterns::runtime::{
        cert_bundle_branch_pattern, cert_bundle_header_pattern, cert_chain_pattern,
        cert_common_name_pattern, connect_to_modulus_pattern, crypto_ed_public_key_pattern,
        crypto_rsa_modulus_pattern, integrity_pattern, integrity_pattern_alt,
        signature_modulus_pattern,
    };
    use crate::patterns::{cert_bundle_url_pattern, portal_pattern};
    use crate::portal_domain::PortalDomain;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(process_handle: HANDLE) -> i32;
        fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    }

    /// Configurable knobs for the launch subcommand.
    pub struct LaunchOptions<'a> {
        pub exe_path: &'a str,
        pub key_config: &'a KeyConfig,
        pub portal_domain: &'a PortalDomain,
        pub cert_bundle: &'a CertBundleConfig,
        /// Apply legacy-cert-mode patches: SignatureModulus replacement,
        /// CryptoRsaModulus replacement, cert-bundle byte injection, and
        /// cert-runtime NOPs (Integrity, CertBundle JZ, CertCommonName,
        /// CertChain). Per Arctium-WoW-Launcher's `legacyCertMode`
        /// gating (`Launcher.cs:249`), this applies to:
        ///   - WoW Classic 1.14.x and newer (incl. 2.5.x, 3.4.x, 4.4.x)
        ///   - WoW retail 9.x, 10.x
        ///
        /// Explicitly NOT 1.13.x:
        ///   - SignatureModulus replacement crashes `InitCredentials`
        ///     even via WriteProcessMemory at this timing point (see
        ///     `analysis/wow-1132-signature-modulus-static-patch-crashes`)
        ///   - CryptoRsaModulus is consumed as a NUL-terminated string at
        ///     a 32-bit hash site (FUN_14131a3e0). The original Blizzard
        ///     bytes contain an early NUL that bounds the loop;
        ///     replacement keys without an early NUL walk past the slot
        ///     into unmapped memory and page-fault. See
        ///     `analysis/wow-1132-crypto-rsa-modulus-not-rsa`.
        ///
        /// Default off. For 1.13.x the load-bearing replacement is
        /// ConnectToModulus alone (always applied in Phase A regardless
        /// of this flag).
        pub legacy_cert_mode: bool,
        /// Override Arxan-decryption auto-detection with a fixed wait.
        /// 0 means use the auto-detection heuristic. Only relevant when
        /// `legacy_cert_mode` is true (cert-runtime NOPs require
        /// decrypted .text).
        pub wait_seconds: u64,
        pub verbose: bool,
    }

    /// One concrete patch site -- a memory address and the bytes to
    /// write there. Constructed during the scan phase, applied during
    /// the write phase, logged during reporting.
    struct PatchOp {
        label: &'static str,
        address: usize,
        bytes: Vec<u8>,
    }

    /// Holding more than this many regions usually means we're
    /// scanning RWX-like junk that shouldn't contain our data slots.
    /// Used as a safety bound on the scan walk.
    const SCAN_MAX_REGIONS: usize = 4096;

    pub fn launch_and_patch(opts: LaunchOptions<'_>) -> Result<(), Box<dyn std::error::Error>> {
        let exe_cstr = CString::new(opts.exe_path)?;
        let work_dir = Path::new(opts.exe_path)
            .parent()
            .and_then(|p| CString::new(p.to_string_lossy().as_ref()).ok());

        let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        if opts.verbose {
            println!("Launching: {}", opts.exe_path);
        }
        let success = unsafe {
            CreateProcessA(
                exe_cstr.as_ptr() as *const u8,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null(),
                work_dir
                    .as_ref()
                    .map(|s| s.as_ptr() as *const u8)
                    .unwrap_or(std::ptr::null()),
                &startup_info,
                &mut process_info,
            )
        };
        if success == 0 {
            return Err(format!("CreateProcess failed: {}", io::Error::last_os_error()).into());
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;
        // Guard kills the process on early-return error paths so we
        // don't leak a zombie suspended client. On the success path we
        // disarm by calling `mem::forget(guard)` after the resume.
        let guard = TerminateOnDrop {
            process_handle,
            thread_handle,
        };

        if opts.verbose {
            println!("Process created (PID: {})", process_info.dwProcessId);
            println!("Resuming process for memory initialization...");
        }
        // Per Arctium-WoW-Launcher (Launcher.cs:226-237):
        //   1. Resume to let the kernel map the PE image into memory
        //   2. Wait for VirtualQueryEx to confirm the image base region
        //      is committed (RegionSize > 0x1000)
        //   3. NtSuspendProcess
        //   4. Patch .rdata data slots IMMEDIATELY (no Arxan-decryption
        //      wait -- those patches don't depend on .text decryption)
        //   5. NtResumeProcess so Arxan's TLS callback runs
        //   6. (Legacy mode only) Wait for unpack, then apply runtime
        //      .text patches (CertBundle JZ, CertCommonName, etc.)
        //
        // Static patching of SignatureModulus crashes the client at
        // startup on Wine staging 11.0 (verified for 1.13.2 -- see
        // Serena memory `analysis/wow-1132-signature-modulus-static-patch-crashes`).
        // Doing the same writes via WriteProcessMemory at THIS specific
        // moment (between memory-init-complete and Arxan-TLS-callback-
        // resume) avoids that crash because the InitCredentials code
        // path that reads the modulus has not yet executed.
        unsafe { NtResumeProcess(process_handle) };

        let base_address = wait_for_memory_init(process_handle, opts.verbose)?;
        if opts.verbose {
            println!("Base address: 0x{base_address:X}");
            println!("Suspending process to apply .rdata patches...");
        }
        unsafe { NtSuspendProcess(process_handle) };

        // Validate RSA key once up front.
        let rsa_key = opts.key_config.rsa_modulus().to_vec();
        if rsa_key.len() != 256 {
            return Err(format!("RSA modulus must be 256 bytes, got {}", rsa_key.len()).into());
        }

        // ---- PHASE A: data slot patches (always applied) ----
        //
        // Per Arctium's `Launcher.cs:262-273`. These hit `.rdata` only,
        // so they don't depend on Arxan having decrypted `.text` -- we
        // can apply them right after memory init.
        //
        //   - ConnectToModulus  (always)
        //   - CryptoRsaModulus  (1.13.x; superseded by Ed25519 in
        //                        clients newer than 1.14.4 retail)
        //   - Ed25519           (when present in the binary; harmless to
        //                        attempt scan if absent)
        //   - Portal            (.actual.battle.net rewrite)
        //   - VersionUrl        (TACT versions endpoint)
        //   - CdnsUrl           (TACT CDN list endpoint)
        //   - CertBundleUrl     (cert-bundle download URL; optional)
        //
        // Patches that DON'T go in Phase A:
        //   - SignatureModulus: legacy_cert_mode only. On 1.13.2 the
        //     bundle pin verifies against ConnectToModulus, so leaving
        //     SignatureModulus stock is correct (and necessary --
        //     replacing it crashes InitCredentials on Wine).
        //   - Cert bundle bytes / cert-runtime NOPs / Integrity NOPs:
        //     legacy_cert_mode only. See PHASE B.
        let scan_start = base_address;
        let scan_end = scan_start.saturating_add(0x10_000_000); // 256 MiB
        let mut patches: Vec<PatchOp> = Vec::new();

        scan_and_queue(
            process_handle,
            scan_start,
            scan_end,
            "RSA ConnectToModulus",
            &connect_to_modulus_pattern(),
            Some(rsa_key.clone()),
            None,
            &mut patches,
            opts.verbose,
        );
        // CryptoRsaModulus is NOT in Phase A: on 1.13.2 the bytes are
        // consumed as a NUL-terminated string by FUN_14131a3e0, and our
        // replacement key (no early NUL) crashes the hasher when it
        // walks past the slot. Move under legacy_cert_mode for 1.14+
        // builds where the read-as-string path is presumed absent.
        let ed_key = opts.key_config.ed25519_public_key().to_vec();
        if ed_key.len() == 32 {
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "Ed25519 public key",
                &crypto_ed_public_key_pattern(),
                Some(ed_key),
                None,
                &mut patches,
                opts.verbose,
            );
        }
        let portal_replacement_bytes = opts.portal_domain.portal_replacement();
        scan_and_queue(
            process_handle,
            scan_start,
            scan_end,
            "BGS portal suffix",
            portal_pattern(),
            None,
            Some(make_portal_replacer(
                portal_replacement_bytes,
                portal_pattern().len(),
            )),
            &mut patches,
            opts.verbose,
        );
        if let Some(url) = opts.cert_bundle.download_url() {
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "Cert bundle URL",
                cert_bundle_url_pattern(),
                None,
                Some(make_url_replacer(
                    url.as_bytes().to_vec(),
                    cert_bundle_url_pattern().len(),
                )),
                &mut patches,
                opts.verbose,
            );
        }

        // legacy_cert_mode adds SignatureModulus + CryptoRsaModulus +
        // cert bundle bytes at the same write moment. All three are
        // unsafe on 1.13.x for distinct reasons documented on the
        // `legacy_cert_mode` field above; the assumption is that 1.14+
        // doesn't trip those code paths (untested -- the empirical
        // verification on 1.14+ is future work).
        if opts.legacy_cert_mode {
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "RSA SignatureModulus (legacy)",
                &signature_modulus_pattern(),
                Some(rsa_key.clone()),
                None,
                &mut patches,
                opts.verbose,
            );
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "RSA CryptoRsaModulus (legacy)",
                &crypto_rsa_modulus_pattern(),
                Some(rsa_key.clone()),
                None,
                &mut patches,
                opts.verbose,
            );
            if let Some(bundle) = opts.cert_bundle.bundle_bytes() {
                scan_and_queue(
                    process_handle,
                    scan_start,
                    scan_end,
                    "Cert bundle envelope (legacy)",
                    &cert_bundle_header_pattern(),
                    None,
                    Some(make_bundle_replacer(bundle.to_vec(), 32_761)),
                    &mut patches,
                    opts.verbose,
                );
            }
        }

        // Drop unused borrow so the closure-replacers aren't shadowed.
        let _unused_for_legacy_runtime_only = (
            integrity_pattern,
            integrity_pattern_alt,
            cert_bundle_branch_pattern,
            cert_common_name_pattern,
            cert_chain_pattern,
            replace_prologue_with_ret0,
            replace_first2_with_nop_pair,
            replace_jne_pair_with_movb_al_1,
            replace_first6_with_movb_bl_1,
        );

        if patches.is_empty() {
            unsafe { NtResumeProcess(process_handle) };
            std::mem::forget(guard);
            return Err(
                "No patches applied -- no patterns matched. The binary may be unsupported.".into(),
            );
        }

        // Phase A write pass.
        let mut applied = 0usize;
        for p in &patches {
            match write_memory(process_handle, p.address, &p.bytes) {
                Ok(()) => {
                    applied += 1;
                    if opts.verbose {
                        println!(
                            "  ✓ {} @ 0x{:X} ({} bytes)",
                            p.label,
                            p.address,
                            p.bytes.len()
                        );
                    }
                }
                Err(e) => {
                    if opts.verbose {
                        println!("  ✗ {} @ 0x{:X}: {}", p.label, p.address, e);
                    }
                }
            }
        }
        if opts.verbose {
            println!("Phase A: applied {applied}/{} patches.", patches.len());
            println!("Resuming process for Arxan TLS callback...");
        }
        unsafe { NtResumeProcess(process_handle) };

        // ---- PHASE B: runtime `.text` patches (legacy_cert_mode only) ----
        //
        // Mirrors Arctium's `WaitForUnpack` + the post-resume QueuePatch
        // batch (`Launcher.cs:288-300`). Required for 1.14+ legacy
        // mode where the cert-validation conditional branches in
        // `.text` need NOPing.
        //
        // For 1.13.2: this block is skipped entirely.
        if opts.legacy_cert_mode {
            if opts.verbose {
                println!("Waiting for Arxan to decrypt .text section...");
            }
            if opts.wait_seconds > 0 {
                thread::sleep(time::Duration::from_secs(opts.wait_seconds));
            } else {
                if let Err(e) =
                    wait_for_decryption(process_handle, base_address + 0x1000, opts.verbose)
                {
                    eprintln!("Warning: {e}. Skipping runtime cert patches.");
                    unsafe {
                        CloseHandle(process_handle);
                        CloseHandle(thread_handle);
                    }
                    std::mem::forget(guard);
                    return Ok(());
                }
            }

            if opts.verbose {
                println!("Suspending again to apply runtime cert patches...");
            }
            unsafe { NtSuspendProcess(process_handle) };

            let mut runtime_patches: Vec<PatchOp> = Vec::new();
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "Integrity (primary encoding)",
                &integrity_pattern(),
                None,
                Some(replace_prologue_with_ret0),
                &mut runtime_patches,
                opts.verbose,
            );
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "Integrity (alt encoding)",
                &integrity_pattern_alt(),
                None,
                Some(replace_prologue_with_ret0),
                &mut runtime_patches,
                opts.verbose,
            );
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "CertBundle branch (NOP JZ)",
                &cert_bundle_branch_pattern(),
                None,
                Some(replace_first2_with_nop_pair),
                &mut runtime_patches,
                opts.verbose,
            );
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "CertCommonName (force AL=1)",
                &cert_common_name_pattern(),
                None,
                Some(replace_jne_pair_with_movb_al_1),
                &mut runtime_patches,
                opts.verbose,
            );
            scan_and_queue(
                process_handle,
                scan_start,
                scan_end,
                "CertChain (force BL=1)",
                &cert_chain_pattern(),
                None,
                Some(replace_first6_with_movb_bl_1),
                &mut runtime_patches,
                opts.verbose,
            );

            let mut runtime_applied = 0usize;
            for p in &runtime_patches {
                match write_memory(process_handle, p.address, &p.bytes) {
                    Ok(()) => {
                        runtime_applied += 1;
                        if opts.verbose {
                            println!(
                                "  ✓ {} @ 0x{:X} ({} bytes)",
                                p.label,
                                p.address,
                                p.bytes.len()
                            );
                        }
                    }
                    Err(e) => {
                        if opts.verbose {
                            println!("  ✗ {} @ 0x{:X}: {}", p.label, p.address, e);
                        }
                    }
                }
            }
            if opts.verbose {
                println!(
                    "Phase B: applied {runtime_applied}/{} runtime patches.",
                    runtime_patches.len()
                );
                println!("Final resume.");
            }
            unsafe { NtResumeProcess(process_handle) };
        }

        // Disarm the guard -- we want the process to keep running.
        std::mem::forget(guard);
        unsafe {
            CloseHandle(process_handle);
            CloseHandle(thread_handle);
        }
        Ok(())
    }

    // ---- Pattern scanning + replacement helpers ----

    type ReplacerFn = fn(&[u8]) -> Vec<u8>;

    /// Scan committed memory regions for `pattern`. For each match,
    /// either use the supplied `replacement` (must be `pattern.len()`
    /// bytes) or call `make_replacement` with the matched bytes to
    /// produce the bytes to write.
    ///
    /// Patches are appended to `out`. Errors during region read are
    /// non-fatal (the region is skipped).
    #[allow(clippy::too_many_arguments)]
    fn scan_and_queue(
        process_handle: HANDLE,
        scan_start: usize,
        scan_end: usize,
        label: &'static str,
        pattern: &Pattern,
        replacement: Option<Vec<u8>>,
        make_replacement: Option<ReplacerFn>,
        out: &mut Vec<PatchOp>,
        verbose: bool,
    ) {
        let pattern_len = pattern.len();
        if pattern_len == 0 {
            return;
        }
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let mut addr = scan_start;
        let mut regions_visited = 0usize;
        let mut found_any = false;

        while addr < scan_end && regions_visited < SCAN_MAX_REGIONS {
            regions_visited += 1;
            let qresult =
                unsafe { VirtualQueryEx(process_handle, addr as *const _, &mut mbi, mbi_size) };
            if qresult == 0 {
                // End of address space or query failed -- stop.
                break;
            }
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            let next_addr = region_base.saturating_add(region_size);

            if mbi.State != MEM_COMMIT || region_size < pattern_len {
                addr = next_addr;
                continue;
            }

            // Read region bytes (cap at a sane buffer to avoid O(GiB)
            // allocations on huge regions).
            const MAX_REGION_READ: usize = 32 * 1024 * 1024;
            let read_size = region_size.min(MAX_REGION_READ);
            let mut buf = vec![0u8; read_size];
            let mut bytes_read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    process_handle,
                    region_base as *const _,
                    buf.as_mut_ptr() as *mut _,
                    read_size,
                    &mut bytes_read,
                )
            };
            if ok == 0 || bytes_read < pattern_len {
                addr = next_addr;
                continue;
            }
            buf.truncate(bytes_read);

            // Match the pattern against the buffer. We use the same
            // wildcard semantics as the static patcher (i16 == -1
            // matches anything; values 0..=255 must match exactly).
            let mut local_off = 0usize;
            while local_off + pattern_len <= buf.len() {
                let mut matched = true;
                for (i, &p) in pattern.iter().enumerate() {
                    if p >= 0 && buf[local_off + i] != p as u8 {
                        matched = false;
                        break;
                    }
                }
                if matched {
                    let match_addr = region_base + local_off;
                    let matched_bytes = &buf[local_off..local_off + pattern_len];
                    let bytes = if let Some(ref r) = replacement {
                        r.clone()
                    } else if let Some(make) = make_replacement {
                        make(matched_bytes)
                    } else {
                        // No replacement supplied -- just record the
                        // location for visibility.
                        Vec::new()
                    };
                    if !bytes.is_empty() {
                        out.push(PatchOp {
                            label,
                            address: match_addr,
                            bytes,
                        });
                        found_any = true;
                    }
                    // Move past this match -- patterns shouldn't
                    // overlap meaningfully for our use case.
                    local_off += pattern_len;
                } else {
                    local_off += 1;
                }
            }

            addr = next_addr;
        }

        if verbose && !found_any {
            println!("  ⚠ {label}: pattern not found");
        }
    }

    /// Write `bytes` at `address` in the target process. Temporarily
    /// flips page protection to PAGE_EXECUTE_READWRITE if needed.
    fn write_memory(
        process_handle: HANDLE,
        address: usize,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut old_protect: u32 = 0;
        // Try to bump protection so we can write to executable pages.
        // Failure is non-fatal -- WriteProcessMemory may still succeed
        // depending on what the page already allows.
        unsafe {
            VirtualProtectEx(
                process_handle,
                address as *mut _,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            );
        }
        let mut written: usize = 0;
        let ok = unsafe {
            WriteProcessMemory(
                process_handle,
                address as *mut _,
                bytes.as_ptr() as *const _,
                bytes.len(),
                &mut written,
            )
        };
        if old_protect != 0 {
            let mut tmp: u32 = 0;
            unsafe {
                VirtualProtectEx(
                    process_handle,
                    address as *mut _,
                    bytes.len(),
                    old_protect,
                    &mut tmp,
                );
            }
        }
        if ok == 0 || written < bytes.len() {
            return Err(format!(
                "WriteProcessMemory failed at 0x{:X}: {}",
                address,
                io::Error::last_os_error()
            )
            .into());
        }
        Ok(())
    }

    // ---- Replacement byte builders for patterns that aren't a
    //      simple drop-in of `replacement_bytes` ----

    fn replace_prologue_with_ret0(matched: &[u8]) -> Vec<u8> {
        let mut out = matched.to_vec();
        // C2 00 00 = `ret 0` (cdecl-style return that pops 0 bytes).
        // The remaining bytes of the matched range stay as-is so the
        // surrounding code's offset arithmetic is unaffected.
        if out.len() >= 3 {
            out[0] = 0xC2;
            out[1] = 0x00;
            out[2] = 0x00;
        }
        out
    }

    /// Patch the cert_bundle_branch site: replace the leading `JZ rel8 +0x06`
    /// with `NOP NOP` (90 90) so control falls through into the success
    /// branch unconditionally.
    fn replace_first2_with_nop_pair(matched: &[u8]) -> Vec<u8> {
        let mut out = matched.to_vec();
        if out.len() >= 2 {
            out[0] = 0x90;
            out[1] = 0x90;
        }
        out
    }

    /// Patch the cert_common_name site: replace the leading `cmp ... 0x2A;
    /// jne ...` (`80 ?? 2A 75 ??`) with `MOV AL, 0x01` (B0 01) so the
    /// CN-mismatch branch is never taken.
    fn replace_jne_pair_with_movb_al_1(matched: &[u8]) -> Vec<u8> {
        let mut out = matched.to_vec();
        if out.len() >= 2 {
            out[0] = 0xB0;
            out[1] = 0x01;
        }
        out
    }

    /// Patch the cert_chain dev-mode bypass: replace `xor bl, bl; jmp +2`
    /// (`32 DB EB 02`) plus the next two bytes with `MOV BL, 0x01;
    /// jmp +0x02` so BL is forced to 1 and execution continues into
    /// the success path.
    fn replace_first6_with_movb_bl_1(matched: &[u8]) -> Vec<u8> {
        let mut out = matched.to_vec();
        // B3 01 = `mov bl, 0x01`
        // EB 02 = `jmp +0x02` (preserves original JMP semantics)
        if out.len() >= 4 {
            out[0] = 0xB3;
            out[1] = 0x01;
            out[2] = 0xEB;
            out[3] = 0x02;
        }
        out
    }

    /// Build a closure-like replacer for the cert-bundle envelope:
    /// take the `{"Created":` match, write `bundle_bytes` followed by
    /// NUL padding to fill `slot_size`. The match itself is just the
    /// 11-byte header; we expand the write to cover the full bundle
    /// slot starting at the match address.
    fn make_bundle_replacer(bundle_bytes: Vec<u8>, slot_size: usize) -> ReplacerFn {
        // Cannot capture variables in fn pointers, so encode via a
        // thread-local. We have at most one cert-bundle replacer per
        // launch invocation so this is safe.
        BUNDLE_PAYLOAD.with(|cell| *cell.borrow_mut() = (bundle_bytes, slot_size));
        bundle_replacer
    }

    fn bundle_replacer(_matched: &[u8]) -> Vec<u8> {
        BUNDLE_PAYLOAD.with(|cell| {
            let (bundle, slot) = cell.borrow().clone();
            let mut out = Vec::with_capacity(slot);
            out.extend_from_slice(&bundle);
            out.resize(slot, 0);
            out
        })
    }

    fn make_url_replacer(url_bytes: Vec<u8>, slot_size: usize) -> ReplacerFn {
        URL_PAYLOAD.with(|cell| *cell.borrow_mut() = (url_bytes, slot_size));
        url_replacer
    }

    fn url_replacer(_matched: &[u8]) -> Vec<u8> {
        URL_PAYLOAD.with(|cell| {
            let (url, slot) = cell.borrow().clone();
            let mut out = Vec::with_capacity(slot);
            out.extend_from_slice(&url);
            out.resize(slot, 0);
            out
        })
    }

    fn make_portal_replacer(replacement: Vec<u8>, slot_size: usize) -> ReplacerFn {
        PORTAL_PAYLOAD.with(|cell| *cell.borrow_mut() = (replacement, slot_size));
        portal_replacer
    }

    fn portal_replacer(_matched: &[u8]) -> Vec<u8> {
        PORTAL_PAYLOAD.with(|cell| {
            let (replacement, slot) = cell.borrow().clone();
            let mut out = Vec::with_capacity(slot);
            out.extend_from_slice(&replacement);
            out.resize(slot, 0);
            out
        })
    }

    use std::cell::RefCell;
    thread_local! {
        static BUNDLE_PAYLOAD: RefCell<(Vec<u8>, usize)> = const { RefCell::new((Vec::new(), 0)) };
        static URL_PAYLOAD: RefCell<(Vec<u8>, usize)> = const { RefCell::new((Vec::new(), 0)) };
        static PORTAL_PAYLOAD: RefCell<(Vec<u8>, usize)> = const { RefCell::new((Vec::new(), 0)) };
    }

    // ---- Process-handle lifecycle ----

    struct TerminateOnDrop {
        process_handle: HANDLE,
        thread_handle: HANDLE,
    }

    impl Drop for TerminateOnDrop {
        fn drop(&mut self) {
            unsafe {
                TerminateProcess(self.process_handle, 1);
                CloseHandle(self.process_handle);
                CloseHandle(self.thread_handle);
            }
        }
    }

    // ---- Wait helpers (mirror cmd::dump's logic) ----

    /// Wait for the main module image to be mapped, then return its base
    /// address.
    ///
    /// Fast path: probe 0x140000000 (the preferred image base for WoW
    /// x64). Fallback: walk the address space for a MEM_IMAGE region
    /// starting with an `MZ` header whose size is in the 30-200 MB range
    /// covering all known WoW Classic builds (1.13.2 ~38 MB on disk
    /// through 5.5.3 ~62 MB). See cmd::dump for the dump-side variant
    /// that uses an exact PE-derived size hint.
    fn wait_for_memory_init(
        process_handle: HANDLE,
        verbose: bool,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let sleep_duration = time::Duration::from_millis(100);
        let mut attempts: u32 = 0;
        let max_attempts: u32 = 600; // 60 seconds total

        loop {
            let result = unsafe {
                VirtualQueryEx(
                    process_handle,
                    0x140000000usize as *const _,
                    &mut mbi,
                    mbi_size,
                )
            };
            if result != 0
                && mbi.RegionSize > 0x1000
                && mbi.State == MEM_COMMIT
                && mbi.Type == MEM_IMAGE
            {
                return Ok(mbi.BaseAddress as usize);
            }

            if let Some(base) = scan_for_module_image(process_handle) {
                if verbose {
                    println!("Module image located at 0x{base:X} via fallback scan");
                }
                return Ok(base);
            }

            attempts += 1;
            if attempts > max_attempts {
                return Err(format!(
                    "Timeout waiting for memory initialization after {attempts} attempts \
                     (probe at 0x140000000: result={result}, RegionSize=0x{:X}, State=0x{:X}, \
                     Type=0x{:X}, AllocationBase=0x{:X})",
                    mbi.RegionSize, mbi.State, mbi.Type, mbi.AllocationBase as usize
                )
                .into());
            }
            if verbose && attempts.is_multiple_of(10) {
                println!(
                    "Waiting for memory initialization... ({attempts}) [probe@0x140000000: \
                     result={result}, RegionSize=0x{:X}, State=0x{:X}, Type=0x{:X}, \
                     AllocationBase=0x{:X}]",
                    mbi.RegionSize, mbi.State, mbi.Type, mbi.AllocationBase as usize
                );
            }
            thread::sleep(sleep_duration);
        }
    }

    /// Walk the address space for the WoW main module image. Returns
    /// AllocationBase of the first MEM_IMAGE allocation that:
    ///   - starts with `MZ` (a PE header) at AllocationBase, and
    ///   - has total contiguous extent in the 30-200 MB range matching
    ///     known WoW Classic image sizes.
    fn scan_for_module_image(process_handle: HANDLE) -> Option<usize> {
        const LOWER: usize = 30 * 1024 * 1024;
        const UPPER: usize = 200 * 1024 * 1024;

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let mut addr: usize = 0x10000;
        let scan_ceiling: usize = 0x0000_8000_0000_0000;

        let mut current_alloc_base: usize = 0;
        let mut current_extent: usize = 0;
        let mut current_is_pe: bool = false;

        loop {
            if addr >= scan_ceiling {
                break;
            }
            let result =
                unsafe { VirtualQueryEx(process_handle, addr as *const _, &mut mbi, mbi_size) };
            if result == 0 {
                break;
            }
            let region_base = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;
            let alloc_base = mbi.AllocationBase as usize;

            if mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE && alloc_base != 0 {
                if alloc_base != current_alloc_base {
                    if current_is_pe && (LOWER..=UPPER).contains(&current_extent) {
                        return Some(current_alloc_base);
                    }
                    current_alloc_base = alloc_base;
                    current_extent = 0;
                    let mut mz = [0u8; 2];
                    let mut br: usize = 0;
                    let ok = unsafe {
                        ReadProcessMemory(
                            process_handle,
                            alloc_base as *const _,
                            mz.as_mut_ptr() as *mut _,
                            mz.len(),
                            &mut br,
                        )
                    };
                    current_is_pe = ok != 0 && br == 2 && mz == *b"MZ";
                }
                current_extent += region_size;
            } else if alloc_base != current_alloc_base && current_alloc_base != 0 {
                if current_is_pe && (LOWER..=UPPER).contains(&current_extent) {
                    return Some(current_alloc_base);
                }
                current_alloc_base = 0;
                current_extent = 0;
                current_is_pe = false;
            }

            let next = region_base.saturating_add(region_size);
            if next <= addr {
                break;
            }
            addr = next;
        }
        if current_is_pe && (LOWER..=UPPER).contains(&current_extent) {
            return Some(current_alloc_base);
        }
        None
    }

    fn wait_for_decryption(
        process_handle: HANDLE,
        text_base: usize,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sleep_duration = time::Duration::from_millis(500);
        let mut attempts: u32 = 0;
        let sample_offsets: &[usize] = &[0x100000, 0x400000, 0x800000, 0xC00000, 0x1000000];

        loop {
            let mut decrypted_count = 0;
            for &off in sample_offsets {
                let addr = text_base + off;
                let mut buf = [0u8; 16];
                let mut bytes_read: usize = 0;
                let ok = unsafe {
                    ReadProcessMemory(
                        process_handle,
                        addr as *const _,
                        buf.as_mut_ptr() as *mut _,
                        buf.len(),
                        &mut bytes_read,
                    )
                };
                if ok != 0 && bytes_read >= 16 {
                    let b0 = buf[0];
                    let b1 = buf[1];
                    let is_code = matches!(
                        b0,
                        0x48 | 0x4C
                            | 0x40
                            | 0x55
                            | 0xC3
                            | 0xC2
                            | 0xCC
                            | 0x90
                            | 0x53
                            | 0x56
                            | 0x57
                            | 0x41
                    ) || (b0 == 0x0F && b1 == 0x1F)
                        || (b0 == 0x66 && b1 == 0x90);
                    if is_code {
                        decrypted_count += 1;
                    }
                }
            }
            if decrypted_count >= 3 {
                if verbose {
                    println!(
                        "Code detected at {decrypted_count}/{} sample points -- decryption complete",
                        sample_offsets.len()
                    );
                }
                thread::sleep(time::Duration::from_secs(2));
                return Ok(());
            }
            attempts += 1;
            if attempts > 120 {
                return Err("Timeout waiting for Arxan decryption".into());
            }
            if verbose && attempts.is_multiple_of(4) {
                println!(
                    "Waiting for decryption... ({} seconds, {decrypted_count}/{} valid)",
                    attempts / 2,
                    sample_offsets.len()
                );
            }
            thread::sleep(sleep_duration);
        }
    }

    // Suppress dead-code warning for PAGE_READWRITE (referenced in
    // commented-out fallback path; kept here in case we add a less
    // permissive write helper later).
    const _: u32 = PAGE_READWRITE;
}

#[cfg(not(target_os = "windows"))]
pub fn launch_and_patch_stub() -> Result<(), Box<dyn std::error::Error>> {
    Err(
        "launch is only available on Windows (or Wine). Cross-compile with: \
         cargo build --target x86_64-pc-windows-gnu"
            .into(),
    )
}
