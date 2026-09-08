/// Dump sections from a running WoW process.
///
/// Arxan TransformIT encrypts the .text section and zeroes most of .data
/// in the static PE image. This module launches the client suspended,
/// lets Arxan decrypt via its TLS callback, optionally waits for C++
/// static initialization to populate .data, then reads section bytes
/// from process memory.
///
/// Windows-only. Designed to run under Wine for cross-platform use.
#[cfg(target_os = "windows")]
pub mod win {
    use std::ffi::CString;
    use std::path::Path;
    use std::{io, thread, time};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, VirtualProtectEx,
        VirtualQueryEx,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, TerminateProcess,
    };

    // ntdll functions not in windows-sys — link manually
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(process_handle: HANDLE) -> i32;
        fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    }

    /// Describes one section in the PE file.
    #[derive(Debug, Clone)]
    pub struct SectionInfo {
        pub name: String,
        pub virtual_address: u64,
        pub virtual_size: usize,
    }

    /// Parse all sections from PE headers on disk.
    fn read_all_sections(exe_path: &str) -> Result<Vec<SectionInfo>, Box<dyn std::error::Error>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut f = std::fs::File::open(exe_path)?;

        f.seek(SeekFrom::Start(0x3C))?;
        let mut buf4 = [0u8; 4];
        f.read_exact(&mut buf4)?;
        let pe_offset = u32::from_le_bytes(buf4) as u64;

        f.seek(SeekFrom::Start(pe_offset + 4))?;
        let mut coff = [0u8; 20];
        f.read_exact(&mut coff)?;
        let num_sections = u16::from_le_bytes([coff[2], coff[3]]);
        let opt_header_size = u16::from_le_bytes([coff[16], coff[17]]);

        let sections_offset = pe_offset + 4 + 20 + opt_header_size as u64;
        f.seek(SeekFrom::Start(sections_offset))?;

        let mut sections = Vec::with_capacity(num_sections as usize);
        for _ in 0..num_sections {
            let mut section = [0u8; 40];
            f.read_exact(&mut section)?;
            let name = std::str::from_utf8(&section[..8])
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();
            let virtual_size =
                u32::from_le_bytes([section[8], section[9], section[10], section[11]]) as usize;
            let virtual_address =
                u32::from_le_bytes([section[12], section[13], section[14], section[15]]) as u64;
            sections.push(SectionInfo {
                name,
                virtual_address,
                virtual_size,
            });
        }
        Ok(sections)
    }

    /// Find a specific section by name.
    fn find_section<'a>(
        sections: &'a [SectionInfo],
        name: &str,
    ) -> Result<&'a SectionInfo, Box<dyn std::error::Error>> {
        sections
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| format!("No {name} section found in PE headers").into())
    }

    /// Legacy entry point: dump just the .text section.
    pub fn dump_text_section(
        exe_path: &str,
        output_path: &str,
        wait_seconds: u64,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        dump_sections(
            exe_path,
            &[(String::from(".text"), String::from(output_path))],
            wait_seconds,
            0, // no post-decryption wait
            verbose,
        )
    }

    /// Dump one or more named sections to separate output files.
    ///
    /// For `.text`: resume process, wait for Arxan to decrypt, dump.
    /// For `.data` and others: resume process, wait for decryption AND
    /// static-initialization (`post_decrypt_wait` seconds), then dump.
    ///
    /// Multiple sections can be dumped in a single process invocation —
    /// the process is snapshotted once at the latest requested timing.
    pub fn dump_sections(
        exe_path: &str,
        targets: &[(String, String)],
        wait_seconds: u64,
        post_decrypt_wait: u64,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let all_sections = read_all_sections(exe_path)?;

        // Resolve each requested section name to its header info
        let mut resolved: Vec<(SectionInfo, String)> = Vec::with_capacity(targets.len());
        for (name, out_path) in targets {
            let info = find_section(&all_sections, name)?;
            resolved.push((info.clone(), out_path.clone()));
        }

        if verbose {
            for (info, out) in &resolved {
                println!(
                    "Planned dump: {:8} RVA 0x{:X}, size {} bytes ({:.1} MB) -> {}",
                    info.name,
                    info.virtual_address,
                    info.virtual_size,
                    info.virtual_size as f64 / 1_048_576.0,
                    out,
                );
            }
        }

        let exe_cstr = CString::new(exe_path)?;
        let work_dir = Path::new(exe_path)
            .parent()
            .and_then(|p| CString::new(p.to_string_lossy().as_ref()).ok());

        let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        if verbose {
            println!("Launching: {exe_path}");
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
        let _guard = scopeguard(process_handle, thread_handle);

        if verbose {
            println!("Process created (PID: {})", process_info.dwProcessId);
            println!("Resuming process for Arxan decryption...");
        }
        unsafe { NtResumeProcess(process_handle) };

        // Total image size hint from PE headers — last section's VA+VSize
        // rounded up gives an upper bound for the loaded image. Used to
        // verify a scanned candidate region is the main module image,
        // not some unrelated mapping.
        let image_size_hint: usize = all_sections
            .iter()
            .map(|s| s.virtual_address as usize + s.virtual_size)
            .max()
            .unwrap_or(0);

        let base_address = wait_for_memory_init(process_handle, image_size_hint, verbose)?;
        if verbose {
            println!("Base address: 0x{base_address:X}");
        }

        // Reference point for decryption detection: the .text section
        let text_info = find_section(&all_sections, ".text")?;
        let text_base = base_address + text_info.virtual_address as usize;

        if wait_seconds > 0 {
            if verbose {
                println!("Waiting {wait_seconds} seconds for Arxan decryption...");
            }
            thread::sleep(time::Duration::from_secs(wait_seconds));
        } else {
            wait_for_decryption(process_handle, text_base, verbose)?;
        }

        // Additional wait for static initialization and startup code.
        // Useful when dumping .data which needs C++ ctors to have run.
        if post_decrypt_wait > 0 {
            if verbose {
                println!(
                    "Waiting {post_decrypt_wait} additional seconds for static init / startup..."
                );
            }
            thread::sleep(time::Duration::from_secs(post_decrypt_wait));
        }

        if verbose {
            println!("Suspending process...");
        }
        unsafe { NtSuspendProcess(process_handle) };

        // Snapshot each requested section
        for (info, out_path) in &resolved {
            let section_base = base_address + info.virtual_address as usize;
            if verbose {
                println!(
                    "Reading section {}: 0x{:X} ({} bytes / {:.1} MB)",
                    info.name,
                    section_base,
                    info.virtual_size,
                    info.virtual_size as f64 / 1_048_576.0,
                );
            }

            let buffer = read_section_with_protect_fallback(
                process_handle,
                section_base,
                info.virtual_size,
                &info.name,
                verbose,
            )?;
            let bytes_read = buffer.len();

            if verbose {
                println!("  Read {bytes_read} bytes");
            }

            std::fs::write(out_path, &buffer)?;
            println!(
                "Dumped {} section to: {out_path} ({bytes_read} bytes)",
                info.name
            );
        }

        Ok(())
    }

    /// Wait for the main module image to be mapped, then return its base
    /// address.
    ///
    /// Fast path: probe 0x140000000 (the preferred image base for WoW
    /// x64). If a committed image-backed region is mapped there, return.
    ///
    /// Fallback path (used when 0x140000000 isn't mapped — e.g. clients
    /// with a `*_loader.dll` sidecar that load the main image elsewhere):
    /// walk the address space via VirtualQueryEx, find the first
    /// MEM_IMAGE allocation whose first page starts with `MZ` (a PE
    /// header) and whose extent matches the on-disk image size hint
    /// (±25%). Return the AllocationBase.
    ///
    /// Diagnostic logging every 10 attempts dumps what the fast-path
    /// probe sees (RegionSize, State, Type, AllocationBase) so an
    /// operator can tell whether the image is unmapped, reserved, or
    /// mapped at a different base.
    fn wait_for_memory_init(
        process_handle: HANDLE,
        image_size_hint: usize,
        verbose: bool,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let sleep_duration = time::Duration::from_millis(100);
        let mut attempts = 0;
        let max_attempts = 600; // 60 seconds total

        loop {
            // Fast path: probe the preferred image base.
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

            // Fallback: scan for a MEM_IMAGE region of the expected size
            // anywhere in the user address space. The PE header (an `MZ`
            // signature) is read from the candidate's AllocationBase to
            // confirm it is a module image.
            if let Some(base) = scan_for_module_image(process_handle, image_size_hint) {
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
                     Type=0x{:X}, AllocationBase=0x{:X}). The main module did not become \
                     mapped at 0x140000000 and the fallback MEM_IMAGE scan found no match.",
                    mbi.RegionSize, mbi.State, mbi.Type, mbi.AllocationBase as usize
                )
                .into());
            }

            if verbose && attempts % 10 == 0 {
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

    /// Walk the target process address space looking for the main module
    /// image. Returns the AllocationBase of the first MEM_IMAGE region
    /// that:
    ///   1. Has an `MZ` PE signature at its AllocationBase.
    ///   2. Has a total extent (sum of contiguous regions sharing the
    ///      same AllocationBase) within 25% of `image_size_hint`.
    ///
    /// Returns None if no candidate is found in this pass.
    fn scan_for_module_image(process_handle: HANDLE, image_size_hint: usize) -> Option<usize> {
        if image_size_hint == 0 {
            return None;
        }
        let lower = image_size_hint.saturating_mul(3) / 4;
        let upper = image_size_hint.saturating_mul(5) / 4;

        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        let mut addr: usize = 0x10000; // skip the null page
        let mut last_alloc_base: usize = 0;
        let mut current_extent: usize = 0;
        let mut current_alloc_base: usize = 0;
        let mut current_is_pe: bool = false;

        // Cap the scan to the 64-bit user-mode address space WoW would
        // realistically occupy (8 TiB upper bound; Windows user-mode is
        // typically 128 TiB but WoW images live in the low region).
        let scan_ceiling: usize = 0x0000_8000_0000_0000;

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
                    // Starting a new allocation — finalize the previous.
                    if current_is_pe && current_extent >= lower && current_extent <= upper {
                        return Some(current_alloc_base);
                    }
                    current_alloc_base = alloc_base;
                    current_extent = 0;
                    // Probe MZ at AllocationBase
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
                    last_alloc_base = alloc_base;
                }
                current_extent += region_size;
            } else if alloc_base != current_alloc_base && current_alloc_base != 0 {
                // Region for a different (or no) allocation — finalize.
                if current_is_pe && current_extent >= lower && current_extent <= upper {
                    return Some(current_alloc_base);
                }
                current_alloc_base = 0;
                current_extent = 0;
                current_is_pe = false;
            }
            let _ = last_alloc_base; // silence unused

            // Advance past this region.
            let next = region_base.saturating_add(region_size);
            if next <= addr {
                break;
            }
            addr = next;
        }

        // Finalize the trailing allocation.
        if current_is_pe && current_extent >= lower && current_extent <= upper {
            return Some(current_alloc_base);
        }
        None
    }

    /// Read a section's worth of bytes from the target process.
    ///
    /// First attempts a single ReadProcessMemory. If that fails
    /// (typically ERROR_ACCESS_DENIED on Wine when an Arxan-decrypted
    /// `.text` page is mapped PAGE_EXECUTE without read permission),
    /// walks the section page-by-page, temporarily flipping each
    /// region to PAGE_EXECUTE_READ via VirtualProtectEx, reading, and
    /// restoring the original protection. Pages that remain unreadable
    /// (e.g. PAGE_NOACCESS guard pages, or never-committed BSS tail)
    /// are zero-filled in the output buffer.
    fn read_section_with_protect_fallback(
        process_handle: HANDLE,
        section_base: usize,
        section_size: usize,
        section_name: &str,
        verbose: bool,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut buffer = vec![0u8; section_size];

        // Fast path: one big read.
        let mut bytes_read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                process_handle,
                section_base as *const _,
                buffer.as_mut_ptr() as *mut _,
                section_size,
                &mut bytes_read,
            )
        };
        if ok != 0 && bytes_read == section_size {
            return Ok(buffer);
        }

        if verbose {
            let err = io::Error::last_os_error();
            println!(
                "  Bulk ReadProcessMemory partial/failed for {section_name} \
                 ({bytes_read}/{section_size} bytes, error: {err}). Falling back \
                 to per-region read with VirtualProtectEx."
            );
        }

        // Fallback: walk the section page-by-page, bumping protection
        // as needed. Track unreadable regions for diagnostic output.
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let section_end = section_base + section_size;
        let mut cursor = section_base;
        let mut total_read: usize = 0;
        let mut total_unreadable: usize = 0;
        let mut protect_flips: usize = 0;

        while cursor < section_end {
            let qres =
                unsafe { VirtualQueryEx(process_handle, cursor as *const _, &mut mbi, mbi_size) };
            if qres == 0 {
                // Treat unmapped tail as zero-fill.
                total_unreadable += section_end - cursor;
                break;
            }
            let region_base = mbi.BaseAddress as usize;
            let region_end = region_base.saturating_add(mbi.RegionSize);
            let read_from = cursor.max(region_base);
            let read_to = section_end.min(region_end);
            let read_len = read_to.saturating_sub(read_from);

            if read_len == 0 {
                // Pathological: advance to avoid infinite loop.
                cursor = region_end.max(cursor + 0x1000);
                continue;
            }

            if mbi.State != MEM_COMMIT {
                // Uncommitted (reserved or free) — zero-fill in buffer.
                total_unreadable += read_len;
                cursor = read_to;
                continue;
            }

            let buf_off = read_from - section_base;
            let mut br: usize = 0;
            let mut ok2 = unsafe {
                ReadProcessMemory(
                    process_handle,
                    read_from as *const _,
                    buffer[buf_off..buf_off + read_len].as_mut_ptr() as *mut _,
                    read_len,
                    &mut br,
                )
            };

            if ok2 == 0 || br < read_len {
                // Bump protection to PAGE_EXECUTE_READ for the region
                // and retry.
                let mut old_protect: u32 = 0;
                let protect_ok = unsafe {
                    VirtualProtectEx(
                        process_handle,
                        read_from as *mut _,
                        read_len,
                        PAGE_EXECUTE_READ,
                        &mut old_protect,
                    )
                };
                if protect_ok != 0 {
                    protect_flips += 1;
                    br = 0;
                    ok2 = unsafe {
                        ReadProcessMemory(
                            process_handle,
                            read_from as *const _,
                            buffer[buf_off..buf_off + read_len].as_mut_ptr() as *mut _,
                            read_len,
                            &mut br,
                        )
                    };
                    // Restore original protection (best-effort).
                    let mut tmp: u32 = 0;
                    unsafe {
                        VirtualProtectEx(
                            process_handle,
                            read_from as *mut _,
                            read_len,
                            old_protect,
                            &mut tmp,
                        );
                    }
                }
            }

            if ok2 != 0 && br > 0 {
                total_read += br;
                if br < read_len {
                    total_unreadable += read_len - br;
                }
            } else {
                total_unreadable += read_len;
            }

            cursor = read_to;
        }

        if verbose {
            println!(
                "  Per-region read for {section_name}: {total_read} bytes \
                 readable, {total_unreadable} bytes zero-filled, \
                 {protect_flips} protection flips"
            );
        }

        if total_read == 0 {
            return Err(format!(
                "ReadProcessMemory failed for section {section_name}: \
                 no readable bytes recovered (section_base=0x{:X}, size={})",
                section_base, section_size
            )
            .into());
        }

        Ok(buffer)
    }

    fn wait_for_decryption(
        process_handle: HANDLE,
        text_base: usize,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sleep_duration = time::Duration::from_millis(500);
        let mut attempts = 0;

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
                        "Code detected at {decrypted_count}/{} sample points — decryption complete",
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

            if verbose && attempts % 4 == 0 {
                println!(
                    "Waiting for decryption... ({} seconds, {decrypted_count}/{} valid)",
                    attempts / 2,
                    sample_offsets.len()
                );
            }

            thread::sleep(sleep_duration);
        }
    }

    struct ProcessGuard {
        process_handle: HANDLE,
        thread_handle: HANDLE,
    }

    impl Drop for ProcessGuard {
        fn drop(&mut self) {
            unsafe {
                TerminateProcess(self.process_handle, 0);
                CloseHandle(self.process_handle);
                CloseHandle(self.thread_handle);
            }
        }
    }

    fn scopeguard(process_handle: HANDLE, thread_handle: HANDLE) -> ProcessGuard {
        ProcessGuard {
            process_handle,
            thread_handle,
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn dump_text_section(
    _exe_path: &str,
    _output_path: &str,
    _wait: u64,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("dump-text is only available on Windows (or Wine)".into())
}

#[cfg(not(target_os = "windows"))]
pub fn dump_sections(
    _exe_path: &str,
    _targets: &[(String, String)],
    _wait: u64,
    _post_decrypt_wait: u64,
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("dump-sections is only available on Windows (or Wine)".into())
}
