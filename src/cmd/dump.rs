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
        MEM_COMMIT, MEMORY_BASIC_INFORMATION, VirtualQueryEx,
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

        let base_address = wait_for_memory_init(process_handle, verbose)?;
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

            let mut buffer = vec![0u8; info.virtual_size];
            let mut bytes_read: usize = 0;

            let read_ok = unsafe {
                ReadProcessMemory(
                    process_handle,
                    section_base as *const _,
                    buffer.as_mut_ptr() as *mut _,
                    info.virtual_size,
                    &mut bytes_read,
                )
            };

            if read_ok == 0 {
                return Err(format!(
                    "ReadProcessMemory failed for section {}: {}",
                    info.name,
                    io::Error::last_os_error()
                )
                .into());
            }

            if verbose {
                println!("  Read {bytes_read} bytes");
            }

            std::fs::write(out_path, &buffer[..bytes_read])?;
            println!(
                "Dumped {} section to: {out_path} ({bytes_read} bytes)",
                info.name
            );
        }

        Ok(())
    }

    fn wait_for_memory_init(
        process_handle: HANDLE,
        verbose: bool,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();
        let sleep_duration = time::Duration::from_millis(100);
        let mut attempts = 0;

        loop {
            let result = unsafe {
                VirtualQueryEx(
                    process_handle,
                    0x140000000usize as *const _,
                    &mut mbi,
                    mbi_size,
                )
            };

            if result != 0 && mbi.RegionSize > 0x1000 && mbi.State == MEM_COMMIT {
                return Ok(mbi.BaseAddress as usize);
            }

            attempts += 1;
            if attempts > 300 {
                return Err("Timeout waiting for memory initialization".into());
            }

            if verbose && attempts % 10 == 0 {
                println!("Waiting for memory initialization... ({attempts})");
            }

            thread::sleep(sleep_duration);
        }
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
