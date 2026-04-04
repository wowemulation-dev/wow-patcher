/// Dump decrypted .text section from a running WoW process.
///
/// Arxan TransformIT encrypts the .text section in the static PE image.
/// This module launches the client suspended, lets Arxan decrypt via its
/// TLS callback, then reads the decrypted .text bytes from process memory.
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
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessA, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOA,
        CREATE_SUSPENDED,
    };

    // ntdll functions not in windows-sys — link manually
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtResumeProcess(process_handle: HANDLE) -> i32;
        fn NtSuspendProcess(process_handle: HANDLE) -> i32;
    }

    /// Parse .text section RVA and virtual size from PE headers on disk.
    fn read_text_section_info(
        exe_path: &str,
    ) -> Result<(u64, usize), Box<dyn std::error::Error>> {
        use std::io::{Read, Seek, SeekFrom};

        let mut f = std::fs::File::open(exe_path)?;

        // DOS header: e_lfanew at offset 0x3C
        f.seek(SeekFrom::Start(0x3C))?;
        let mut buf4 = [0u8; 4];
        f.read_exact(&mut buf4)?;
        let pe_offset = u32::from_le_bytes(buf4) as u64;

        // PE signature (4) + COFF header (20)
        f.seek(SeekFrom::Start(pe_offset + 4))?;
        let mut coff = [0u8; 20];
        f.read_exact(&mut coff)?;
        let num_sections = u16::from_le_bytes([coff[2], coff[3]]);
        let opt_header_size = u16::from_le_bytes([coff[16], coff[17]]);

        // Skip optional header to reach section headers
        let sections_offset = pe_offset + 4 + 20 + opt_header_size as u64;
        f.seek(SeekFrom::Start(sections_offset))?;

        for _ in 0..num_sections {
            let mut section = [0u8; 40];
            f.read_exact(&mut section)?;
            let name = std::str::from_utf8(&section[..8])
                .unwrap_or("")
                .trim_end_matches('\0');
            if name == ".text" {
                let virtual_size = u32::from_le_bytes([
                    section[8], section[9], section[10], section[11],
                ]) as usize;
                let virtual_address = u32::from_le_bytes([
                    section[12], section[13], section[14], section[15],
                ]) as u64;
                return Ok((virtual_address, virtual_size));
            }
        }

        Err("No .text section found in PE headers".into())
    }

    /// Launch Wow.exe suspended, wait for Arxan to decrypt, dump .text section.
    pub fn dump_text_section(
        exe_path: &str,
        output_path: &str,
        wait_seconds: u64,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Read .text section info from PE headers
        let (text_start_rva, text_size) = read_text_section_info(exe_path)?;
        if verbose {
            println!(
                ".text section: RVA 0x{:X}, size {} bytes ({:.1} MB)",
                text_start_rva,
                text_size,
                text_size as f64 / 1_048_576.0
            );
        }

        let exe_cstr = CString::new(exe_path)?;
        let work_dir = Path::new(exe_path)
            .parent()
            .map(|p| CString::new(p.to_string_lossy().as_ref()).ok())
            .flatten();

        let mut startup_info: STARTUPINFOA = unsafe { std::mem::zeroed() };
        startup_info.cb = std::mem::size_of::<STARTUPINFOA>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        if verbose {
            println!("Launching: {exe_path}");
        }

        // Step 1: Create process suspended
        let success = unsafe {
            CreateProcessA(
                exe_cstr.as_ptr() as *const u8,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0, // bInheritHandles = false
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
            return Err(format!(
                "CreateProcess failed: {}",
                io::Error::last_os_error()
            )
            .into());
        }

        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;

        // Ensure cleanup on any exit path
        let _guard = scopeguard(process_handle, thread_handle);

        if verbose {
            println!("Process created (PID: {})", process_info.dwProcessId);
        }

        // Step 2: Resume to let Arxan TLS callback decrypt .text
        if verbose {
            println!("Resuming process for Arxan decryption...");
        }
        unsafe { NtResumeProcess(process_handle) };

        // Step 3: Wait for memory region to initialize
        let base_address = wait_for_memory_init(process_handle, verbose)?;

        if verbose {
            println!("Base address: 0x{base_address:X}");
        }

        // Step 4: Wait for Arxan to finish decrypting
        let text_base = base_address + text_start_rva as usize;

        if wait_seconds > 0 {
            // Timer-based: wait a fixed duration for Arxan to complete
            if verbose {
                println!("Waiting {wait_seconds} seconds for Arxan decryption...");
            }
            thread::sleep(time::Duration::from_secs(wait_seconds));
        } else {
            // Verification-based: poll until bytes at a known offset change
            // from their encrypted form
            wait_for_decryption(process_handle, text_base, verbose)?;
        }

        // Step 5: Suspend the process
        if verbose {
            println!("Suspending process...");
        }
        unsafe { NtSuspendProcess(process_handle) };

        // Step 6: Read decrypted .text section
        if verbose {
            println!(
                "Reading .text section: 0x{:X} ({} bytes / {:.1} MB)",
                text_base,
                text_size,
                text_size as f64 / 1_048_576.0
            );
        }

        let mut buffer = vec![0u8; text_size];
        let mut bytes_read: usize = 0;

        let read_ok = unsafe {
            ReadProcessMemory(
                process_handle,
                text_base as *const _,
                buffer.as_mut_ptr() as *mut _,
                text_size,
                &mut bytes_read,
            )
        };

        if read_ok == 0 {
            return Err(format!(
                "ReadProcessMemory failed: {}",
                io::Error::last_os_error()
            )
            .into());
        }

        if verbose {
            println!("Read {bytes_read} bytes from process memory");
        }

        // Step 7: Write dump to file
        std::fs::write(output_path, &buffer[..bytes_read])?;
        println!(
            "Dumped decrypted .text section to: {output_path} ({bytes_read} bytes)"
        );

        // Step 8: Terminate (cleanup handled by _guard)
        Ok(())
    }

    /// Wait for the process memory region to be initialized.
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
                    0x140000000usize as *const _, // Expected image base for 64-bit PE
                    &mut mbi,
                    mbi_size,
                )
            };

            if result != 0 && mbi.RegionSize > 0x1000 && mbi.State == MEM_COMMIT {
                return Ok(mbi.BaseAddress as usize);
            }

            attempts += 1;
            if attempts > 300 {
                // 30 seconds
                return Err("Timeout waiting for memory initialization".into());
            }

            if verbose && attempts % 10 == 0 {
                println!("Waiting for memory initialization... ({attempts})");
            }

            thread::sleep(sleep_duration);
        }
    }

    /// Wait for Arxan decryption by checking if code bytes have changed.
    ///
    /// Reads a sample of bytes from several offsets in .text and checks if
    /// they form valid x86-64 instruction patterns. Encrypted bytes are
    /// high-entropy random-looking data; decrypted code has structure
    /// (common prologues, ret instructions, nop padding).
    fn wait_for_decryption(
        process_handle: HANDLE,
        text_base: usize,
        verbose: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sleep_duration = time::Duration::from_millis(500);
        let mut attempts = 0;

        // Sample offsets deep into .text (avoid the entry point area which
        // may already have some unencrypted code)
        let sample_offsets: &[usize] = &[
            0x100000,  // ~1MB in
            0x400000,  // ~4MB in
            0x800000,  // ~8MB in
            0xC00000,  // ~12MB in
            0x1000000, // ~16MB in
        ];

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
                    // Check for common x86-64 patterns that indicate decrypted code:
                    // - Function prologues: 48 89 5C (mov [rsp+..], rbx)
                    // - Push rbp: 55 or 40 55
                    // - Sub rsp: 48 83 EC or 48 81 EC
                    // - Ret: C3, C2
                    // - Int3 padding: CC CC CC
                    // - Nop: 90, 66 90, 0F 1F
                    let b0 = buf[0];
                    let b1 = buf[1];
                    let is_code = matches!(b0, 0x48 | 0x4C | 0x40 | 0x55 | 0xC3 | 0xC2 | 0xCC | 0x90 | 0x53 | 0x56 | 0x57 | 0x41)
                        || (b0 == 0x0F && b1 == 0x1F)
                        || (b0 == 0x66 && b1 == 0x90);

                    if is_code {
                        decrypted_count += 1;
                    }
                }
            }

            // If most samples look like valid code, decryption is likely done
            if decrypted_count >= 3 {
                if verbose {
                    println!(
                        "Code detected at {decrypted_count}/{} sample points — decryption complete",
                        sample_offsets.len()
                    );
                }
                // Wait a bit more to ensure full decryption
                thread::sleep(time::Duration::from_secs(2));
                return Ok(());
            }

            attempts += 1;
            if attempts > 120 {
                // 60 seconds
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

    /// RAII guard for process handle cleanup.
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
    _verbose: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("dump-text is only available on Windows (or Wine)".into())
}
