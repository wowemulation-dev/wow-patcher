use std::{
    ffi::{OsString, c_void},
    io,
    mem::size_of,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::Path,
    ptr,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Diagnostics::{
            Debug::{
                FlushInstructionCache, GetThreadContext, ReadProcessMemory, WriteProcessMemory,
            },
            ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPMODULE,
                TH32CS_SNAPPROCESS, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
            },
        },
        Memory::{
            MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS,
            MapViewOfFile, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
            UnmapViewOfFile, VirtualAllocEx, VirtualProtectEx, VirtualQueryEx,
        },
        Threading::{
            CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, GetExitCodeThread, OpenProcess,
            OpenThread, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW, ResumeThread, STARTUPINFOW, SuspendThread,
            THREAD_QUERY_INFORMATION, THREAD_TERMINATE, TerminateProcess, TerminateThread,
            WaitForSingleObject,
        },
    },
};

use super::Result;

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtQueryInformationThread(
        thread: HANDLE,
        class: u32,
        info: *mut c_void,
        len: u32,
        returned: *mut u32,
    ) -> i32;
    fn NtSuspendProcess(process: HANDLE) -> i32;
    fn NtResumeProcess(process: HANDLE) -> i32;
    fn NtCreateSection(
        section: *mut HANDLE,
        access: u32,
        attributes: *const c_void,
        maximum_size: *mut i64,
        protection: u32,
        allocation_attributes: u32,
        file: HANDLE,
    ) -> i32;
    fn NtUnmapViewOfSection(process: HANDLE, address: *const c_void) -> i32;
    fn NtMapViewOfSection(
        section: HANDLE,
        process: HANDLE,
        address: *mut *mut c_void,
        zero_bits: usize,
        commit_size: usize,
        offset: *mut i64,
        view_size: *mut usize,
        inherit: u32,
        allocation_type: u32,
        protection: u32,
    ) -> i32;
}

pub(super) struct Handle(HANDLE);

impl Handle {
    fn new(raw: HANDLE) -> Result<Self> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(raw))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(super) struct Process {
    handle: Handle,
    _main_thread: Handle,
    pub pid: u32,
    pub base: usize,
    released: bool,
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.released {
            unsafe {
                TerminateProcess(self.handle.0, 1);
                WaitForSingleObject(self.handle.0, 5000);
            }
        }
    }
}

impl Process {
    pub fn ensure_not_running(executable: &Path) -> Result<()> {
        let snapshot = Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
        let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of_val(&entry) as u32;
        let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
        while found != 0 {
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            if String::from_utf16_lossy(&entry.szExeFile[..end]).eq_ignore_ascii_case("Wow.exe") {
                let process = unsafe {
                    OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID)
                };
                let process = Handle::new(process).map_err(|error| {
                    format!(
                        "Another Wow.exe (PID {}) is running but its path cannot be queried: {error}",
                        entry.th32ProcessID
                    )
                })?;
                let mut path = vec![0u16; 32768];
                let mut length = path.len() as u32;
                if unsafe {
                    QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length)
                } == 0
                {
                    return Err(format!(
                        "Another Wow.exe (PID {}) is running but its path cannot be queried: {}",
                        entry.th32ProcessID,
                        io::Error::last_os_error()
                    )
                    .into());
                }
                path.truncate(length as usize);
                let running = OsString::from_wide(&path);
                if Path::new(&running)
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&executable.to_string_lossy())
                {
                    return Err(format!(
                        "This client is already running as PID {}",
                        entry.th32ProcessID
                    )
                    .into());
                }
            }
            found = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }
        Ok(())
    }

    pub fn create(executable: &Path, config: &str) -> Result<Self> {
        let path: Vec<u16> = executable
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let folder: Vec<u16> = executable
            .parent()
            .ok_or("Missing game directory")?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        // Both strings were validated before launch; neither can contain a quote.
        let mut command: Vec<u16> = format!("\"{}\" -config \"{}\"", executable.display(), config)
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            CreateProcessW(
                path.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED,
                ptr::null(),
                folder.as_ptr(),
                &startup,
                &mut info,
            )
        };
        if ok == 0 {
            return Err(format!("CreateProcessW: {}", io::Error::last_os_error()).into());
        }
        let mut process = Self {
            handle: Handle::new(info.hProcess)?,
            _main_thread: Handle::new(info.hThread)?,
            pid: info.dwProcessId,
            base: 0,
            released: false,
        };
        // PROCESS_BASIC_INFORMATION is six pointer-sized fields on Windows x64.
        let mut basic = [0usize; 6];
        let status = unsafe {
            NtQueryInformationProcess(
                process.handle.0,
                0,
                basic.as_mut_ptr().cast(),
                size_of_val(&basic) as u32,
                ptr::null_mut(),
            )
        };
        check_status(status, "Querying process information")?;
        process.base = usize::from_le_bytes(process.read(basic[1] + 0x10, 8)?.try_into().unwrap());
        if process.base == 0 {
            return Err("The client image base is null".into());
        }
        Ok(process)
    }

    pub fn read(&self, address: usize, length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0; length];
        let mut read = 0;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle.0,
                address as _,
                bytes.as_mut_ptr().cast(),
                length,
                &mut read,
            )
        };
        if ok == 0 || read != length {
            return Err(format!(
                "ReadProcessMemory at 0x{address:X}: {} ({read}/{length} bytes)",
                io::Error::last_os_error()
            )
            .into());
        }
        Ok(bytes)
    }

    pub fn write(&self, address: usize, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let first_page = address & !0xfff;
        let last_page = address
            .checked_add(bytes.len() - 1)
            .ok_or("Remote write address overflow")?
            & !0xfff;
        let mut pages = Vec::new();
        let result: Result<()> = (|| {
            let mut page = first_page;
            loop {
                let mut old = 0;
                if unsafe {
                    VirtualProtectEx(self.handle.0, page as _, 0x1000, PAGE_READWRITE, &mut old)
                } == 0
                {
                    return Err(format!(
                        "VirtualProtectEx at 0x{page:X}: {}",
                        io::Error::last_os_error()
                    )
                    .into());
                }
                pages.push((page, old));
                if page == last_page {
                    break;
                }
                page = page
                    .checked_add(0x1000)
                    .ok_or("Remote write page overflow")?;
            }
            let mut written = 0;
            let ok = unsafe {
                WriteProcessMemory(
                    self.handle.0,
                    address as _,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    &mut written,
                )
            };
            if ok == 0 || written != bytes.len() {
                return Err(format!(
                    "WriteProcessMemory at 0x{address:X}: {} ({written}/{})",
                    io::Error::last_os_error(),
                    bytes.len()
                )
                .into());
            }
            if self.read(address, bytes.len())? != bytes {
                return Err(format!("Write verification failed at 0x{address:X}").into());
            }
            Ok(())
        })();
        let mut restoration: Result<()> = Ok(());
        for (page, protection) in pages {
            let mut discarded = 0;
            if unsafe {
                VirtualProtectEx(self.handle.0, page as _, 0x1000, protection, &mut discarded)
            } == 0
                && restoration.is_ok()
            {
                restoration =
                    Err(format!("Restoring memory protection at 0x{page:X} failed").into());
            }
        }
        result?;
        restoration?;
        self.flush(address, bytes.len())
    }

    pub fn flush(&self, address: usize, length: usize) -> Result<()> {
        if unsafe { FlushInstructionCache(self.handle.0, address as _, length) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn protect(&self, address: usize, length: usize, protection: u32) -> Result<u32> {
        let mut old = 0;
        if unsafe { VirtualProtectEx(self.handle.0, address as _, length, protection, &mut old) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(old)
    }

    pub fn allocate(&self, length: usize, protection: u32) -> Result<usize> {
        let address = unsafe {
            VirtualAllocEx(
                self.handle.0,
                ptr::null(),
                length,
                MEM_COMMIT | MEM_RESERVE,
                protection,
            )
        };
        if address.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        Ok(address as usize)
    }

    pub fn region(&self, address: usize) -> Result<MEMORY_BASIC_INFORMATION> {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { VirtualQueryEx(self.handle.0, address as _, &mut info, size_of_val(&info)) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(info)
    }

    pub fn protection(&self, address: usize) -> Result<u32> {
        Ok(self.region(address)?.Protect)
    }

    pub fn suspend(&self) -> Result<()> {
        check_status(
            unsafe { NtSuspendProcess(self.handle.0) },
            "Suspending client",
        )
    }

    pub fn resume(&self) -> Result<()> {
        check_status(unsafe { NtResumeProcess(self.handle.0) }, "Resuming client")
    }

    pub fn resume_initial(&self) -> Result<()> {
        if unsafe { ResumeThread(self._main_thread.0) } == u32::MAX {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    pub fn initial_thread_rip(&self) -> Result<usize> {
        if unsafe { SuspendThread(self._main_thread.0) } == u32::MAX {
            return Err(io::Error::last_os_error().into());
        }
        let result: Result<usize> = (|| {
            let mut context = vec![0u128; 77];
            let pointer = context.as_mut_ptr().cast::<u8>();
            unsafe {
                pointer.cast::<u32>().add(12).write(0x00100001);
                if GetThreadContext(self._main_thread.0, pointer.cast()) == 0 {
                    return Err(io::Error::last_os_error().into());
                }
                Ok(pointer.add(0xf8).cast::<usize>().read_unaligned())
            }
        })();
        let resumed = unsafe { ResumeThread(self._main_thread.0) };
        let rip = result?;
        if resumed == u32::MAX {
            return Err(io::Error::last_os_error().into());
        }
        Ok(rip)
    }

    pub fn ensure_running(&self) -> Result<()> {
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err("The client exited during runtime preparation".into()),
            _ => Err(io::Error::last_os_error().into()),
        }
    }

    pub fn release(mut self) -> Result<()> {
        self.ensure_running()?;
        self.released = true;
        Ok(())
    }

    pub fn run_reader(&self, address: usize) -> Result<()> {
        // The address points to the validated, image-resident x64 reader stub.
        let entry = unsafe {
            std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(address)
        };
        let thread = Handle::new(unsafe {
            CreateRemoteThread(
                self.handle.0,
                ptr::null(),
                0,
                Some(entry),
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        })?;
        if unsafe { WaitForSingleObject(thread.0, 5000) } != WAIT_OBJECT_0 {
            return Err("The image reader did not finish within five seconds".into());
        }
        // Its return value is the last qword read, not a status code.
        self.ensure_running()
    }

    pub fn run_zero_reader(&self, address: usize, timeout: Duration) -> Result<()> {
        let entry = unsafe {
            std::mem::transmute::<usize, unsafe extern "system" fn(*mut c_void) -> u32>(address)
        };
        let thread = Handle::new(unsafe {
            CreateRemoteThread(
                self.handle.0,
                ptr::null(),
                0,
                Some(entry),
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        })?;
        let deadline = Instant::now() + timeout;
        loop {
            self.ensure_running()?;
            match unsafe { WaitForSingleObject(thread.0, 50) } {
                WAIT_OBJECT_0 => {
                    let mut exit = u32::MAX;
                    if unsafe { GetExitCodeThread(thread.0, &mut exit) } == 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                    if exit != 0 {
                        return Err(format!("Code-page reader exited with 0x{exit:08X}").into());
                    }
                    return Ok(());
                }
                WAIT_TIMEOUT if Instant::now() < deadline => {}
                WAIT_TIMEOUT => return Err("Code-page preparation timed out".into()),
                _ => return Err(io::Error::last_os_error().into()),
            }
        }
    }

    pub fn loader_module(&self) -> Result<Option<(usize, usize)>> {
        let snapshot =
            Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid) })?;
        let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of_val(&entry) as u32;
        let mut found = unsafe { Module32FirstW(snapshot.0, &mut entry) };
        let mut loader = None;
        while found != 0 {
            let end = entry
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szModule.len());
            if String::from_utf16_lossy(&entry.szModule[..end])
                .eq_ignore_ascii_case("Wow_loader.dll")
            {
                if loader.is_some() {
                    return Err("More than one Wow_loader.dll module is loaded".into());
                }
                loader = Some((entry.modBaseAddr as usize, entry.modBaseSize as usize));
            }
            found = unsafe { Module32NextW(snapshot.0, &mut entry) };
        }
        Ok(loader)
    }

    pub fn loader_workers(&self, loader: (usize, usize)) -> Result<Vec<Handle>> {
        let snapshot = Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of_val(&entry) as u32;
        let mut found = unsafe { Thread32First(snapshot.0, &mut entry) };
        let mut workers = Vec::new();
        while found != 0 {
            if entry.th32OwnerProcessID == self.pid
                && let Ok(thread) = Handle::new(unsafe {
                    OpenThread(
                        THREAD_QUERY_INFORMATION | THREAD_TERMINATE,
                        0,
                        entry.th32ThreadID,
                    )
                })
            {
                let mut start = 0usize;
                let status = unsafe {
                    NtQueryInformationThread(
                        thread.0,
                        9,
                        (&mut start as *mut usize).cast(),
                        8,
                        ptr::null_mut(),
                    )
                };
                if status == 0 && (loader.0..loader.0 + loader.1).contains(&start) {
                    workers.push(thread);
                }
            }
            found = unsafe { Thread32Next(snapshot.0, &mut entry) };
        }
        Ok(workers)
    }

    pub fn replace_mapping(&self, mapping: usize, bytes: &[u8]) -> Result<()> {
        let mut raw_section = ptr::null_mut();
        let mut maximum_size = i64::try_from(bytes.len())?;
        check_status(
            unsafe {
                NtCreateSection(
                    &mut raw_section,
                    0xf001f,
                    ptr::null(),
                    &mut maximum_size,
                    PAGE_EXECUTE_READWRITE,
                    0x08400000,
                    ptr::null_mut(),
                )
            },
            "Creating loader replacement section",
        )?;
        let section = Handle::new(raw_section)?;
        let mut staging = MEMORY_MAPPED_VIEW_ADDRESS::default();
        let result = (|| {
            staging = unsafe { MapViewOfFile(section.0, 2, 0, 0, bytes.len()) };
            if staging.Value.is_null() {
                return Err(io::Error::last_os_error().into());
            }
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), staging.Value.cast::<u8>(), bytes.len());
                if UnmapViewOfFile(staging) == 0 {
                    return Err(io::Error::last_os_error().into());
                }
            }
            staging = MEMORY_MAPPED_VIEW_ADDRESS::default();
            check_status(
                unsafe { NtUnmapViewOfSection(self.handle.0, mapping as _) },
                "Unmapping original loader code",
            )?;
            let mut actual = mapping as *mut c_void;
            let mut view_size = bytes.len();
            check_status(
                unsafe {
                    NtMapViewOfSection(
                        section.0,
                        self.handle.0,
                        &mut actual,
                        0,
                        0,
                        ptr::null_mut(),
                        &mut view_size,
                        2,
                        0,
                        PAGE_EXECUTE_READ,
                    )
                },
                "Mapping replacement loader code",
            )?;
            if actual as usize != mapping || view_size != bytes.len() {
                return Err(format!(
                    "Loader remap changed address/size: 0x{:X}/{view_size}, expected 0x{mapping:X}/{}",
                    actual as usize,
                    bytes.len()
                )
                .into());
            }
            Ok(())
        })();
        if !staging.Value.is_null() {
            unsafe {
                UnmapViewOfFile(staging);
            }
        }
        result
    }

    pub fn stop_workers(&self, workers: &[Handle]) -> Result<()> {
        if workers.len() != 7 {
            return Err("Expected exactly seven loader workers".into());
        }
        for thread in workers {
            if unsafe { TerminateThread(thread.0, 1) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
}

fn check_status(status: i32, operation: &str) -> Result<()> {
    if status < 0 {
        return Err(format!("{operation} failed: NTSTATUS 0x{status:08X}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::PAGE_READONLY;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};

    #[test]
    fn failed_owned_launch_is_terminated_and_writes_restore_protection() {
        // A suspended copy of this test executable never executes the test suite.
        let process = Process::create(&std::env::current_exe().unwrap(), "Config.wtf").unwrap();
        let observer =
            Handle::new(unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, process.pid) }).unwrap();
        let address = process.allocate(32, PAGE_READONLY).unwrap();
        process.write(address, b"verified write").unwrap();
        assert_eq!(process.read(address, 14).unwrap(), b"verified write");
        assert_eq!(process.protection(address).unwrap(), PAGE_READONLY);
        let previous = process
            .protect(address, 32, PAGE_EXECUTE_READWRITE)
            .unwrap();
        assert_eq!(previous, PAGE_READONLY);
        process.write(address, b"temporary stub").unwrap();
        assert_eq!(process.protection(address).unwrap(), PAGE_EXECUTE_READWRITE);
        process.protect(address, 32, previous).unwrap();
        assert_eq!(process.protection(address).unwrap(), PAGE_READONLY);
        assert_eq!(unsafe { WaitForSingleObject(observer.0, 0) }, WAIT_TIMEOUT);
        drop(process);
        assert_eq!(
            unsafe { WaitForSingleObject(observer.0, 5000) },
            WAIT_OBJECT_0
        );
    }
}
