use std::{ffi::c_void, io, mem::size_of, os::windows::ffi::OsStrExt, path::Path, ptr};

use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{
        Diagnostics::{
            Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory},
            ToolHelp::{
                CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW,
                TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
            },
        },
        Memory::{
            MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE,
            VirtualAllocEx, VirtualProtectEx, VirtualQueryEx,
        },
        Threading::{
            CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, OpenThread, PROCESS_INFORMATION,
            STARTUPINFOW, THREAD_QUERY_INFORMATION, THREAD_TERMINATE, TerminateProcess,
            TerminateThread, WaitForSingleObject,
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
        let mut old = 0;
        let ok = unsafe {
            VirtualProtectEx(
                self.handle.0,
                address as _,
                bytes.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        };
        if ok == 0 {
            return Err(format!(
                "VirtualProtectEx at 0x{address:X}: {}",
                io::Error::last_os_error()
            )
            .into());
        }
        let result: Result<()> = (|| {
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
                    "WriteProcessMemory at 0x{address:X}: {}",
                    io::Error::last_os_error()
                )
                .into());
            }
            if unsafe { FlushInstructionCache(self.handle.0, address as _, bytes.len()) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(())
        })();
        // Restore protection even when the write or cache flush failed.
        let mut discarded = 0;
        let restored = unsafe {
            VirtualProtectEx(
                self.handle.0,
                address as _,
                bytes.len(),
                old,
                &mut discarded,
            )
        };
        result?;
        if restored == 0 {
            return Err("Restoring memory protection failed".into());
        }
        if self.read(address, bytes.len())? != bytes {
            return Err(format!("Write verification failed at 0x{address:X}").into());
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

    pub fn protection(&self, address: usize) -> Result<u32> {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { VirtualQueryEx(self.handle.0, address as _, &mut info, size_of_val(&info)) }
            == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(info.Protect)
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

    pub fn loader_module(&self) -> Result<Option<(usize, usize)>> {
        let snapshot =
            Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, self.pid) })?;
        let mut entry: MODULEENTRY32W = unsafe { std::mem::zeroed() };
        entry.dwSize = size_of_val(&entry) as u32;
        let mut found = unsafe { Module32FirstW(snapshot.0, &mut entry) };
        while found != 0 {
            let end = entry
                .szModule
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szModule.len());
            if String::from_utf16_lossy(&entry.szModule[..end])
                .eq_ignore_ascii_case("Wow_loader.dll")
            {
                return Ok(Some((
                    entry.modBaseAddr as usize,
                    entry.modBaseSize as usize,
                )));
            }
            found = unsafe { Module32NextW(snapshot.0, &mut entry) };
        }
        Ok(None)
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
