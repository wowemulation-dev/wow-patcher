use std::{
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READ, PAGE_NOACCESS, PAGE_READONLY};

use super::{process::Process, *};

struct CodeSite {
    rva: usize,
    signature: &'static str,
}

const CODE_SITES: &[CodeSite] = &[
    CodeSite {
        rva: FILE_RESOLVER,
        signature: "48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD",
    },
    CodeSite {
        rva: PATH_GATE,
        signature: "41 F6 C5 01 74 ?? 85 ED 74 ?? 48 8B 0D ?? ?? ?? ?? 8B D5 E8",
    },
    CodeSite {
        rva: CERT_DEV,
        signature: "48 89 5C 24 18 57 48 83 EC 40 80 79 5D 00 48 8B F9",
    },
    CodeSite {
        rva: SYSTEM_CERT,
        signature: "?? ?? EB 02 B3 01 48 8B CE FF 15 FB 10 25 00",
    },
    CodeSite {
        rva: COMMON_NAME,
        signature: "?? ?? ?? ?? ?? ?? ?? B6 F0 84 C0 0F 85 ED 02 00 00",
    },
];

fn matches(actual: &[u8], signature: &str) -> bool {
    let pattern: Vec<_> = signature.split_whitespace().collect();
    actual.len() == pattern.len()
        && actual.iter().zip(pattern).all(|(&byte, expected)| {
            expected == "??" || u8::from_str_radix(expected, 16) == Ok(byte)
        })
}

fn validate_code(process: &Process) -> Result<()> {
    for site in CODE_SITES {
        let bytes = process.read(
            process.base + site.rva,
            site.signature.split_whitespace().count(),
        )?;
        if !matches(&bytes, site.signature) {
            return Err(format!("Decrypted code mismatch at RVA 0x{:X}", site.rva).into());
        }
    }
    Ok(())
}

fn wait_until<T>(
    process: &Process,
    timeout: Duration,
    description: &str,
    mut check: impl FnMut() -> Result<Option<T>>,
) -> Result<T> {
    let deadline = Instant::now() + timeout;
    loop {
        process.ensure_running()?;
        if let Some(value) = check()? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(format!("Timed out waiting for {description}").into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn launch(opts: &Options, plan: &Plan) -> Result<()> {
    let process = Process::create(&plan.executable, &opts.config)?;
    println!("Created client PID {}", process.pid);
    for patch in &plan.data {
        let address = process.base + patch.rva;
        if process.read(address, patch.original.len())? != patch.original {
            return Err(format!("{} changed before patching", patch.name).into());
        }
        process.write(address, &patch.replacement)?;
    }
    process.resume()?;
    let loader = wait_until(
        &process,
        opts.timeout,
        "the protected entry point and loader",
        || {
            // Module snapshots can fail while the loader changes the module list.
            if let Ok(Some(loader)) = process.loader_module()
                && process.protection(process.base + plan.entry_rva)? == PAGE_NOACCESS
            {
                return Ok(Some(loader));
            }
            Ok(None)
        },
    )?;
    thread::sleep(Duration::from_millis(2200));
    let workers = wait_until(&process, opts.timeout, "seven loader workers", || {
        let workers = process.loader_workers(loader)?;
        match workers.len() {
            7 => Ok(Some(workers)),
            0..7 => Ok(None),
            _ => Err("Unexpected loader worker count; refusing this startup layout".into()),
        }
    })?;
    process.stop_workers(&workers)?;
    println!("Stopped seven loader workers; preparing code pages");
    process.suspend()?;

    let cave = process.base + TEXT_START + TEXT_SIZE;
    let saved = process.read(cave, read_stub(0, 0).len())?;
    if saved.iter().any(|&byte| byte != 0) {
        return Err("The temporary code space after .text is not empty".into());
    }
    let deadline = Instant::now() + opts.timeout;
    let ranges = sweep_ranges();
    for (start, end) in &ranges {
        if Instant::now() >= deadline {
            return Err("Code-page preparation timed out".into());
        }
        process.write(cave, &read_stub(process.base + start, process.base + end))?;
        process.run_reader(cave)?;
    }
    process.write(cave, &saved)?;
    process.resume()?;
    println!(
        "Prepared {} code ranges; temporary bytes restored",
        ranges.len()
    );

    wait_until(
        &process,
        opts.timeout,
        "the five plaintext code signatures",
        || Ok(validate_code(&process).ok()),
    )?;
    process.suspend()?;
    // Recheck after suspension so no detour is installed against stale bytes.
    validate_code(&process)?;
    let path = plan
        .certificate
        .to_str()
        .ok_or("Invalid certificate path")?;
    let mut path_bytes = path.as_bytes().to_vec();
    path_bytes.push(0);
    let path_address = process.allocate(path_bytes.len(), PAGE_READONLY)?;
    process.write(path_address, &path_bytes)?;

    let handler_len = certificate_handler(0, 0).len();
    let handler = process.allocate(handler_len + PROLOGUE.len() + 12, PAGE_EXECUTE_READ)?;
    let trampoline = handler + handler_len;
    let mut trampoline_code = PROLOGUE.to_vec();
    trampoline_code.extend_from_slice(&absolute_jump(
        process.base + FILE_RESOLVER + PROLOGUE.len(),
    ));
    process.write(trampoline, &trampoline_code)?;
    process.write(handler, &certificate_handler(path_address, trampoline))?;
    let mut detour = absolute_jump(handler);
    detour.resize(PROLOGUE.len(), 0x90);

    let code_patches = [
        (FILE_RESOLVER, detour),
        (PATH_GATE + 4, vec![0x90, 0x90]),
        (CERT_DEV, vec![0x33, 0xc0, 0xc3]),
        (SYSTEM_CERT, vec![0xb3, 0x01]),
        (COMMON_NAME, vec![0xbf, 0x01, 0, 0, 0, 0x90, 0x90]),
    ];
    for (rva, bytes) in &code_patches {
        process.write(process.base + rva, bytes)?;
        if opts.verbose {
            println!("Verified code patch: RVA 0x{rva:X}, {} bytes", bytes.len());
        }
    }
    for patch in &plan.data {
        if process.read(process.base + patch.rva, patch.replacement.len())? != patch.replacement {
            return Err(format!("{} did not survive startup", patch.name).into());
        }
    }
    process.resume()?;
    println!(
        "Retail patches installed and verified; client PID {} resumed",
        process.pid
    );
    process.release()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_require_full_windows_and_reject_changed_instructions() {
        assert!(matches(&[0x48, 0xff, 0xc3], "48 ?? C3"));
        assert!(!matches(&[0x49, 0xff, 0xc3], "48 ?? C3"));
        assert!(!matches(&[0x48, 0xff], "48 ?? C3"));
        assert!(!matches(&[0x48, 0xff, 0xc3, 0], "48 ?? C3"));
        assert!(
            CODE_SITES[0]
                .signature
                .starts_with("48 89 5C 24 08 57 48 83 EC 20 48 8B F9")
        );
    }
}
