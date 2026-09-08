//! Opt-in runtime recipe for retail 12.0.7.68887.
//!
//! Encrypted code is validated in memory before any certificate patch is written.
//! The default static patcher and the existing launch command are independent.

mod process;
mod runtime;

use std::{fs, path::PathBuf, time::Duration};

use crate::platform::{Version, extract_version};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(crate) struct Options {
    pub executable: PathBuf,
    pub server_cert: PathBuf,
    pub portal_suffix: Option<String>,
    pub config: String,
    pub version_url: Option<String>,
    pub ed25519: Vec<u8>,
    pub timeout: Duration,
    pub dry_run: bool,
    pub verbose: bool,
}

struct DataPatch {
    name: &'static str,
    rva: usize,
    original: Vec<u8>,
    replacement: Vec<u8>,
}

struct Plan {
    executable: PathBuf,
    certificate: PathBuf,
    entry_rva: usize,
    data: Vec<DataPatch>,
}

const TEXT_START: usize = 0x1000;
const TEXT_SIZE: usize = 0x35c0b4c;
const FILE_RESOLVER: usize = 0x33ff200;
const PATH_GATE: usize = 0x33f5543;
const CERT_DEV: usize = 0x265fc80;
const SYSTEM_CERT: usize = 0x337105e;
const COMMON_NAME: usize = 0x336e721;
const PROLOGUE: &[u8] = &[
    0x48, 0x89, 0x5c, 0x24, 0x08, 0x57, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xf9,
];

fn padded_string(value: &str, capacity: usize) -> Result<Vec<u8>> {
    if !value.is_ascii() || value.as_bytes().contains(&0) || value.len() >= capacity {
        return Err(format!(
            "Replacement must be ASCII without NUL, at most {} bytes",
            capacity - 1
        )
        .into());
    }
    let mut bytes = vec![0; capacity];
    bytes[..value.len()].copy_from_slice(value.as_bytes());
    Ok(bytes)
}

fn client_path(path: &std::path::Path) -> Result<PathBuf> {
    let absolute = fs::canonicalize(path)?;
    let value = absolute
        .to_str()
        .ok_or("Client paths must be valid Unicode")?;
    // The client normalizes separators internally and cannot open its data
    // cache when the working directory retains a verbatim Windows prefix.
    Ok(if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else {
        PathBuf::from(value.strip_prefix(r"\\?\").unwrap_or(value))
    })
}

fn prepare(opts: &Options) -> Result<Plan> {
    if extract_version(&opts.executable) != Some(Version::new(12, 0, 7, 68887)) {
        return Err(
            "launch-retail supports only 12.0.7.68887; other builds need a verified runtime recipe"
                .into(),
        );
    }
    let executable = client_path(&opts.executable)?;
    let folder = executable.parent().ok_or("Missing executable directory")?;
    if !folder.join("Wow_loader.dll").is_file() {
        return Err("Wow_loader.dll must be beside the executable and match its build".into());
    }
    if opts.config.is_empty()
        || opts.config.contains(['/', '\\', '"', '\0', ':'])
        || !folder.join("WTF").join(&opts.config).is_file()
    {
        return Err("--config must name an existing file in the client's WTF directory".into());
    }
    let certificate = client_path(&opts.server_cert)?;
    // The client's file-path hook uses a narrow, NUL-terminated path.
    let cert_path = certificate
        .to_str()
        .ok_or("Certificate path must be ASCII")?;
    if !cert_path.is_ascii() {
        return Err("Certificate path must be ASCII".into());
    }
    let pem = fs::read_to_string(&certificate)?;
    if !pem.contains("-----BEGIN CERTIFICATE-----")
        || !pem.contains("-----END CERTIFICATE-----")
        || pem.contains("PRIVATE KEY")
    {
        return Err(
            "--server-cert must contain a public PEM certificate and no private key".into(),
        );
    }
    if opts.ed25519.len() != 32 {
        return Err("Ed25519 key must contain 32 bytes".into());
    }
    let bytes = fs::read(&executable)?;
    let pe = goblin::pe::PE::parse(&bytes)?;
    if !pe.is_64 || pe.header.coff_header.machine != 0x8664 {
        return Err("The runtime recipe requires an x64 PE image".into());
    }
    let text = pe
        .sections
        .iter()
        .find(|s| s.name().ok() == Some(".text"))
        .ok_or("Missing .text section")?;
    if text.virtual_address as usize != TEXT_START || text.virtual_size as usize != TEXT_SIZE {
        return Err("Unexpected .text layout for 12.0.7.68887".into());
    }
    let mut data = Vec::new();
    let mut add = |name, rva: usize, anchor: &[u8], replacement: Vec<u8>| -> Result<()> {
        let size = replacement.len();
        let section = pe
            .sections
            .iter()
            .find(|s| {
                let start = s.virtual_address as usize;
                matches!(s.name().ok(), Some(".rdata" | ".data"))
                    && rva >= start
                    && rva + size <= start + s.size_of_raw_data as usize
            })
            .ok_or("Data patch extends outside a file-backed data section")?;
        let offset = section.pointer_to_raw_data as usize + rva - section.virtual_address as usize;
        let original = bytes
            .get(offset..offset + size)
            .ok_or("Truncated data patch slot")?;
        if !original.starts_with(anchor) {
            return Err(
                format!("{name} does not match the original bytes at RVA 0x{rva:X}").into(),
            );
        }
        data.push(DataPatch {
            name,
            rva,
            original: original.to_vec(),
            replacement,
        });
        Ok(())
    };
    add(
        "Ed25519 public key",
        0x35ebf30,
        &[0x15, 0xd6, 0x18, 0xbd, 0x7d, 0xb5, 0x77, 0xbd],
        opts.ed25519.clone(),
    )?;
    if let Some(suffix) = &opts.portal_suffix {
        add(
            "Portal suffix",
            0x37cdaa0,
            b".actual.battle.net\0",
            padded_string(suffix, 19)?,
        )?;
    }
    if let Some(url) = &opts.version_url {
        for (rva, original) in [
            (
                0x3993770,
                "https://cn.version.battlenet.com.cn/v2/products/%s/%s",
            ),
            (0x39937b0, "https://%s.version.battle.net/v2/products/%s/%s"),
        ] {
            add(
                "Version URL",
                rva,
                original.as_bytes(),
                padded_string(url, original.len() + 1)?,
            )?;
        }
    }
    Ok(Plan {
        entry_rva: pe.entry as usize,
        executable,
        certificate,
        data,
    })
}

pub(crate) fn run(opts: Options) -> Result<()> {
    let plan = prepare(&opts)?;
    println!("Retail runtime recipe: 12.0.7.68887");
    for patch in &plan.data {
        println!(
            "  {}: RVA 0x{:X}, {} bytes",
            patch.name,
            patch.rva,
            patch.replacement.len()
        );
    }
    println!("  Certificate file: {}", plan.certificate.display());
    if opts.dry_run {
        println!(
            "Dry run: input checks passed; startup preparation and five code writes require a live process. No process started or files written."
        );
        return Ok(());
    }
    runtime::launch(&opts, &plan)?;
    Ok(())
}

fn absolute_jump(destination: usize) -> Vec<u8> {
    let mut code = vec![0x48, 0xb8];
    code.extend_from_slice(&(destination as u64).to_le_bytes());
    code.extend_from_slice(&[0xff, 0xe0]);
    code
}

fn certificate_handler(path: usize, trampoline: usize) -> Vec<u8> {
    // cmp edx,7725530; jne original; mov rax,path; ret; original: jmp trampoline.
    // Negative and all other file ids retain the original resolver's behavior.
    let mut code = vec![0x81, 0xfa];
    code.extend_from_slice(&7725530u32.to_le_bytes());
    code.extend_from_slice(&[0x75, 11, 0x48, 0xb8]);
    code.extend_from_slice(&(path as u64).to_le_bytes());
    code.push(0xc3);
    code.extend_from_slice(&absolute_jump(trampoline));
    code
}

fn read_stub(start: usize, end: usize) -> Vec<u8> {
    let mut code = vec![0x48, 0xbb];
    code.extend_from_slice(&(start as u64).to_le_bytes());
    code.extend_from_slice(&[0x48, 0xb9]);
    code.extend_from_slice(&(end as u64).to_le_bytes());
    code.extend_from_slice(&[
        0x48, 0xba, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x48, 0x39, 0xcb, 0x0f, 0x8d, 0x0b, 0, 0, 0,
        0x48, 0x8b, 0x03, 0x48, 0x01, 0xd3, 0xe9, 0xec, 0xff, 0xff, 0xff, 0xc3,
    ]);
    code
}

fn sweep_ranges() -> Vec<(usize, usize)> {
    // Reproduce the 100 skipped pages used to validate this build. The final
    // range ends at the virtual section boundary, not the next page boundary.
    const SKIP: [usize; 100] = [
        18, 194, 268, 356, 393, 433, 534, 621, 807, 1014, 1453, 1638, 1663, 1822, 1893, 1975, 2259,
        2293, 2583, 2599, 2669, 2864, 2877, 3061, 3153, 3163, 3303, 3670, 4049, 4205, 4267, 4782,
        4914, 5138, 5522, 5653, 5720, 5810, 5925, 6028, 6161, 6190, 6527, 6534, 7025, 7095, 7280,
        7314, 7476, 7508, 7742, 7748, 7797, 8001, 8099, 8420, 8433, 8439, 8547, 8583, 8720, 8913,
        9056, 9381, 9477, 9582, 9595, 9673, 9690, 10103, 10391, 10418, 10445, 10536, 10576, 10674,
        10784, 10831, 10872, 11035, 11122, 11150, 11405, 11967, 12003, 12155, 12209, 12233, 12682,
        12703, 12789, 12991, 12992, 13124, 13386, 13394, 13425, 13510, 13669, 13727,
    ];
    let mut ranges = Vec::new();
    let mut cursor = TEXT_START;
    for stop in SKIP
        .into_iter()
        .map(|page| TEXT_START + page * 0x1000)
        .chain(std::iter::once(TEXT_START + TEXT_SIZE))
    {
        if cursor < stop {
            ranges.push((cursor, stop));
        }
        cursor = stop + 0x1000;
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_paths_do_not_keep_verbatim_windows_prefixes() {
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join("certificate file.pem");
        fs::write(&input, b"test").unwrap();
        let path = client_path(&input).unwrap();
        assert!(path.is_absolute());
        assert!(!path.to_str().unwrap().starts_with(r"\\?\"));
        assert_eq!(fs::read(path).unwrap(), b"test");
    }

    #[test]
    fn certificate_handler_executes_both_routes() {
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc, VirtualFree,
        };
        let allocation = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        assert!(!allocation.is_null());
        struct Allocation(*mut std::ffi::c_void);
        impl Drop for Allocation {
            fn drop(&mut self) {
                unsafe {
                    VirtualFree(self.0, 0, MEM_RELEASE);
                }
            }
        }
        let allocation = Allocation(allocation);
        let trampoline = allocation.0 as usize + 128;
        // The original resolver substitute returns a distinct marker.
        let original = [0xb8, 0x78, 0x56, 0x34, 0x12, 0xc3];
        let handler = certificate_handler(0x123456789, trampoline);
        unsafe {
            std::ptr::copy_nonoverlapping(original.as_ptr(), trampoline as *mut u8, original.len());
            std::ptr::copy_nonoverlapping(handler.as_ptr(), allocation.0.cast(), handler.len());
            let call = std::mem::transmute::<
                *mut std::ffi::c_void,
                extern "system" fn(usize, i32) -> usize,
            >(allocation.0);
            assert_eq!(call(0, 7725530), 0x123456789);
            for id in [-1, i32::MIN, 0, 7725529, 7725531, i32::MAX] {
                assert_eq!(call(0, id), 0x12345678);
            }
        }
    }

    #[test]
    fn string_slots_require_a_terminator_and_preserve_explicit_empty_suffix() {
        assert_eq!(padded_string("", 19).unwrap(), vec![0; 19]);
        assert_eq!(padded_string("abc", 4).unwrap(), b"abc\0");
        assert!(padded_string("abcd", 4).is_err());
        assert!(padded_string("a\0b", 4).is_err());
        assert!(padded_string("é", 4).is_err());
    }

    #[test]
    fn sweep_excludes_exactly_100_pages_and_covers_patch_targets() {
        let ranges = sweep_ranges();
        let pages: usize = ranges
            .iter()
            .map(|(start, end)| (end - start).div_ceil(0x1000))
            .sum();
        assert_eq!(pages, TEXT_SIZE.div_ceil(0x1000) - 100);
        assert_eq!(ranges.last().unwrap().1, TEXT_START + TEXT_SIZE);
        for pair in ranges.windows(2) {
            assert!(pair[0].1 < pair[1].0);
        }
        for site in [FILE_RESOLVER, PATH_GATE, CERT_DEV, SYSTEM_CERT, COMMON_NAME] {
            assert!(
                ranges
                    .iter()
                    .any(|&(start, end)| site >= start && site < end)
            );
        }
    }

    #[test]
    fn reader_branches_stay_within_stub() {
        let code = read_stub(0x140001000, 0x1435c1b4c);
        assert_eq!(code.len(), 51);
        assert_eq!(
            u64::from_le_bytes(code[2..10].try_into().unwrap()),
            0x140001000
        );
        assert_eq!(
            u64::from_le_bytes(code[12..20].try_into().unwrap()),
            0x1435c1b4c
        );
        assert_eq!(
            39 + i32::from_le_bytes(code[35..39].try_into().unwrap()),
            50
        );
        assert_eq!(
            50 + i32::from_le_bytes(code[46..50].try_into().unwrap()),
            30
        );
    }

    #[test]
    fn certificate_handler_routes_other_ids_to_original_code() {
        let code = certificate_handler(0x123456789, 0x987654321);
        assert_eq!(u32::from_le_bytes(code[2..6].try_into().unwrap()), 7725530);
        let fallback = 8 + code[7] as usize;
        assert_eq!(&code[fallback..], absolute_jump(0x987654321));
        assert_eq!(
            u64::from_le_bytes(code[10..18].try_into().unwrap()),
            0x123456789
        );
        assert_eq!(code[18], 0xc3);
    }
}
