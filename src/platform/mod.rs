use goblin::Object;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    /// Build number. 32-bit because recent WoW builds exceed u16 (e.g. 66290).
    pub build: u32,
}

impl Version {
    pub fn new(major: u16, minor: u16, patch: u16, build: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}",
            self.major, self.minor, self.patch, self.build
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Retail,
    Classic,
    ClassicEra,
    Unknown,
}

impl ClientType {
    pub fn uses_ed25519(&self) -> bool {
        match self {
            ClientType::Retail | ClientType::Unknown => true,
            // Classic (1.13.x, 2.5.x, 3.4.x) and Classic Era do not embed
            // an Ed25519 public key. Verified via RE of Classic 1.13.2.31650:
            // the pattern (15 D6 18 BD...) is absent from the binary.
            ClientType::Classic | ClientType::ClassicEra => false,
        }
    }
}

impl std::fmt::Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientType::Retail => write!(f, "Retail"),
            ClientType::Classic => write!(f, "Classic"),
            ClientType::ClassicEra => write!(f, "Classic Era"),
            ClientType::Unknown => write!(f, "Unknown"),
        }
    }
}

pub fn detect_client_type(exe_path: &str) -> ClientType {
    let path_lower = exe_path.to_lowercase();

    // Check directory markers
    if path_lower.contains("_retail_") {
        return ClientType::Retail;
    }
    if path_lower.contains("_classic_era_") {
        return ClientType::ClassicEra;
    }
    if path_lower.contains("_classic_") {
        return ClientType::Classic;
    }

    // Check filename
    let filename = Path::new(exe_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    if filename.contains("wowclassic") {
        return ClientType::Classic;
    }
    if filename == "wow.exe" || filename == "world of warcraft" {
        return ClientType::Retail;
    }

    ClientType::Unknown
}

#[cfg(target_os = "macos")]
pub mod darwin;

pub fn find_warcraft_client_executable() -> String {
    #[cfg(target_os = "macos")]
    {
        "/Applications/World of Warcraft/_retail_/World of Warcraft.app/Contents/MacOS/World of Warcraft".to_string()
    }

    #[cfg(not(target_os = "macos"))]
    {
        String::new()
    }
}

#[cfg(target_os = "macos")]
pub fn remove_codesigning_signature(path: &str) -> Result<(), crate::errors::WowPatcherError> {
    darwin::remove_codesign(Path::new(path))
}

#[cfg(not(target_os = "macos"))]
pub fn remove_codesigning_signature(_path: &str) -> Result<(), crate::errors::WowPatcherError> {
    println!("ℹ️  Code signing removal is not required on this platform");
    Ok(())
}

/// Extract version information from a WoW executable.
///
/// Only Windows PE binaries are supported. Mach-O parsing is not implemented.
pub fn extract_version(exe_path: &Path) -> Option<Version> {
    let data = std::fs::read(exe_path).ok()?;
    match Object::parse(&data).ok()? {
        Object::PE(pe) => extract_pe_version(&pe),
        _ => None,
    }
}

/// Extract version from PE file via the VS_VERSIONINFO resource.
fn extract_pe_version(pe: &goblin::pe::PE) -> Option<Version> {
    let version_info = pe.resource_data.as_ref()?.version_info.as_ref()?;

    // Prefer the StringFileInfo "FileVersion" entry: WoW Classic variants
    // (e.g. MoP 5.5.x) carry their gameplay version here in human form
    // ("5.5.3.66290"), while VsFixedFileInfo holds the underlying retail
    // engine version and would mislead callers.
    if let Some(s) = version_info.string_info.file_version()
        && let Some(v) = parse_dotted_version(&s)
    {
        return Some(v);
    }
    if let Some(s) = version_info.string_info.product_version()
        && let Some(v) = parse_dotted_version(&s)
    {
        return Some(v);
    }

    let fixed = version_info.fixed_info?;
    Some(Version::new(
        (fixed.file_version_ms >> 16) as u16,
        (fixed.file_version_ms & 0xFFFF) as u16,
        (fixed.file_version_ls >> 16) as u16,
        fixed.file_version_ls & 0xFFFF,
    ))
}

fn parse_dotted_version(s: &str) -> Option<Version> {
    let mut parts = s.split('.');
    let major = parts.next()?.trim().parse().ok()?;
    let minor = parts.next()?.trim().parse().ok()?;
    let patch = parts.next()?.trim().parse().ok()?;
    let build = parts.next()?.trim().parse().ok()?;
    Some(Version::new(major, minor, patch, build))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_client_type() {
        assert_eq!(
            detect_client_type("C:\\Program Files\\World of Warcraft\\_retail_\\Wow.exe"),
            ClientType::Retail
        );

        assert_eq!(
            detect_client_type(
                "/Applications/World of Warcraft/_retail_/World of Warcraft.app/Contents/MacOS/World of Warcraft"
            ),
            ClientType::Retail
        );

        assert_eq!(
            detect_client_type("C:\\Program Files\\World of Warcraft\\_classic_\\WowClassic.exe"),
            ClientType::Classic
        );

        assert_eq!(
            detect_client_type("/home/user/wow/_classic_era_/WowClassic.exe"),
            ClientType::ClassicEra
        );

        assert_eq!(detect_client_type("WowClassic.exe"), ClientType::Classic);

        assert_eq!(detect_client_type("Wow.exe"), ClientType::Retail);

        assert_eq!(
            detect_client_type("/some/path/game.exe"),
            ClientType::Unknown
        );

        assert_eq!(
            detect_client_type("C:\\Games\\WoW\\_RETAIL_\\WOW.EXE"),
            ClientType::Retail
        );
    }

    #[test]
    fn test_client_type_uses_ed25519() {
        assert!(ClientType::Retail.uses_ed25519());
        assert!(!ClientType::Classic.uses_ed25519());
        assert!(!ClientType::ClassicEra.uses_ed25519());
        assert!(ClientType::Unknown.uses_ed25519());
    }

    #[test]
    fn test_parse_dotted_version_build_exceeds_u16() {
        // MoP Classic 5.5.3.66290 — build > u16::MAX. Regression for
        // earlier truncation when Version.build was u16.
        assert_eq!(
            parse_dotted_version("5.5.3.66290"),
            Some(Version::new(5, 5, 3, 66290))
        );
        assert_eq!(
            parse_dotted_version("4.4.2.60895"),
            Some(Version::new(4, 4, 2, 60895))
        );
        assert_eq!(parse_dotted_version("Version 5.5.3"), None);
        assert_eq!(parse_dotted_version("5.5.3"), None);
    }

    #[test]
    fn test_client_type_string() {
        assert_eq!(ClientType::Retail.to_string(), "Retail");
        assert_eq!(ClientType::Classic.to_string(), "Classic");
        assert_eq!(ClientType::ClassicEra.to_string(), "Classic Era");
        assert_eq!(ClientType::Unknown.to_string(), "Unknown");
    }
}
