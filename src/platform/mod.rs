use goblin::Object;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Version {
    pub fn new(major: u16, minor: u16, patch: u16, build: u16) -> Self {
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
            ClientType::Retail | ClientType::Classic | ClientType::Unknown => true,
            ClientType::ClassicEra => false,
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

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

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

/// Extract version information from WoW executable
pub fn extract_version(exe_path: &Path) -> Option<Version> {
    let data = std::fs::read(exe_path).ok()?;
    let obj = Object::parse(&data).ok()?;

    match obj {
        Object::PE(pe) => extract_pe_version(&pe),
        Object::Mach(mach) => extract_macho_version(&mach, &data),
        _ => None,
    }
}

/// Extract version from PE file (Windows executables)
fn extract_pe_version(_pe: &goblin::pe::PE) -> Option<Version> {
    // PE files store version info in the VS_VERSIONINFO resource
    // For now, we'll try to find version patterns in the binary
    // The version is usually stored as 4 16-bit values in the VS_FIXEDFILEINFO structure

    // This is a simplified approach - in production, we'd properly parse the resource section
    // For WoW executables, the version is typically stored in a consistent location
    // We'll return None for now and rely on the fallback pattern matching

    None
}

/// Extract version from Mach-O file (macOS executables)
fn extract_macho_version(mach: &goblin::mach::Mach, _data: &[u8]) -> Option<Version> {
    match mach {
        goblin::mach::Mach::Binary(_binary) => {
            // Look for LC_VERSION_MIN_* or LC_BUILD_VERSION commands
            // These contain SDK version but not necessarily app version

            // For WoW on macOS, version info is typically in the Info.plist
            // or embedded as data in the binary
            // This is a simplified implementation
            None
        }
        goblin::mach::Mach::Fat(_fat) => {
            // For fat binaries, we would need to iterate through architectures
            // For now, we'll rely on the fallback pattern matching
            None
        }
    }
}

/// Fallback version extraction using pattern matching
/// This searches for common version string patterns in the binary
pub fn extract_version_fallback(exe_path: &Path) -> Option<Version> {
    use std::fs::File;
    use std::io::{BufReader, Read};

    let file = File::open(exe_path).ok()?;
    let mut reader = BufReader::new(file);
    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).ok()?;

    // Common version patterns in WoW executables
    // Look for patterns like "10.2.5.53584" or "3.4.3.51666"
    let version_regex = regex::Regex::new(r"(\d{1,2})\.(\d{1,2})\.(\d{1,2})\.(\d{5,6})").ok()?;

    // Convert buffer to string, ignoring non-UTF8 sequences
    let text = String::from_utf8_lossy(&buffer);

    // Find the first matching version pattern
    if let Some(captures) = version_regex.captures(&text) {
        let major = captures.get(1)?.as_str().parse().ok()?;
        let minor = captures.get(2)?.as_str().parse().ok()?;
        let patch = captures.get(3)?.as_str().parse().ok()?;
        let build = captures.get(4)?.as_str().parse().ok()?;

        return Some(Version::new(major, minor, patch, build));
    }

    None
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
        assert!(ClientType::Classic.uses_ed25519());
        assert!(!ClientType::ClassicEra.uses_ed25519());
        assert!(ClientType::Unknown.uses_ed25519());
    }

    #[test]
    fn test_client_type_string() {
        assert_eq!(ClientType::Retail.to_string(), "Retail");
        assert_eq!(ClientType::Classic.to_string(), "Classic");
        assert_eq!(ClientType::ClassicEra.to_string(), "Classic Era");
        assert_eq!(ClientType::Unknown.to_string(), "Unknown");
    }
}
