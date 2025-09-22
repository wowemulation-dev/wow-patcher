use std::path::Path;

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
