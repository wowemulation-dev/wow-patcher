use std::env;
use std::path::PathBuf;

pub fn find_wow_executable() -> Option<PathBuf> {
    let home = env::var("HOME").ok()?;

    let possible_paths = vec![
        format!(
            "{}/.wine/drive_c/Program Files/World of Warcraft/_retail_/Wow.exe",
            home
        ),
        format!(
            "{}/.wine/drive_c/Program Files (x86)/World of Warcraft/_retail_/Wow.exe",
            home
        ),
        format!(
            "{}/Games/world-of-warcraft/drive_c/Program Files/World of Warcraft/_retail_/Wow.exe",
            home
        ),
    ];

    for path_str in possible_paths {
        let path = PathBuf::from(path_str);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_wow_executable() {
        // This test will likely return None unless WoW is actually installed
        let _ = find_wow_executable();
    }
}
