use std::path::PathBuf;

pub fn find_wow_executable() -> Option<PathBuf> {
    let possible_paths = vec![
        "C:\\Program Files\\World of Warcraft\\_retail_\\Wow.exe",
        "C:\\Program Files (x86)\\World of Warcraft\\_retail_\\Wow.exe",
        "C:\\Program Files\\World of Warcraft\\_classic_\\WowClassic.exe",
        "C:\\Program Files (x86)\\World of Warcraft\\_classic_\\WowClassic.exe",
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
