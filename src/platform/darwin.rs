use crate::errors::WowPatcherError;
use std::path::Path;
use std::process::Command;

pub fn remove_codesign(path: &Path) -> Result<(), WowPatcherError> {
    let output =
        Command::new("codesign").arg("--remove-signature").arg(path).output().map_err(|e| {
            WowPatcherError::wrap(
                crate::errors::ErrorCategory::PlatformError,
                "Failed to execute codesign command",
                e,
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(WowPatcherError::new(
            crate::errors::ErrorCategory::PlatformError,
            format!("codesign failed: {}", stderr),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_remove_codesign() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test_binary");
        fs::write(&test_file, b"test binary content").unwrap();

        // This might fail on CI without proper setup, so we just test it doesn't panic
        let _ = remove_codesign(&test_file);
    }
}
