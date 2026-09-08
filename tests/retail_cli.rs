#![cfg(feature = "cli")]

use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wow-patcher"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn retail_help_describes_the_build_and_required_certificate() {
    let result = cli(&["launch-retail", "--help"]);
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("12.0.7.68887"));
    assert!(output.contains("--server-cert <FILE>"));
    assert!(output.contains("--portal-suffix"));
}

#[test]
fn retail_rejects_missing_certificate_and_invalid_timeouts() {
    assert!(!cli(&["launch-retail"]).status.success());
    for timeout in ["0", "2", "301", "invalid"] {
        let result = cli(&[
            "launch-retail",
            "--server-cert",
            "unused.pem",
            "--timeout",
            timeout,
        ]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--timeout"));
    }
}

#[test]
fn retail_rejects_options_from_other_patching_modes() {
    for option in [
        "--rsa-file",
        "--cert-bundle",
        "--bgs-portal-domain",
        "--cdns-url",
        "--patches",
    ] {
        let result = cli(&[
            "launch-retail",
            "--server-cert",
            "unused.pem",
            option,
            "unused",
        ]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("do not apply"));
    }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[test]
fn retail_dry_run_rejects_an_unsupported_image_without_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let input = dir.path().join("Wow.exe");
    std::fs::write(&input, b"unsupported image").unwrap();
    let result = cli(&[
        "launch-retail",
        "-l",
        input.to_str().unwrap(),
        "--server-cert",
        "unused.pem",
        "--dry-run",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("supports only 12.0.7.68887"));
    assert_eq!(std::fs::read(input).unwrap(), b"unsupported image");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
