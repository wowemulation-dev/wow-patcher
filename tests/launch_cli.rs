#![cfg(feature = "cli")]

use std::process::{Command, Output};
use tempfile::TempDir;

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wow-patcher"))
        .env_remove("WOW_BGS_PORTAL_DOMAIN")
        .args(args)
        .output()
        .unwrap()
}

fn resource_record(key: &str, value: &[u8], text: bool, child: &[u8]) -> Vec<u8> {
    let mut record = vec![0; 6];
    for unit in key.encode_utf16().chain(Some(0)) {
        record.extend_from_slice(&unit.to_le_bytes());
    }
    record.resize(record.len().next_multiple_of(4), 0);
    record.extend_from_slice(value);
    record.resize(record.len().next_multiple_of(4), 0);
    record.extend_from_slice(child);
    let len = record.len() as u16;
    record[..2].copy_from_slice(&len.to_le_bytes());
    let value_len = if text { value.len() / 2 } else { value.len() } as u16;
    record[2..4].copy_from_slice(&value_len.to_le_bytes());
    record[4..6].copy_from_slice(&u16::from(text).to_le_bytes());
    record
}

/// Minimal PE with FileVersion text and deliberately different fixed engine
/// version fields. Fixtures contain no client code and must never be launched.
fn versioned_client(dir: &TempDir, version: &str, name: &str) -> std::path::PathBuf {
    let value: Vec<_> = version
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect();
    let value = resource_record("FileVersion", &value, true, &[]);
    let table = resource_record("040904b0", &[], true, &value);
    let strings = resource_record("StringFileInfo", &[], true, &table);
    let mut fixed = vec![0; 52];
    fixed[..4].copy_from_slice(&0xfeef04bdu32.to_le_bytes());
    fixed[4..8].copy_from_slice(&0x10000u32.to_le_bytes());
    fixed[8..12].copy_from_slice(&(12u32 << 16).to_le_bytes());
    fixed[12..16].copy_from_slice(&((7u32 << 16) | (68887 & 0xffff)).to_le_bytes());
    let info = resource_record("VS_VERSION_INFO", &fixed, false, &strings);
    let raw_size = (0x60 + info.len()).next_multiple_of(0x200);
    let mut bytes = vec![0; 0x200 + raw_size];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    let optional = &mut bytes[0x98..0x188];
    optional[..2].copy_from_slice(&0x20bu16.to_le_bytes());
    optional[24..32].copy_from_slice(&0x140000000u64.to_le_bytes());
    optional[32..36].copy_from_slice(&0x1000u32.to_le_bytes());
    optional[36..40].copy_from_slice(&0x200u32.to_le_bytes());
    optional[56..60].copy_from_slice(&0x2000u32.to_le_bytes());
    optional[60..64].copy_from_slice(&0x200u32.to_le_bytes());
    optional[108..112].copy_from_slice(&16u32.to_le_bytes());
    optional[128..132].copy_from_slice(&0x1000u32.to_le_bytes());
    optional[132..136].copy_from_slice(&(raw_size as u32).to_le_bytes());
    let section = &mut bytes[0x188..0x1b0];
    section[..8].copy_from_slice(b".rsrc\0\0\0");
    section[8..12].copy_from_slice(&(raw_size as u32).to_le_bytes());
    section[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    section[16..20].copy_from_slice(&(raw_size as u32).to_le_bytes());
    section[20..24].copy_from_slice(&0x200u32.to_le_bytes());
    section[36..40].copy_from_slice(&0x40000040u32.to_le_bytes());
    let resource = &mut bytes[0x200..];
    for (offset, id, child) in [
        (0, 16u32, 0x80000018u32),
        (0x18, 1, 0x80000030),
        (0x30, 1033, 0x48),
    ] {
        resource[offset + 14..offset + 16].copy_from_slice(&1u16.to_le_bytes());
        resource[offset + 16..offset + 20].copy_from_slice(&id.to_le_bytes());
        resource[offset + 20..offset + 24].copy_from_slice(&child.to_le_bytes());
    }
    resource[0x48..0x4c].copy_from_slice(&0x1060u32.to_le_bytes());
    resource[0x4c..0x50].copy_from_slice(&(info.len() as u32).to_le_bytes());
    resource[0x60..0x60 + info.len()].copy_from_slice(&info);
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    assert_eq!(
        wow_patcher::platform::extract_version(&path)
            .unwrap()
            .to_string(),
        version
    );
    path
}

#[test]
fn launch_help_exposes_both_strategies_without_a_separate_command() {
    let result = cli(&["launch", "--help"]);
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("12.x and later"));
    assert!(output.contains("--server-cert <FILE>"));
    assert!(output.contains("--legacy-cert-mode"));
    assert!(!cli(&["launch-retail", "--help"]).status.success());
}

#[test]
fn launch_rejects_invalid_timeouts() {
    for timeout in ["0", "2", "301", "invalid"] {
        let result = cli(&["launch", "--timeout", timeout]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("--timeout"));
    }
}

#[test]
fn file_version_selects_retail_even_when_named_like_classic() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "12.0.7.68887", "WowClassic.exe");
    let result = cli(&["launch", "-l", input.to_str().unwrap(), "-v"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("launch strategy: Retail"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires --server-cert"));
}

#[test]
fn newer_retail_versions_enter_retail_but_require_a_matching_recipe() {
    for version in [
        "12.0.0.65655",
        "12.0.7.68886",
        "12.0.7.68888",
        "12.1.0.68914",
        "12.1.0.69586",
        "12.1.0.69588",
        "12.0.7.69587",
        "13.0.0.70000",
    ] {
        let dir = TempDir::new().unwrap();
        let input = versioned_client(&dir, version, "Wow.exe");
        let result = cli(&["launch", "-l", input.to_str().unwrap(), "--dry-run", "-v"]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stdout).contains("launch strategy: Retail"));
        assert!(String::from_utf8_lossy(&result.stderr).contains("No verified retail recipe"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn classic_file_version_overrides_fixed_engine_version_and_filename() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "3.4.4.60000", "Wow.exe");
    let result = cli(&["launch", "-l", input.to_str().unwrap(), "--dry-run", "-v"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("launch strategy: Legacy"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("no process started"));
}

#[test]
fn retail_rejects_options_from_the_older_strategy() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "12.0.7.68887", "Wow.exe");
    for option in [
        "--rsa-file",
        "--cert-bundle",
        "--bgs-portal-domain",
        "--cdns-url",
        "--patches",
    ] {
        let result = cli(&[
            "launch",
            "-l",
            input.to_str().unwrap(),
            "--server-cert",
            "unused.pem",
            option,
            "unused",
        ]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("do not apply"));
    }
}

#[test]
fn older_strategy_rejects_retail_options_and_incompatible_certificate_mode() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "1.13.2.31650", "WowClassic.exe");
    let result = cli(&[
        "launch",
        "-l",
        input.to_str().unwrap(),
        "--legacy-cert-mode",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("incompatible with 1.13.x"));
    let result = cli(&[
        "launch",
        "-l",
        input.to_str().unwrap(),
        "--server-cert",
        "unused.pem",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("require the retail strategy"));
}

#[test]
fn missing_version_metadata_does_not_fall_back_to_a_filename_heuristic() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("Wow.exe");
    std::fs::write(&input, b"unsupported image").unwrap();
    let result = cli(&["launch", "-l", input.to_str().unwrap(), "--dry-run"]);
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("Cannot read the executable's file version")
    );
    assert_eq!(std::fs::read(input).unwrap(), b"unsupported image");
}

#[test]
fn newer_verified_version_requires_certificate_without_starting() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "12.1.0.69587", "Wow.exe");
    let result = cli(&["launch", "-l", input.to_str().unwrap(), "-v"]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("launch strategy: Retail"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("requires --server-cert"));
}

#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
#[test]
fn forged_version_metadata_cannot_bypass_image_identity_check() {
    let dir = TempDir::new().unwrap();
    let input = versioned_client(&dir, "12.1.0.69587", "Wow.exe");
    std::fs::write(dir.path().join("Wow_loader.dll"), b"invalid loader").unwrap();
    std::fs::create_dir(dir.path().join("WTF")).unwrap();
    std::fs::write(dir.path().join("WTF/Config.wtf"), b"").unwrap();
    let cert = dir.path().join("public.pem");
    std::fs::write(
        &cert,
        b"-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----",
    )
    .unwrap();
    let result = cli(&[
        "launch",
        "-l",
        input.to_str().unwrap(),
        "--server-cert",
        cert.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Unverified executable: SHA-256"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("Created client PID"));
}
