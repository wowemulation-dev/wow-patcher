use std::fs;
use tempfile::TempDir;
use wow_patcher::binary::{PatternExt, patch};
use wow_patcher::patterns::{
    connect_to_modulus_pattern, crypto_ed_public_key_pattern, portal_pattern,
};
use wow_patcher::trinity::{CRYPTO_ED25519_PUBLIC_KEY, RSA_MODULUS};

fn create_mock_executable() -> Vec<u8> {
    let size = 100 * 1024;
    let mut data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();

    // Insert portal pattern at offset 1000
    let portal_str = b".actual.battle.net";
    data[1000..1000 + portal_str.len()].copy_from_slice(portal_str);

    // Insert RSA pattern at offset 5000
    let rsa_pattern = &[0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];
    data[5000..5000 + rsa_pattern.len()].copy_from_slice(rsa_pattern);

    // Insert Ed25519 pattern at offset 10000
    let ed_pattern = &[0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD];
    data[10000..10000 + ed_pattern.len()].copy_from_slice(ed_pattern);

    data
}

#[test]
fn test_full_patching_workflow() {
    let temp_dir = TempDir::new().unwrap();
    let mock_exe = create_mock_executable();

    let input_file = temp_dir.path().join("test_wow_input.exe");
    fs::write(&input_file, &mock_exe).unwrap();

    let output_file = temp_dir.path().join("test_wow_output.exe");

    // Read the input file
    let mut data = fs::read(&input_file).unwrap();

    // Apply patches
    let _ = patch(&mut data, portal_pattern(), &portal_pattern().empty());
    let _ = patch(&mut data, connect_to_modulus_pattern(), RSA_MODULUS);
    let _ = patch(
        &mut data,
        crypto_ed_public_key_pattern(),
        CRYPTO_ED25519_PUBLIC_KEY,
    );

    // Write output
    fs::write(&output_file, &data).unwrap();

    // Verify output file exists
    assert!(output_file.exists());

    let metadata = fs::metadata(&output_file).unwrap();
    assert!(metadata.is_file());
}

#[test]
fn test_patching_with_real_patterns() {
    let mut data = vec![0u8; 2048];

    // Insert portal pattern
    let portal_str = b".actual.battle.net";
    let portal_offset = 100;
    data[portal_offset..portal_offset + portal_str.len()].copy_from_slice(portal_str);

    // Insert RSA pattern
    let rsa_pattern = &[0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];
    let rsa_offset = 300;
    data[rsa_offset..rsa_offset + rsa_pattern.len()].copy_from_slice(rsa_pattern);

    // Insert Ed25519 pattern
    let ed_pattern = &[0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD];
    let ed_offset = 800;
    data[ed_offset..ed_offset + ed_pattern.len()].copy_from_slice(ed_pattern);

    // Apply patches
    let result = patch(&mut data, portal_pattern(), &portal_pattern().empty());
    assert!(result.is_ok());

    let result = patch(&mut data, connect_to_modulus_pattern(), RSA_MODULUS);
    assert!(result.is_ok());

    let result = patch(
        &mut data,
        crypto_ed_public_key_pattern(),
        CRYPTO_ED25519_PUBLIC_KEY,
    );
    assert!(result.is_ok());

    // Verify patches were applied.

    // Portal pattern was zeroed.
    assert_eq!(
        &data[portal_offset..portal_offset + portal_str.len()],
        &vec![0u8; portal_str.len()][..]
    );

    // RSA pattern was replaced with the FULL 256-byte modulus, not
    // just the first 8 bytes (regression test for the truncation bug
    // tracked in AGENTS.md "Critical: RSA and Ed25519 Key Replacement
    // Truncation"). The replacement extends past the end of the 8-byte
    // anchor pattern, overwriting 248 bytes of trailing buffer.
    assert_eq!(RSA_MODULUS.len(), 256);
    assert_eq!(
        &data[rsa_offset..rsa_offset + RSA_MODULUS.len()],
        RSA_MODULUS,
        "full RSA modulus must be written, not truncated to pattern length"
    );

    // Ed25519 pattern was replaced with the FULL 32-byte key.
    assert_eq!(CRYPTO_ED25519_PUBLIC_KEY.len(), 32);
    assert_eq!(
        &data[ed_offset..ed_offset + CRYPTO_ED25519_PUBLIC_KEY.len()],
        CRYPTO_ED25519_PUBLIC_KEY,
        "full Ed25519 public key must be written, not truncated to pattern length"
    );
}

#[test]
fn test_patching_error_handling() {
    // Empty data
    let mut data = vec![];
    let result = patch(&mut data, portal_pattern(), &[]);
    assert!(result.is_err());

    // Pattern not found
    let mut data = b"random data without patterns".to_vec();
    let result = patch(&mut data, connect_to_modulus_pattern(), RSA_MODULUS);
    assert!(result.is_err());
}
