//! Example showing how to use custom cryptographic keys from hex strings.
//!
//! Run with: cargo run --example custom_keys

use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WoW Patcher Library - Custom Keys ===\n");

    // Example custom keys (from your server config).
    // These are random-looking hex that passes the entropy validation
    // in KeyConfig::validate(). Replace with your actual server keys.
    // RSA modulus: 256 bytes (512 hex chars)
    // Ed25519 public key: 32 bytes (64 hex chars)
    let custom_rsa = concat!(
        "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "10213a4b5c6d7e8f90a1b2c3d4e5f607",
        "81929a3b4c5d6e7f80910a2b3c4d5e6f",
        "71809a1b2c3d4e5f6071829a3b4c5d6e",
        "7f80910a2b3c4d5e6f71809a1b2c3d4e",
        "5f60718293a4b5c6d7e8f90a1b2c3d4e",
        "5f60718293a4b5c6d7e8f90a1b2c3d4e",
        "71809a1b2c3d4e5f60718293a4b5c6d7e",
        "8f90a1b2c3d4e5f60718293a4b5c6d7e",
        "8f90a1b2c3d4e5f60718293a4b5c6d7e",
        "a1b2c3d4e5f60718293a4b5c6d7e8f90",
        "10213a4b5c6d7e8f90a1b2c3d4e5f607",
        "81929a3b4c5d6e7f80910a2b3c4d5e6f",
        "71809a1b2c3d4e5f6071829a3b4c5d6e",
        "7f80910a2b3c4d5e6f71809a1b2c3d4e",
        "5f60718293a4b5c6d7e8f90a1b2c3d4e",
    );
    let custom_ed25519 = concat!(
        "f1e2d3c4b5a60918a2b3c4d5e6f70819",
        "a2b3c4d5e6f70819f1e2d3c4b5a60918",
    );

    Patcher::new("Wow.exe")
        .output("Wow-custom.exe")
        .custom_keys_from_hex(custom_rsa, custom_ed25519)?
        .verbose(true)
        .dry_run(true)
        .patch()?;

    println!("\n✅ Patching complete with custom keys!");

    Ok(())
}
