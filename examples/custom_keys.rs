//! Example showing how to use custom cryptographic keys from hex strings.
//!
//! Run with: cargo run --example custom_keys

use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WoW Patcher Library - Custom Keys ===\n");

    // Example custom keys (normally you'd load these from your server config)
    let custom_rsa = "C".repeat(512); // 512 hex chars (256 bytes)
    let custom_ed25519 = "D".repeat(64); // 64 hex chars (32 bytes)

    Patcher::new("Wow.exe")
        .output("Wow-custom.exe")
        .custom_keys_from_hex(&custom_rsa, &custom_ed25519)?
        .verbose(true)
        .patch()?;

    println!("\n✅ Patching complete with custom keys!");

    Ok(())
}
