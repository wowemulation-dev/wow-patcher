//! Basic example of using wow-patcher as a library with TrinityCore defaults.
//!
//! Run with: cargo run --example basic_usage

use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WoW Patcher Library - Basic Usage ===\n");

    // Simple usage with TrinityCore default keys
    Patcher::new("Wow.exe")
        .output("Wow-patched.exe")
        .trinity_core_keys()
        .verbose(true)
        .patch()?;

    println!("\n✅ Patching complete!");
    println!("You can now run Wow-patched.exe to connect to TrinityCore servers.");

    Ok(())
}
