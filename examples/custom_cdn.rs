//! Example showing how to redirect WoW client to a custom CDN server.
//!
//! Run with: cargo run --example custom_cdn

use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WoW Patcher Library - Custom CDN ===\n");

    Patcher::new("Wow.exe")
        .output("Wow-custom-cdn.exe")
        .trinity_core_keys()
        .custom_cdn("http://my-wow-cdn.local")
        .verbose(true)
        .patch()?;

    println!("\n✅ Patching complete!");
    println!("Client will use: http://my-wow-cdn.local for game data");

    Ok(())
}
