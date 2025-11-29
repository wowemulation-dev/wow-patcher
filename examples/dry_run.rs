//! Example showing dry run mode to preview changes without modifying files.
//!
//! Run with: cargo run --example dry_run

use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== WoW Patcher Library - Dry Run ===\n");

    Patcher::new("Wow.exe")
        .output("Wow-preview.exe")
        .trinity_core_keys()
        .dry_run(true) // Preview mode - no files will be modified
        .verbose(true)
        .patch()?;

    println!("\n📋 This was a dry run - no files were modified.");
    println!("Remove .dry_run(true) to apply the patches.");

    Ok(())
}
