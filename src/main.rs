use wow_patcher::cmd;
use std::process;

fn main() {
    if let Err(e) = cmd::run() {
        eprintln!("❌ Patching failed - the client has not been modified.");
        eprintln!();
        eprintln!("Error: {}", e);
        eprintln!();
        eprintln!("💡 Common solutions:");
        eprintln!("  • Ensure you have the correct path to your WoW executable");
        eprintln!("  • Check that you have read/write permissions");
        eprintln!("  • Verify the WoW executable is not currently running");
        eprintln!("  • Make sure the output directory exists");
        process::exit(1);
    }
}
