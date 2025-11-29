//! Example showing how to embed wow-patcher in a custom Battle.net agent.
//!
//! This demonstrates the use case mentioned: a Rust Battle.net agent that can
//! optionally patch the WoW client for private server use.
//!
//! Run with: cargo run --example battlenet_agent

use std::path::Path;
use wow_patcher::Patcher;

/// Simulated Battle.net agent functionality
struct BattleNetAgent {
    wow_install_path: String,
    private_server_mode: bool,
}

impl BattleNetAgent {
    fn new(wow_path: &str) -> Self {
        Self {
            wow_install_path: wow_path.to_string(),
            private_server_mode: false,
        }
    }

    /// Enable private server mode with an optional flag
    fn enable_private_server_mode(&mut self) {
        self.private_server_mode = true;
        println!("🔒 Private server mode enabled");
    }

    /// Launch World of Warcraft
    fn launch_wow(&self) -> Result<(), Box<dyn std::error::Error>> {
        let wow_exe = Path::new(&self.wow_install_path).join("Wow.exe");

        if self.private_server_mode {
            println!("\n🔧 Patching WoW client for private server...");

            // Create a patched version
            let patched_exe = Path::new(&self.wow_install_path).join("Wow-private.exe");

            Patcher::new(&wow_exe)
                .output(&patched_exe)
                .trinity_core_keys()
                .custom_cdn("http://my-private-cdn.local")
                .verbose(false) // Keep it quiet in the agent
                .patch()?;

            println!("✅ Client patched successfully!");
            println!("🎮 Launching: {:?}", patched_exe);
            // Here you would actually launch the executable
            // std::process::Command::new(patched_exe).spawn()?;
        } else {
            println!("🎮 Launching official WoW: {:?}", wow_exe);
            // Here you would launch the official executable
            // std::process::Command::new(wow_exe).spawn()?;
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Custom Battle.net Agent with Embedded Patcher ===\n");

    // Simulate command-line argument: --private-server
    let use_private_server = std::env::args().any(|arg| arg == "--private-server");

    let mut agent = BattleNetAgent::new("/path/to/wow/installation");

    if use_private_server {
        agent.enable_private_server_mode();
    }

    agent.launch_wow()?;

    println!("\n💡 Usage:");
    println!("  cargo run --example battlenet_agent              # Launch official");
    println!("  cargo run --example battlenet_agent -- --private-server  # Patch & launch");

    Ok(())
}
