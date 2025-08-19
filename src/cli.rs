use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "wow-patcher",
    about = "Modifies WoW binary to enable connecting to private servers",
    long_about = "wow-patcher is a binary patcher for World of Warcraft retail clients that enables
connections to TrinityCore-based private servers.

This tool modifies your WoW executable by:
  • Removing Battle.net portal connections
  • Replacing RSA authentication keys
  • Updating Ed25519 cryptographic keys

The patched client will only work with TrinityCore servers that use valid TLS
certificates and hostname-based connections (not IP addresses).",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
    
    /// Path to your WoW executable (auto-detected on macOS)
    #[arg(short = 'l', long = "warcraft-exe", value_name = "FILE", global = true)]
    pub location: Option<String>,
    
    /// Output filename for the patched WoW executable
    #[arg(short = 'o', long = "output-file", value_name = "FILE", default_value = "Arctium", global = true)]
    pub output: Option<String>,
    
    /// Preview changes without modifying any files
    #[arg(short = 'n', long = "dry-run", default_value_t = false, global = true)]
    pub dry_run: bool,
    
    /// Remove macOS code signing (required for patched executable to run on macOS)
    #[arg(short = 's', long = "strip-binary-codesign", default_value_t = true, global = true)]
    pub sign: bool,
    
    /// Enable verbose output
    #[arg(short = 'v', long, default_value_t = false, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Print version information
    Version {
        /// Show detailed version information
        #[arg(short = 'd', long = "detailed")]
        detailed: bool,
    },
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    match cli.command {
        Some(Commands::Version { detailed }) => {
            if detailed {
                println!("{}", crate::version::detailed_info());
            } else {
                println!("{}", crate::version::info());
            }
            Ok(())
        }
        None => {
            // Default behavior - patch the file
            let location = cli.location.unwrap_or_else(|| {
                crate::platform::find_warcraft_client_executable()
            });
            
            if location.is_empty() {
                return Err("No WoW executable specified. Use -l flag to specify the path.".into());
            }
            
            let input_path = PathBuf::from(&location);
            let output_path = PathBuf::from(cli.output.unwrap_or_else(|| "Arctium".to_string()));
            
            crate::cmd::execute::execute_patch(
                &input_path,
                &output_path,
                cli.dry_run,
                cli.sign,
                cli.verbose,
            )?;
            
            Ok(())
        }
    }
}