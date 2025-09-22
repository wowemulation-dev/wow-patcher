use crate::keys::KeyConfig;
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
    #[arg(
        short = 'o',
        long = "output-file",
        value_name = "FILE",
        default_value = "Arctium",
        global = true
    )]
    pub output: Option<String>,

    /// Preview changes without modifying any files
    #[arg(short = 'n', long = "dry-run", default_value_t = false, global = true)]
    pub dry_run: bool,

    /// Remove macOS code signing (required for patched executable to run on macOS)
    #[arg(
        short = 's',
        long = "strip-binary-codesign",
        default_value_t = true,
        global = true
    )]
    pub sign: bool,

    /// Enable verbose output
    #[arg(short = 'v', long, default_value_t = false, global = true)]
    pub verbose: bool,

    /// Custom RSA modulus file (256 bytes binary)
    #[arg(long = "rsa-file", value_name = "FILE", global = true)]
    pub rsa_file: Option<String>,

    /// Custom RSA modulus as hex string (512 hex characters)
    #[arg(long = "rsa-hex", value_name = "HEX", global = true)]
    pub rsa_hex: Option<String>,

    /// Custom Ed25519 public key file (32 bytes binary)
    #[arg(long = "ed25519-file", value_name = "FILE", global = true)]
    pub ed25519_file: Option<String>,

    /// Custom Ed25519 public key as hex string (64 hex characters)
    #[arg(long = "ed25519-hex", value_name = "HEX", global = true)]
    pub ed25519_hex: Option<String>,
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
            let location = cli
                .location
                .unwrap_or_else(|| crate::platform::find_warcraft_client_executable());

            if location.is_empty() {
                return Err("No WoW executable specified. Use -l flag to specify the path.".into());
            }

            // Build key configuration from CLI arguments
            let mut key_config = KeyConfig::default();

            // Check for conflicting RSA arguments
            if cli.rsa_file.is_some() && cli.rsa_hex.is_some() {
                return Err("Cannot specify both --rsa-file and --rsa-hex at the same time".into());
            }

            // Check for conflicting Ed25519 arguments
            if cli.ed25519_file.is_some() && cli.ed25519_hex.is_some() {
                return Err(
                    "Cannot specify both --ed25519-file and --ed25519-hex at the same time".into(),
                );
            }

            // Load RSA modulus from file or hex
            if let Some(rsa_file) = &cli.rsa_file {
                key_config = key_config.with_rsa_from_file(rsa_file)?;
            } else if let Some(rsa_hex) = &cli.rsa_hex {
                key_config = key_config.with_rsa_from_hex(rsa_hex)?;
            }

            // Load Ed25519 key from file or hex
            if let Some(ed25519_file) = &cli.ed25519_file {
                key_config = key_config.with_ed25519_from_file(ed25519_file)?;
            } else if let Some(ed25519_hex) = &cli.ed25519_hex {
                key_config = key_config.with_ed25519_from_hex(ed25519_hex)?;
            }

            if cli.verbose && !key_config.is_trinity_core() {
                println!("Using custom server keys: {}", key_config.display_info());
            }

            let input_path = PathBuf::from(&location);
            let output_path = PathBuf::from(cli.output.unwrap_or_else(|| "Arctium".to_string()));

            crate::cmd::execute::execute_patch(
                &input_path,
                &output_path,
                key_config,
                cli.dry_run,
                cli.sign,
                cli.verbose,
            )?;

            Ok(())
        }
    }
}
