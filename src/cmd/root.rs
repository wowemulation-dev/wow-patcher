use clap::Parser;
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
    version,
    after_help = "Examples:
  # Basic usage - patch WoW.exe and save as Arctium
  wow-patcher -l \"C:\\Program Files\\World of Warcraft\\_retail_\\Wow.exe\"

  # Specify custom output filename
  wow-patcher -l /path/to/Wow.exe -o WowPrivate.exe

  # macOS - explicit path (default strips code signing)
  wow-patcher -l \"/Applications/World of Warcraft/_retail_/World of Warcraft.app/Contents/MacOS/World of Warcraft\"

  # Preview changes without modifying files (dry run)
  wow-patcher --dry-run -l ./Wow.exe"
)]
pub struct Args {
    /// Path to your WoW executable (auto-detected on macOS)
    #[arg(short = 'l', long = "warcraft-exe", value_name = "FILE", default_value_t = String::from(crate::platform::find_warcraft_client_executable()))]
    pub location: String,

    /// Output filename for the patched WoW executable (defaults to 'Arctium' if not specified)
    #[arg(short = 'o', long = "output-file", value_name = "FILE")]
    pub output: Option<String>,

    /// Preview changes without modifying any files
    #[arg(short = 'n', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,

    /// Remove macOS code signing (required for patched executable to run on macOS)
    #[arg(short = 's', long = "strip-binary-codesign", default_value_t = true)]
    pub sign: bool,

    /// Enable verbose output
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Convert to paths
    let input_path = PathBuf::from(&args.location);
    let output_path = PathBuf::from(args.output.unwrap_or_else(|| "Arctium".to_string()));

    // Execute the patching
    crate::cmd::execute::execute_patch(
        &input_path,
        &output_path,
        args.dry_run,
        args.sign,
        args.verbose,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parsing() {
        let args = Args::try_parse_from(&["wow-patcher", "-l", "/path/to/wow.exe"]);
        assert!(args.is_ok());

        let args = args.unwrap();
        assert_eq!(args.location, "/path/to/wow.exe");
        assert_eq!(args.output, None); // No default value unless explicitly set
        assert!(!args.dry_run);
        assert!(args.sign);
        assert!(!args.verbose);
    }

    #[test]
    fn test_cli_with_all_options() {
        let args = Args::try_parse_from(&[
            "wow-patcher",
            "-l",
            "/path/to/wow.exe",
            "-o",
            "/path/to/output.exe",
            "--dry-run",
            "--verbose",
        ]);
        if let Err(e) = &args {
            eprintln!("Error parsing args: {}", e);
        }
        assert!(args.is_ok());

        let args = args.unwrap();
        assert_eq!(args.location, "/path/to/wow.exe");
        assert_eq!(args.output, Some("/path/to/output.exe".to_string()));
        assert!(args.dry_run);
        assert!(args.sign); // defaults to true
        assert!(args.verbose);
    }

    #[test]
    fn test_cli_help() {
        let mut cmd = Args::command();
        let help = cmd.render_help().to_string();

        assert!(help.contains("wow-patcher"));
        assert!(help.contains("Modifies WoW binary") || help.contains("private servers"));
    }
}
