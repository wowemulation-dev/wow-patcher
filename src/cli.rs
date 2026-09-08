use crate::cert_bundle::CertBundleConfig;
use crate::errors::{ErrorCategory, WowPatcherError};
use crate::keys::KeyConfig;
use crate::patch_group::parse_patch_groups;
use crate::portal_domain::PortalDomain;
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

    /// Custom version URL for CDN redirection
    #[arg(long = "version-url", value_name = "URL", global = true)]
    pub version_url: Option<String>,

    /// Custom CDNs URL for CDN redirection
    #[arg(long = "cdns-url", value_name = "URL", global = true)]
    pub cdns_url: Option<String>,

    /// Override the public BGS portal domain rewritten into the binary.
    ///
    /// The patcher rewrites the BGS Aurora-RPC portal hostname suffix
    /// `.actual.battle.net` to `.actual.<domain>`. The default
    /// `wowemu.dev` is byte-identical in length to `battle.net` so no
    /// NUL padding is needed. Shorter domains (max 10 bytes total)
    /// work via NUL-padding.
    ///
    /// Scope: this flag controls ONLY the BGS portal suffix. The
    /// cert-bundle download URL has its own `--cert-bundle-url` flag,
    /// and the cosmetic `nydus.battle.net` URLs (driver-unsupported,
    /// trial-restriction, gametime, checkout, checkoutnav) are NOT
    /// rewritten by the current patcher.
    ///
    /// Use this for local testing with a domain you control via
    /// `/etc/hosts` (e.g. `bgs.corp`). Falls back to the
    /// `WOW_BGS_PORTAL_DOMAIN` env var if the flag is not set.
    #[arg(
        long = "bgs-portal-domain",
        value_name = "DOMAIN",
        env = "WOW_BGS_PORTAL_DOMAIN",
        global = true
    )]
    pub portal_domain: Option<String>,

    /// Inject a custom signed cert bundle (≤ 32761 bytes).
    ///
    /// The file's bytes replace the embedded cert bundle in `.rdata`
    /// of clients that ship with one (1.14.0/.1/.2, 2.5.3). For
    /// clients without an embedded bundle (1.13.2, 1.15.2, 3.4.3,
    /// 4.4.2), this flag has no effect at the embedded-slot site;
    /// pair with `--cert-bundle-url` to redirect the download URL
    /// to a host you control instead.
    ///
    /// The bundle must be signed by a key whose modulus matches the
    /// one rewritten via `--rsa-file` / `--rsa-hex`.
    #[arg(long = "cert-bundle", value_name = "FILE", global = true)]
    pub cert_bundle: Option<String>,

    /// Override the cert-bundle download URL (≤ 59 bytes).
    ///
    /// Replaces the literal `http://nydus.battle.net/Bnet/zxx/client/bgs-key-fingerprint`
    /// in builds that have it as a flat string (1.13.2, 1.14.x, 2.5.3).
    /// Use this when you want the patched client to fetch its bundle
    /// from a URL you control (e.g. a different host than the BGS
    /// portal hostname controlled by `--bgs-portal-domain`).
    #[arg(long = "cert-bundle-url", value_name = "URL", global = true)]
    pub cert_bundle_url: Option<String>,

    /// Comma-separated list of patch groups to apply.
    ///
    /// Valid groups: all, rsa, ed25519, portal, version, cdns,
    /// cert-bundle, cert-bundle-url.
    ///
    /// Default: all (every group). Use this to select a subset, e.g.
    /// `--patches version,cdns` to only rewrite version and CDN URLs.
    #[arg(
        long = "patches",
        value_name = "GROUPS",
        default_value = "all",
        global = true
    )]
    pub patches: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch retail 12.0.7.68887 with in-memory certificate patches (Windows x64).
    LaunchRetail {
        /// Public server certificate in PEM format (no private key).
        #[arg(long, value_name = "FILE")]
        server_cert: PathBuf,

        /// Portal suffix; pass an empty string to use the configured portal verbatim.
        #[arg(long, allow_hyphen_values = true)]
        portal_suffix: Option<String>,

        /// Client configuration filename under the game's WTF directory.
        #[arg(long, default_value = "Config.wtf")]
        config: String,

        /// Timeout in seconds for each startup phase.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(3..=300))]
        timeout: u64,
    },
    /// Print version information
    Version {
        /// Show detailed version information
        #[arg(short = 'd', long = "detailed")]
        detailed: bool,
    },
    /// Dump decrypted .text section from Arxan-protected client (Windows/Wine only)
    ///
    /// Launches the WoW client suspended, waits for Arxan TransformIT to
    /// decrypt the .text section, then reads decrypted bytes from process
    /// memory and saves to a raw binary file. The dump can be loaded into
    /// a disassembler to replace the encrypted .text section.
    DumpText {
        /// Output file for the raw .text dump
        #[arg(short = 'o', long, default_value = "text_dump.bin")]
        output: String,

        /// Seconds to wait for Arxan decryption (0 = auto-detect)
        #[arg(short = 'w', long, default_value_t = 0)]
        wait: u64,
    },

    /// Dump one or more PE sections from a running Arxan-protected client.
    ///
    /// Extends dump-text to arbitrary sections (.text, .data, .rdata, .pdata).
    /// Useful for recovering runtime-populated data like opcode handler
    /// tables, Aurora service dispatch tables, and Arxan-resolved IAT
    /// function pointers that live in .data and are zeroed in the static PE.
    ///
    /// For .data recovery, use --post-decrypt-wait to let C++ static
    /// initializers and the Arxan bootstrap finish populating globals
    /// before the snapshot.
    DumpSections {
        /// Sections to dump, as comma-separated pairs `section:output_path`.
        /// Example: `--targets .text:text.bin,.data:data.bin`
        #[arg(short = 't', long, value_name = "TARGETS")]
        targets: String,

        /// Seconds to wait for Arxan decryption (0 = auto-detect)
        #[arg(short = 'w', long, default_value_t = 0)]
        wait: u64,

        /// Additional seconds to wait after decryption completes, to let
        /// C++ static init and startup code populate .data. Recommended
        /// value for .data dumps: 10-30 seconds.
        #[arg(long = "post-decrypt-wait", default_value_t = 0)]
        post_decrypt_wait: u64,
    },

    /// Launch the WoW client with runtime-mode patches applied
    /// (Windows / Wine only).
    ///
    /// Resumes the client from a CREATE_SUSPENDED state, waits for
    /// Arxan to decrypt the .text section, NOPs the integrity check,
    /// then writes the configured RSA / Ed25519 / portal / cert-bundle
    /// patches via WriteProcessMemory before resuming.
    ///
    /// This is the runtime counterpart to the default static-binary
    /// patching flow. Use it when static patching of SignatureModulus
    /// crashes the client at startup (verified failure mode on Wine
    /// staging 11.0 against WoW Classic 1.13.2; see Serena memory
    /// `analysis/wow-1132-signature-modulus-static-patch-crashes`).
    ///
    /// The same global flags (--rsa-hex, --bgs-portal-domain,
    /// --cert-bundle-url, --cert-bundle, etc.) configure the patches.
    Launch {
        /// Seconds to wait for Arxan decryption (0 = auto-detect via
        /// the same heuristic dump-sections uses). Only relevant
        /// when --legacy-cert-mode is set.
        #[arg(short = 'w', long, default_value_t = 0)]
        wait: u64,

        /// Apply legacy-cert-mode patches (1.14+ only).
        ///
        /// Adds SignatureModulus replacement, embedded cert-bundle
        /// byte injection, and runtime cert-validation NOPs
        /// (Integrity, CertBundle JZ, CertCommonName, CertChain) on
        /// top of the default data-slot patches. These additions
        /// match Arctium-WoW-Launcher's `legacyCertMode` block at
        /// `Launcher.cs:249-260,288-300`.
        ///
        /// Do NOT use for 1.13.x: that build's cert-bundle pin
        /// verifies against ConnectToModulus directly, so
        /// SignatureModulus must be left stock. (Replacing it
        /// statically crashes `bgs::schannel_filter::InitCredentials`;
        /// see `analysis/wow-1132-signature-modulus-static-patch-crashes`.)
        #[arg(long = "legacy-cert-mode", default_value_t = false)]
        legacy_cert_mode: bool,
    },
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::LaunchRetail {
            server_cert,
            portal_suffix,
            config,
            timeout,
        }) => {
            if cli.rsa_file.is_some()
                || cli.rsa_hex.is_some()
                || cli.portal_domain.is_some()
                || cli.cert_bundle.is_some()
                || cli.cert_bundle_url.is_some()
                || cli.cdns_url.is_some()
                || cli.patches != "all"
            {
                return Err("launch-retail accepts Ed25519 keys, --version-url and --portal-suffix; RSA, bundle, domain, CDN and patch-group options do not apply".into());
            }
            if cli.ed25519_file.is_some() && cli.ed25519_hex.is_some() {
                return Err("Use only one of --ed25519-file and --ed25519-hex".into());
            }
            let mut keys = KeyConfig::default();
            if let Some(path) = cli.ed25519_file {
                keys = keys.with_ed25519_from_file(path)?;
            } else if let Some(value) = cli.ed25519_hex {
                keys = keys.with_ed25519_from_hex(&value)?;
            }
            #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
            {
                crate::cmd::retail::run(crate::cmd::retail::Options {
                    executable: cli
                        .location
                        .ok_or("Specify the client executable with -l")?
                        .into(),
                    server_cert,
                    portal_suffix,
                    config,
                    version_url: cli.version_url,
                    ed25519: keys.ed25519_public_key().to_vec(),
                    timeout: std::time::Duration::from_secs(timeout),
                    dry_run: cli.dry_run,
                    verbose: cli.verbose,
                })
            }
            #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
            {
                let _ = (server_cert, portal_suffix, config, timeout, keys);
                Err("launch-retail requires a Windows x64 patcher executable".into())
            }
        }
        Some(Commands::Version { detailed }) => {
            if detailed {
                println!("{}", crate::version::detailed_info());
            } else {
                println!("{}", crate::version::info());
            }
            Ok(())
        }
        Some(Commands::DumpText { output, wait: _ }) => {
            let location = cli
                .location
                .unwrap_or_else(crate::platform::find_warcraft_client_executable);

            if location.is_empty() {
                return Err("No WoW executable specified. Use -l flag to specify the path.".into());
            }

            #[cfg(target_os = "windows")]
            {
                crate::cmd::dump::win::dump_text_section(&location, &output, 0, cli.verbose)?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (&location, &output);
                Err("dump-text requires Windows (or Wine). Cross-compile with: cargo build --target x86_64-pc-windows-gnu".into())
            }
        }
        Some(Commands::DumpSections {
            targets,
            wait,
            post_decrypt_wait,
        }) => {
            let location = cli
                .location
                .unwrap_or_else(crate::platform::find_warcraft_client_executable);

            if location.is_empty() {
                return Err("No WoW executable specified. Use -l flag to specify the path.".into());
            }

            // Parse `name:path,name:path` into (name, path) pairs
            let parsed: Result<Vec<(String, String)>, String> = targets
                .split(',')
                .map(|entry| {
                    let (name, path) = entry.split_once(':').ok_or_else(|| {
                        format!("Bad --targets entry '{entry}': expected 'section:path'")
                    })?;
                    Ok((name.trim().to_string(), path.trim().to_string()))
                })
                .collect();
            let parsed = parsed?;

            if parsed.is_empty() {
                return Err("--targets must specify at least one section:path pair".into());
            }

            #[cfg(target_os = "windows")]
            {
                crate::cmd::dump::win::dump_sections(
                    &location,
                    &parsed,
                    wait,
                    post_decrypt_wait,
                    cli.verbose,
                )?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (&location, &parsed, wait, post_decrypt_wait);
                Err("dump-sections requires Windows (or Wine). Cross-compile with: cargo build --target x86_64-pc-windows-gnu".into())
            }
        }
        Some(Commands::Launch {
            wait,
            legacy_cert_mode,
        }) => {
            let location = cli
                .location
                .unwrap_or_else(crate::platform::find_warcraft_client_executable);
            if location.is_empty() {
                return Err("No WoW executable specified. Use -l flag to specify the path.".into());
            }

            // Build the same key/portal/cert-bundle config as the
            // static path so users can pass identical flags.
            let mut key_config = KeyConfig::default();
            if cli.rsa_file.is_some() && cli.rsa_hex.is_some() {
                return Err("Cannot specify both --rsa-file and --rsa-hex at the same time".into());
            }
            if cli.ed25519_file.is_some() && cli.ed25519_hex.is_some() {
                return Err(
                    "Cannot specify both --ed25519-file and --ed25519-hex at the same time".into(),
                );
            }
            if let Some(p) = &cli.rsa_file {
                key_config = key_config.with_rsa_from_file(p)?;
            } else if let Some(h) = &cli.rsa_hex {
                key_config = key_config.with_rsa_from_hex(h)?;
            }
            if let Some(p) = &cli.ed25519_file {
                key_config = key_config.with_ed25519_from_file(p)?;
            } else if let Some(h) = &cli.ed25519_hex {
                key_config = key_config.with_ed25519_from_hex(h)?;
            }

            let portal_domain = match &cli.portal_domain {
                Some(d) => PortalDomain::parse(d)?,
                None => PortalDomain::default(),
            };

            let mut cert_bundle = CertBundleConfig::default();
            if let Some(path) = &cli.cert_bundle {
                cert_bundle = cert_bundle.with_bundle_from_file(path)?;
            }
            if let Some(url) = &cli.cert_bundle_url {
                cert_bundle = cert_bundle.with_download_url(url)?;
            }

            #[cfg(target_os = "windows")]
            {
                crate::cmd::launch::win::launch_and_patch(
                    crate::cmd::launch::win::LaunchOptions {
                        exe_path: &location,
                        key_config: &key_config,
                        portal_domain: &portal_domain,
                        cert_bundle: &cert_bundle,
                        legacy_cert_mode,
                        wait_seconds: wait,
                        verbose: cli.verbose,
                    },
                )?;
                Ok(())
            }
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (
                    &location,
                    &key_config,
                    &portal_domain,
                    &cert_bundle,
                    wait,
                    legacy_cert_mode,
                );
                Err("launch requires Windows (or Wine). Cross-compile with: cargo build --target x86_64-pc-windows-gnu".into())
            }
        }
        None => {
            // Default behavior - patch the file
            let location = cli
                .location
                .unwrap_or_else(crate::platform::find_warcraft_client_executable);

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

            // Validate URL parameters
            if let Some(version_url) = &cli.version_url {
                if !version_url.starts_with("http://") && !version_url.starts_with("https://") {
                    return Err("Version URL must start with http:// or https://".into());
                }
                if version_url.len() > 512 {
                    return Err("Version URL too long (max 512 characters)".into());
                }
            }

            if let Some(cdns_url) = &cli.cdns_url {
                if !cdns_url.starts_with("http://") && !cdns_url.starts_with("https://") {
                    return Err("CDNs URL must start with http:// or https://".into());
                }
                if cdns_url.len() > 512 {
                    return Err("CDNs URL too long (max 512 characters)".into());
                }
            }

            if cli.verbose && !key_config.is_trinity_core() {
                println!("Using custom server keys: {}", key_config.display_info());
            }

            if cli.verbose && (cli.version_url.is_some() || cli.cdns_url.is_some()) {
                println!("Using custom CDN URLs:");
                if let Some(version_url) = &cli.version_url {
                    println!("  Version URL: {}", version_url);
                }
                if let Some(cdns_url) = &cli.cdns_url {
                    println!("  CDNs URL: {}", cdns_url);
                }
            }

            // Resolve the portal domain (CLI flag or env, falling back to the public default).
            let portal_domain = match &cli.portal_domain {
                Some(d) => PortalDomain::parse(d)?,
                None => PortalDomain::default(),
            };
            if cli.verbose {
                println!("BGS portal domain: {}", portal_domain.as_str());
            }

            // Resolve cert-bundle overrides (both optional, both validated).
            let mut cert_bundle = CertBundleConfig::default();
            if let Some(path) = &cli.cert_bundle {
                cert_bundle = cert_bundle.with_bundle_from_file(path)?;
                if cli.verbose {
                    println!(
                        "Cert bundle: {} ({} bytes)",
                        path,
                        cert_bundle.bundle_bytes().map(|b| b.len()).unwrap_or(0)
                    );
                }
            }
            if let Some(url) = &cli.cert_bundle_url {
                cert_bundle = cert_bundle.with_download_url(url)?;
                if cli.verbose {
                    println!("Cert bundle URL: {}", url);
                }
            }

            // Parse patch groups
            let patches = parse_patch_groups(&cli.patches)
                .map_err(|e| WowPatcherError::new(ErrorCategory::ValidationError, e))?;

            let input_path = PathBuf::from(&location);
            let output_path = PathBuf::from(cli.output.unwrap_or_else(|| "Arctium".to_string()));

            crate::cmd::execute::execute_patch(
                &input_path,
                &output_path,
                key_config,
                cli.version_url.as_deref(),
                cli.cdns_url.as_deref(),
                portal_domain,
                cert_bundle,
                patches,
                cli.dry_run,
                cli.sign,
                cli.verbose,
            )?;

            Ok(())
        }
    }
}
