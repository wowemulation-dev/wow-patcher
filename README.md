# Classic WoW Patcher

A World of Warcraft client patcher written in Rust that enables retail WoW clients
to connect to TrinityCore-based private servers.

<div align="center">

[![Discord](https://img.shields.io/discord/1394228766414471219?logo=discord&style=flat-square)](https://discord.gg/Q44pPMvGEd)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

</div>

## Features

- Binary patching without in-client memory modifications
- Cross-platform support (Windows, macOS, Linux)
- Support for multiple WoW client versions (Classic, Classic Era)
- Dry-run mode for previewing changes
- Automatic WoW executable detection on macOS
- Code signing removal for macOS compatibility

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/wowemulation-dev/wow-patcher
cd wow-patcher

# Build the project
cargo build --release

# The binary will be available at target/release/wow-patcher
```

## Usage

### Basic Usage

```bash
# Windows - basic patching
wow-patcher -l "C:\Program Files\World of Warcraft\_retail_\Wow.exe"

# macOS - auto-detect WoW location (default)
wow-patcher

# Linux - explicit path required
wow-patcher -l ./Wow.exe -o ./wow-private

# Preview changes without modifying files (dry run)
wow-patcher --dry-run -l ./Wow.exe
```

### Command-Line Options

```
Usage: wow-patcher [OPTIONS] [COMMAND]

Commands:
  version  Print version information
  help     Print this message or the help of the given subcommand(s)

Options:
  -l, --warcraft-exe <FILE>         Path to the WoW executable (auto-detected on macOS)
  -o, --output-file <FILE>          Output filename [default: Arctium]
  -n, --dry-run                      Preview changes without modifying files
  -s, --strip-binary-codesign       Remove macOS code signing [default: true]
  -v, --verbose                      Enable verbose output
      --rsa-file <FILE>              Custom RSA modulus file (256 bytes binary)
      --rsa-hex <HEX>                Custom RSA modulus as hex string (512 hex characters)
      --ed25519-file <FILE>          Custom Ed25519 public key file (32 bytes binary)
      --ed25519-hex <HEX>            Custom Ed25519 public key as hex string (64 hex characters)
      --version-url <URL>            Custom version URL for CDN redirection
      --cdns-url <URL>               Custom CDNs URL for CDN redirection
  -h, --help                         Print help information
  -V, --version                      Print version information
```

### Platform-Specific Examples

#### Windows

```bash
# Custom output location
wow-patcher -l "C:\Program Files\World of Warcraft\_retail_\Wow.exe" -o "D:\Games\WowTC.exe"

# Handle paths with spaces (use quotes)
wow-patcher -l "C:\Program Files (x86)\World of Warcraft\_retail_\Wow.exe" -o "C:\My Games\Wow Private.exe"
```

#### macOS

```bash
# Auto-detect WoW and keep code signing (not recommended)
wow-patcher -s=false

# Explicit path with default code signing removal
wow-patcher -l "/Applications/World of Warcraft/_retail_/World of Warcraft.app/Contents/MacOS/World of Warcraft"

# Custom output name
wow-patcher -o WowTrinityCore
```

#### Linux

```bash
# Basic patching with custom output
wow-patcher -l /opt/wow/Wow.exe -o /home/user/games/wow-tc

# Wine installation example
wow-patcher -l "$HOME/.wine/drive_c/Program Files/World of Warcraft/_retail_/Wow.exe" -o ./WowPrivate.exe
```

### Advanced Options

#### Custom Cryptographic Keys

If you're connecting to a server that uses different cryptographic keys than standard TrinityCore:

```bash
# Using custom RSA modulus from a file (256 bytes)
wow-patcher -l ./Wow.exe --rsa-file ./custom_rsa.bin

# Using custom RSA modulus as hex string (512 hex characters)
wow-patcher -l ./Wow.exe --rsa-hex "91D59BB7D4E183A5EC3710..." # (512 hex chars total)

# Using custom Ed25519 public key from a file (32 bytes)
wow-patcher -l ./Wow.exe --ed25519-file ./custom_ed25519.bin

# Using custom Ed25519 public key as hex string (64 hex characters)
wow-patcher -l ./Wow.exe --ed25519-hex "15D618BD7DB577BD..." # (64 hex chars total)

# Combining custom keys
wow-patcher -l ./Wow.exe --rsa-file ./rsa.bin --ed25519-hex "15D618BD..."
```

#### CDN Redirection

Redirect the client to custom CDN servers for game data and patches:

```bash
# Custom version server
wow-patcher -l ./Wow.exe --version-url "http://my-cdn.example.com/versions"

# Custom CDNs server
wow-patcher -l ./Wow.exe --cdns-url "http://my-cdn.example.com/cdns"

# Both CDN URLs
wow-patcher -l ./Wow.exe --version-url "http://cdn.myserver.com/versions" --cdns-url "http://cdn.myserver.com/cdns"
```

#### Development Options

```bash
# Enable verbose output for debugging
wow-patcher -l ./Wow.exe -v

# Combine with dry-run to preview all changes
wow-patcher -l ./Wow.exe -v --dry-run --version-url "http://local.test/versions"

# Test custom keys without applying changes
wow-patcher -l ./Wow.exe --dry-run --rsa-file ./test_rsa.bin --ed25519-file ./test_ed25519.bin
```

#### Version Command

```bash
# Show basic version information
wow-patcher version

# Show detailed version information with build metadata
wow-patcher version --detailed
```

## Requirements

This tool will ONLY work if you:

1. Are connecting to a server with a valid TLS certificate that chains to a trusted root CA in your system trust store
2. Are using a hostname and not an IP address for your portal cvar setting in `WTF/Config.wtf`
3. Are connecting to a server that uses the same gamecrypto key as TrinityCore

## How It Works

The patcher modifies your WoW executable by:

1. **Removing Battle.net portal connections** - Replaces `.actual.battle.net` with empty bytes
2. **Replacing RSA authentication keys** - Updates the RSA modulus to TrinityCore's 256-byte key
3. **Updating Ed25519 keys** - For supported clients, replaces the Ed25519 public key (32 bytes)

The patcher automatically detects the client type (Retail vs Classic Era) and applies the appropriate patches.

## Building from Source

### Prerequisites

- Rust 1.86.0 or higher
- Cargo (included with Rust)

### Development

```bash
# Run in development mode
cargo run -- -l /path/to/Wow.exe

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -- -l /path/to/Wow.exe

# Format code
cargo fmt

# Run linter
cargo clippy

# Build documentation
cargo doc --open
```

## FAQ

**Q: Why does this generate an exe with the name `Arctium` by default?**

**A:** In the event your client crashes, this helps Blizzard filter out the private server noise from their automated client telemetry.

**Q: Do I need to remove code signing on macOS?**

**A:** Yes, the patched executable needs code signing removed to run on macOS. This is enabled by default.

**Q: Can I use this with any private server?**

**A:** No, this only works with TrinityCore-based servers that use the standard TrinityCore cryptographic keys.

## License

This project is dual-licensed under either:

- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)

at your option.

## Acknowledgments

- Enormous thanks to [Fabian](https://github.com/Fabi) from [Arctium](https://arctium.io/) for the knowledge that made this possible
- The TrinityCore team for their amazing work on the server emulator

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/wowemulation-dev/wow-patcher/issues).

---

**Note**: This project is not affiliated with or endorsed by Blizzard
Entertainment. It is an independent implementation based on reverse engineering
efforts by the World of Warcraft emulation community for educational and
preservation purposes.
