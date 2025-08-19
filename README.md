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
Usage: wow-patcher [OPTIONS]

Options:
  -l, --warcraft-exe <PATH>     Path to the WoW executable
  -o, --output-file <NAME>      Output filename [default: Arctium]
  -s, --strip-binary-codesign   Remove macOS code signing [default: true]
  -n, --dry-run                  Preview changes without modifying files
  -h, --help                     Print help information
  -V, --version                  Print version information
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
