# wow-patcher

World of Warcraft client patcher for TrinityCore-based private servers.

## What It Does

wow-patcher modifies WoW client binaries on disk to enable connections to private servers. It replaces embedded URLs and cryptographic keys with your server's configuration.

**Key difference**: This tool modifies files on disk. It does not modify running processes (unlike runtime patchers).

## Supported Clients

- Retail
- Classic
- Classic Era

## Supported Platforms

- Windows (PE binaries)
- macOS (Mach-O binaries)
- Linux (ELF binaries)

## How It Works

1. Reads the WoW executable
2. Detects client type and version
3. Replaces embedded URLs (portal, version, CDNs)
4. Replaces cryptographic keys (RSA modulus, Ed25519 public key)
5. Writes patched executable to new file

## Quick Start

### CLI

```bash
cargo build --release
./target/release/wow-patcher -l /path/to/Wow.exe -o Wow-patched.exe
```

### Library

```rust
use wow_patcher::Patcher;

Patcher::new("Wow.exe")
    .output("Wow-patched.exe")
    .trinity_core_keys()
    .patch()?;
```

## Next Steps

- [Usage](./usage.md) - Command-line interface
- [Library API](./library.md) - Rust crate integration
- [Configuration](./configuration.md) - Keys and CDNs
- [Patches](./patches.md) - What gets modified
