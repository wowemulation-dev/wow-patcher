# Classic WoW Patcher

A World of Warcraft client patcher written in Rust that lets you run the
WoW client on your own computer and connect to a personal server at home.

<div align="center">

[![Discord](https://img.shields.io/discord/1394228766414471219?logo=discord&style=flat-square)](https://discord.gg/Jj4uWy3DGP)
[![Sponsor](https://img.shields.io/github/sponsors/danielsreichenbach?logo=github&style=flat-square)](https://github.com/sponsors/danielsreichenbach)
[![CI Status](https://github.com/wowemulation-dev/wow-patcher/workflows/CI/badge.svg)](https://github.com/wowemulation-dev/wow-patcher/actions)
[![Rust Version](https://img.shields.io/badge/rust-1.92+-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE-APACHE)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)

</div>

## Overview

Part of the [WoW Emulation project](https://github.com/wowemulation-dev).

The patcher modifies WoW executables by redirecting the login portal,
replacing cryptographic keys, and injecting a custom certificate bundle
to enable connecting to a server you control. You must own the client and
expansions you want to play.

## How It Works

The patcher modifies your WoW executable by:

1. **Redirecting the login portal** - Replaces `.actual.battle.net` with
   `.localhost`, pointing the client at your own server.
2. **Replacing the RSA modulus** - Updates the 256-byte RSA key so the
   client trusts your certificate bundle instead of Blizzard's. The bundle
   tells the client which TLS certificates to accept, and the modulus proves
   the bundle itself hasn't been tampered with.
3. **Rewriting the bundle URL (older clients)** - For builds that download the
   bundle at startup (1.13.2), replaces Blizzard's download URL with your own.
4. **Updating Ed25519 keys** - For supported clients, replaces the Ed25519
   public key (32 bytes).

The patcher detects the client type automatically and applies the right
patches for your version.

## Features

- No in-client memory modifications (patches files on disk)
- Supports Windows, macOS, and Linux
- Works with WoW Classic and Classic Era
- Dry-run mode for previewing changes
- Automatic WoW executable detection on macOS

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

Run `wow-patcher --help` to see all options. The most common invocations:

```bash
# Windows
wow-patcher -l "C:\Program Files\World of Warcraft\_retail_\Wow.exe"

# macOS (auto-detects WoW location)
wow-patcher

# Linux
wow-patcher -l ./Wow.exe -o ./wow-private

# Preview changes without modifying files
wow-patcher --dry-run -l ./Wow.exe
```

<details>
<summary>Platform-specific paths</summary>

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

# Explicit path
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

</details>

<details>
<summary>Custom server / operator options</summary>

If you run your own server with custom keys or CDN URLs:

```bash
# Custom RSA modulus from a file (256 bytes)
wow-patcher -l ./Wow.exe --rsa-file ./custom_rsa.bin

# Custom CDN URLs
wow-patcher -l ./Wow.exe --version-url "http://my-cdn.example.com/versions"

# Custom portal domain
wow-patcher -l ./Wow.exe --bgs-portal-domain bgs.corp

# Inject a custom cert bundle
wow-patcher -l ./Wow.exe --rsa-file bundle-signing-modulus.bin \
    --cert-bundle data/cert-bundle/bgs-key-fingerprint
```

See [docs/src/configuration.md](docs/src/configuration.md) for details.

</details>

<details>
<summary>Requirements</summary>

This tool will only work if you:

1. Are connecting to a server with a valid TLS certificate that chains to a
   trusted root CA in your system trust store
2. Are using a hostname (not an IP address) for your portal cvar setting in
   `WTF/Config.wtf`

</details>

## Building from Source

### Prerequisites

- Rust 1.92.0 or higher
- Cargo (included with Rust)

## FAQ

**Q: Why does this generate an exe with the name `Arctium` by default?**

**A:** In the event your client crashes, this helps Blizzard filter out
community-server traffic from their automated client telemetry.

**Q: Do I need to remove code signing on macOS?**

**A:** Yes, the patched executable needs code signing removed to run on macOS. This is enabled by default.

**Q: macOS shows a warning that the app is damaged or from an unidentified developer. How do I fix this?**

**A:** macOS adds a quarantine attribute to downloaded files. Remove it by running:

```bash
xattr -dr com.apple.quarantine /path/to/wow-patcher
```

If you built from source this is not needed.

**Q: Can I use this with any server?**

**A:** The patcher ships with TrinityCore-compatible defaults. If your server
uses custom keys or a custom certificate bundle, use `--rsa-file`,
`--cert-bundle`, and related flags. See `wow-patcher --help` or
[docs/src/configuration.md](docs/src/configuration.md).

## Acknowledgments

- Enormous thanks to [Fabian](https://github.com/Fabi) from [Arctium](https://arctium.io/) for the knowledge that made this possible
- The TrinityCore team for their work on the server emulator

## Support the Project

If you find this project useful, please consider
[sponsoring the project](https://github.com/sponsors/danielsreichenbach).

This is currently a nights-and-weekends effort by one person. Funding goals:

- **20 hours/week** - Sustained funding to dedicate real development time
  instead of squeezing it into spare hours
- **Public CDN mirror** - Host a community mirror for World of Warcraft builds,
  ensuring long-term availability of historical game data

## Contributing

See the [Contributing Guide](CONTRIBUTING.md) for development setup and
guidelines.

## License

This project is dual-licensed under either:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

You may choose to use either license at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

---

**Note**: This project is not affiliated with Blizzard Entertainment. It is
an independent implementation based on reverse engineering by the World of
Warcraft emulation community.
