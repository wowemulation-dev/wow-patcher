# Usage

## Installation

Build from source:

```bash
cargo build --release
```

The binary will be at `target/release/wow-patcher`.

## Basic Command

```bash
wow-patcher -l /path/to/Wow.exe -o Wow-patched.exe
```

## Arguments

| Argument | Description | Required | Default |
|----------|-------------|-----------|----------|
| `-l, --warcraft-exe` | Path to WoW executable | Yes (auto-detected on macOS) | - |
| `-o, --output-file` | Output file path | No | `Arctium` |

## Optional Flags

| Flag | Description |
|------|-------------|
| `-h, --help` | Show help message |
| `-v, --verbose` | Print detailed output |
| `-n, --dry-run` | Preview changes without writing |
| `-s, --strip-binary-codesign` | Remove macOS code signing (default: true) |

## Custom Keys

Use TrinityCore defaults:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe
```

Load keys from files:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --rsa-file /path/to/rsa.bin \
  --ed25519-file /path/to/ed25519.bin
```

Load keys from hex strings:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --rsa-hex "91D59BB7D4E183A5..." \
  --ed25519-hex "15D618BD7DB577BD..."
```

## Custom CDN

Replace version and CDN URLs:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --version-url "https://my-cdn.example.com/versions" \
  --cdns-url "https://my-cdn.example.com/cdns"
```

## macOS Code Signing

The CLI strips macOS code signatures by default (`--strip-binary-codesign` defaults to `true`). This is required for patched binaries to run on macOS.

To keep the code signature (not recommended):

```bash
wow-patcher -l Wow.exe -s=false
```

## Dry Run

Preview what will change:

```bash
wow-patcher --dry-run -l Wow.exe -o Wow-patched.exe
```

## Verbose Output

See details about each patch operation:

```bash
wow-patcher -v -l Wow.exe -o Wow-patched.exe
```
