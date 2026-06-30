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
| `--bgs-portal-domain` | Portal hostname suffix (max 10 bytes) | No | `wowemu.dev` |
| `--cert-bundle` | Cert bundle file to embed (≤ 32761 bytes) | No | - |
| `--cert-bundle-url` | Cert bundle download URL (≤ 59 bytes) | No | - |

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

## Cert Bundle

For clients that download the bundle at startup (1.13.2), redirect
the download URL:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --rsa-file bundle-signing-modulus.bin \
  --cert-bundle-url "http://my-server.example.com/bnet/bundle"
```

For clients with an embedded bundle (1.14.x / 2.5.3), inject a custom
bundle:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --rsa-file bundle-signing-modulus.bin \
  --cert-bundle data/cert-bundle/bgs-key-fingerprint
```

## Portal Domain

Override the login portal hostname:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --bgs-portal-domain bgs.corp
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
