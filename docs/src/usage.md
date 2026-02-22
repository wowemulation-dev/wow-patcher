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
| `-l, --launcher` | Path to WoW executable | Yes | - |
| `-o, --output` | Output file path | No | `{name}-patched.{ext}` |

## Optional Flags

| Flag | Description |
|------|-------------|
| `-h, --help` | Show help message |
| `-v, --verbose` | Print detailed output |
| `--dry-run` | Preview changes without writing |

## Custom Keys

Use TrinityCore defaults:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe
```

Load keys from files:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --rsa-key /path/to/rsa.key \
  --ed25519-key /path/to/ed25519.key
```

## Custom CDN

Replace version and CDN URLs:

```bash
wow-patcher -l Wow.exe -o Wow-patched.exe \
  --version-url "https://my-cdn.example.com/versions" \
  --cdns-url "https://my-cdn.example.com/cdns"
```

## macOS Code Signing

The patcher preserves macOS code signatures. To remove them (needed for running patched binaries):

```bash
codesign --remove-signature Wow-patched.exe
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
