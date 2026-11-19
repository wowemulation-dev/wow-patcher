# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.1.0] - 2026-11-19

### Added

#### Static patching

- Portal pattern: rewrite the BGS Aurora-RPC portal hostname suffix
  `.actual.battle.net` to `.actual.<domain>` (default `wowemu.dev`,
  NUL-padded for shorter domains). Configurable via `--bgs-portal-domain`
  or the `WOW_BGS_PORTAL_DOMAIN` environment variable.
- RSA modulus replacement: three 8-byte signature patterns (ConnectTo,
  Signature, Crypto) locate the full 256-byte modulus in `.rdata` and
  replace it. Defeats the libcurl public-key-pinning check.
- Ed25519 public key replacement: 32-byte replacement via the Crypto
  Ed25519 pattern (modern clients).
- Version URL patching: three patterns (v1 HTTP, v2 HTTPS, v3 unified
  API) with Arctium CDN defaults.
- CDNs URL patching: HTTP CDN pattern with Arctium CDN default; skipped
  when the v3 unified API is detected.
- Cert bundle injection: `--cert-bundle FILE` replaces the embedded
  `{"Created":` bundle slot (1.14.x / 2.5.3 builds).
- Cert bundle download URL rewrite: `--cert-bundle-url URL` replaces the
  59-byte `nydus.battle.net` download URL literal (1.13.2 / 1.14.x /
  2.5.3 builds).
- Selectable patch groups: `--patches` accepts `all`, `rsa`, `ed25519`,
  `portal`, `version`, `cdns`, `cert-bundle`, `cert-bundle-url`.
- Custom keys: `--rsa-file` / `--rsa-hex` and `--ed25519-file` /
  `--ed25519-hex`.
- Custom CDN URLs: `--version-url` and `--cdns-url`.
- Dry-run mode: `--dry-run` previews all patches without writing files.
- macOS code signing removal via `codesign --remove-signature` (default
  on; disable with `-s=false`).
- Section validation: every pattern offset is verified to lie in a
  patchable data section (`.rdata`/`.data` for PE, `__DATA`/`__DATA_CONST`
  for Mach-O); code sections are rejected.
- Client type detection: path-based heuristic for Retail, Classic, and
  Classic Era.

#### Runtime patching

- `launch` subcommand: strategy selected from the executable's file
  version. Verified retail recipes cover 12.0.7.68887 and 12.1.0.69587
  (Windows x64, requires `--server-cert`); documented older version
  families (1.13.x, 1.14.x, 2.5.x, 3.4.x, 4.4.x, 9.x, 10.x) use the
  existing runtime strategy.
- `dump-text` subcommand: dump the Arxan-decrypted `.text` section from a
  running client (Windows/Wine).
- `dump-sections` subcommand: dump one or more PE sections (`.text`,
  `.data`, `.rdata`, `.pdata`) from a running client, with
  `--post-decrypt-wait` for runtime-populated `.data`.

#### Library API

- `Patcher` builder: input/output paths, keys, CDN URLs, portal domain,
  cert bundle, patch groups, dry-run, strip-codesign, verbose.
- `KeyConfig` with validation (size, zero bytes, entropy) and loaders:
  `trinity_core()`, `new()`, `custom()`, `from_hex()`, `from_files()`.
- `PatchGroup` bitflags for fine-grained patch selection.
- `WowPatcherError` with `ErrorCategory` (FileOperation, Validation,
  Patching, Platform) and context metadata.

#### Tooling

- `scripts/gen-cert-bundle.py`: generates a full TLS CA, leaf server
  cert, bundle-signing key, and signed BGS cert bundle in one pass.
- Five examples: `basic_usage`, `battlenet_agent`, `custom_cdn`,
  `custom_keys`, `dry_run`.
- mdBook documentation site (`docs/`) with usage, library API,
  configuration, patches, and cert-bundle guides.

#### CI / GitHub workflows

- Added a GitHub Actions workflow (`.github/workflows/ci.yml`) that detects
  changed files, then runs quick checks (`fmt`, `check`, `clippy`),
  `cargo-deny`, the test suite on MSRV 1.98 and stable, a docs build, and
  coverage collection, with a branch-protection gate.
- Pinned all actions to commit SHAs and upgraded them to the latest
  versions: `actions/checkout` v4 → v7, `tj-actions/changed-files`
  v45 → v47, `dtolnay/rust-toolchain` v1, `Swatinem/rust-cache` v2 → v2.9.3,
  `taiki-e/install-action` v2 → v2.90.5, `EmbarkStudios/cargo-deny-action`
  v2 → v2.1.2, `codecov/codecov-action` v5 → v7.
- Added `timeout-minutes` to all jobs.
- Scoped `permissions` to the least privilege per job.
- Set `persist-credentials: false` on all checkout steps.
- All workflows pass `jactionlint --strict-exit` with zero warnings and
  errors.

#### Configuration

- Added `rust-toolchain.toml` pinning the 1.98 toolchain with rustfmt,
  clippy, rust-src, and rust-analyzer.
- Added `.config/nextest.toml` with `default`, `ci`, and `release` profiles.
- Added `deny.toml` for `cargo-deny`: security advisories, license
  compliance, and banned dependencies across the supported targets.

#### Tooling

- Added `jactionlint` (via mise) for linting GitHub Actions workflows.
- Added `protobuf`, `sqlx-cli`, and `oauth2c` tools (via mise).

### Changed

#### Workspace

- Rust MSRV 1.92 → 1.98.

#### Tooling

- Replaced `actionlint` with `jactionlint` in mise.
- Removed the unused `node` tool from mise.

### Fixed

#### dump-text

- `dump-text` now supports Wine 11, which reports the main module as
  `MEM_MAPPED` (0x40000) instead of `MEM_IMAGE` and may map the first page
  as only 0x1000 bytes. Module-base detection now accepts both memory types
  and a minimum region size of 0x1000 at the preferred address.

[Unreleased]: https://github.com/wowemulation-dev/wow-patcher/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/wowemulation-dev/wow-patcher/releases/tag/v0.1.0
