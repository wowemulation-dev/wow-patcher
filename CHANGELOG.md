# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
