# AGENTS.md

Guidance for coding agents working in this repository. Documents commands, patterns, conventions, and known issues.

## Project Overview

World of Warcraft client patcher that modifies WoW binaries to enable connections to TrinityCore-based and other private servers. Supports two patching modes:

1. **Static binary patching** (default): on-disk modification of `Wow.exe`. Rewrites byte sequences in `.rdata`/`.data`. Limited to data-section patches because `.text` is Arxan-encrypted on disk in current builds.
2. **Runtime patching** (`launch` subcommand, in progress): launches the client suspended, lets the Arxan TLS callback decrypt `.text` in memory, then patches both code and data via `WriteProcessMemory`, then resumes. This is the only way to bypass certificate-bundle parsing, public-key pinning, and the certificate-chain check, all of which live in `.text`.

Supports Retail, Classic, and Classic Era clients. Works as both a Rust library crate and a CLI binary (behind the `cli` feature flag).

- **Tech stack**: Rust (Edition 2024, MSRV 1.92), binary parsing via `goblin` (PE/Mach-O/ELF), pattern matching with `regex`, hex decoding. Runtime mode uses `windows-sys` for the Win32 process APIs.
- **License**: Dual-licensed under MIT OR Apache-2.0.
- **Binary formats**: PE (Windows), Mach-O (macOS), ELF (Linux).
- **Runtime mode platforms**: Windows native and Linux+Wine. The `dump-text` subcommand demonstrates that `CreateProcessA`, `NtSuspendProcess`, `ReadProcessMemory`, `VirtualQueryEx`, and `WriteProcessMemory` all work under Wine. Earlier project notes claimed otherwise; that claim was wrong.

## Reference Implementation

Based on Arctium WoW-Launcher (`~/Repos/github.com/Arctium/WoW-Launcher`), a C#/.NET project that uses runtime patching. Arctium creates a suspended Windows process and patches memory before execution using NT API calls:

- `NtSuspendProcess` / `NtResumeProcess`
- `WriteProcessMemory`
- `VirtualQueryEx` for region enumeration

The static-patch mode in this crate (default `wow-patcher` invocation) implements the on-disk subset of those patches: RSA moduli, Ed25519 public key, portal hostname, version/CDNs URLs. The runtime mode (`launch` subcommand) ports the remainder: certificate-bundle replacement, certificate-chain check bypass, integrity checks, and dynamic patch sites that have no on-disk byte sequence because the surrounding code is Arxan-encrypted at rest.

The Arctium Classic-DLL (`~/Repos/github.com/Arctium/Classic-DLL`) provides runtime hooks (CASC file loading, Lua restrictions) via DLL injection. Those features are out of scope for this crate; they would belong in a separate DLL-injector tool that uses the same launcher infrastructure.

## Commands

### Building

```bash
cargo build            # Development build
cargo build --release  # Release build (LTO, strip, opt-level 3)
cargo clean            # Clean build artifacts
```

### Testing

```bash
cargo nextest run                    # Run all tests (~69 tests)
cargo nextest run -- --nocapture     # Run tests with output
cargo nextest run test_name          # Run specific test
```

### Code Quality

```bash
cargo fmt                     # Format code
cargo fmt -- --check          # Check formatting
cargo clippy -- -D warnings   # Lint with warnings as errors
cargo doc --no-deps           # Build documentation
```

### Running

```bash
cargo run -- -l /path/to/Wow.exe              # Patch with defaults
cargo run -- -l /path/to/Wow.exe -o Arctium   # Custom output name
cargo run -- --dry-run -l /path/to/Wow.exe    # Preview changes
cargo run -- -l /path/to/Wow.exe -v           # Verbose output
```

### Pre-Commit Checklist

Before considering a task complete:

1. `cargo fmt`
2. `cargo clippy -- -D warnings`
3. `cargo nextest run`
4. `cargo build`

## Architecture

### Module Structure

```
src/
  lib.rs          Library root. Re-exports: WowPatcherError, KeyConfig, Patcher
  main.rs         CLI entry point. Calls cli::run()
  cli.rs          clap argument parsing (behind "cli" feature)
  patcher.rs      Builder-pattern API for library consumers
  binary/
    mod.rs        Pattern type (Vec<i16>), patch(), find_pattern(), traits
    section.rs    PE/Mach-O section detection via goblin
  cmd/
    mod.rs        Module re-export
    execute.rs    execute_patch() -- main patching orchestration (654 lines)
  errors/
    mod.rs        WowPatcherError, ErrorCategory, convenience constructors
  keys/
    mod.rs        KeyConfig struct with validation and multiple loaders
  patterns/
    mod.rs        10 static patterns using OnceLock<Pattern>
  platform/
    mod.rs        ClientType enum, detect_client_type(), version extraction
    darwin.rs     macOS codesign removal via codesign CLI
    linux.rs      find_wow_executable() (unused)
    windows.rs    find_wow_executable() (unused)
  trinity/
    mod.rs        TrinityCore RSA/Ed25519 keys, CDN URL generation
  version/
    mod.rs        Build info from compile-time env vars (build.rs)
```

### Key Components

- **Patcher (`src/patcher.rs`)**: Builder-pattern API. Configures input/output paths, keys, CDN URLs, dry_run, strip_codesign, verbose. Delegates to `cmd::execute::execute_patch()`.
- **Binary module (`src/binary/`)**: `Pattern` is `Vec<i16>` where `-1` is a wildcard matching any byte. `patch()` finds the first occurrence and replaces bytes.
- **Patterns (`src/patterns/`)**: 10 patterns defined via `OnceLock<Pattern>` for thread-safe lazy initialization.
- **Keys (`src/keys/`)**: `KeyConfig` struct with validation (size, zero bytes, entropy checks). Loaders: `trinity_core()`, `new()`, `custom()`, `from_hex()`, `from_files()`.
- **Trinity (`src/trinity/`)**: Constants `RSA_MODULUS` (256 bytes), `CRYPTO_ED25519_PUBLIC_KEY` (32 bytes). URL generators for version and CDNs endpoints.
- **Errors (`src/errors/`)**: `WowPatcherError` with `ErrorCategory` enum (FileOperationError, ValidationError, PatchingError, PlatformError). Has context HashMap for metadata.

### Pattern Type

`Pattern` is `Vec<i16>`. Values 0-255 match literal bytes. The value `-1` acts as a wildcard matching any byte. This allows flexible pattern matching across binary versions.

### Design Patterns

- **Builder pattern**: `Patcher` struct with chained configuration methods.
- **Lazy static initialization**: Patterns use `OnceLock` for thread-safe initialization.
- **Error categorization**: Errors classified as FileOperation, Patching, Validation, or Platform.
- **Wildcard pattern matching**: `-1` values in patterns match any byte.
- **Conditional compilation**: `#[cfg(target_os)]` for platform-specific code.
- **Feature flags**: CLI functionality behind the `cli` feature.

### Patching Process (`execute_patch`)

1. Input validation: File exists, size between 1KB and 1GB.
2. Client detection: Path-based heuristic identifies Retail, Classic, Classic Era, or Unknown.
3. Version extraction: Tries `goblin` parsing (stub, returns None), then regex fallback for patterns like `10.2.5.53584`.
4. Section validation: Locates all pattern offsets and verifies each is in a patchable section (`.rdata`/`.data` for PE, `__DATA`/`__DATA_CONST` for Mach-O).
5. Dry run: If enabled, prints preview of all patches and exits.
6. Apply patches in order:
   - Portal: mandatory, replaced with null bytes. Error if not found.
   - RSA modulus: mandatory, tries ConnectTo → Signature → Crypto pattern. Error if none found.
   - Ed25519: optional (depends on client type). Warning if not found.
   - Version URL: optional, tries v1 → v2 → v3 patterns. Warning if not found.
   - CDNs URL: optional (skipped if v3 unified API used). Warning if not found.
7. Write output with 0o755 permissions on Unix.
8. Strip code signing on macOS if enabled.

## Code Style and Conventions

### Formatting

- **Indentation**: 4 spaces (no tabs)
- **Line endings**: LF (Unix-style)
- **Charset**: UTF-8
- **Final newline**: Required
- **Trailing whitespace**: Not allowed

No `rustfmt.toml` or `clippy.toml` — uses Rust defaults.

### Rust Patterns

- Builder pattern for configuration structs (see `Patcher`, `KeyConfig`).
- `OnceLock` for lazy static initialization (patterns).
- Group fields logically in structs.
- Document public APIs with `///` doc comments including examples.
- Use `#[must_use]` for functions returning values that should not be ignored.
- Prefer returning `Self` for builder methods.
- `Pattern` type is `Vec<i16>` (not `Vec<u8>`) to support `-1` wildcards.

### Error Handling

Custom `WowPatcherError` type with `ErrorCategory` enum.

- **Constructor**: `WowPatcherError::new(category, message)`
- **Wrapping**: `WowPatcherError::wrap(category, message, cause)`
- **Context**: `.with_context(key, value)` for metadata

### Module Structure

- One module per logical component in `src/`.
- Module re-exports in `mod.rs` files.
- Tests inline with code using `#[cfg(test)]` module.
- Library re-exports from `lib.rs`: `WowPatcherError`, `KeyConfig`, `Patcher`.

### Naming

- `snake_case` for functions, methods, variables, modules.
- `PascalCase` for types, traits, enums.
- `SCREAMING_SNAKE_CASE` for constants and `OnceLock` statics.
- Descriptive names, avoid abbreviations.

## Defined Patterns (10 total)

| Pattern           | Signature/Value                                         | Length |
| ----------------- | ------------------------------------------------------- | ------ |
| Portal            | `.actual.battle.net` as bytes                           | 18     |
| ConnectToModulus  | `[0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5]`      | 8      |
| SignatureModulus  | `[0x35, 0xFF, 0x17, 0xE7, 0x33, 0xC4, 0xD3, 0xD4]`      | 8      |
| CryptoRsaModulus  | `[0x71, 0xFD, 0xFA, 0x60, 0x14, 0x0D, 0xF2, 0x05]`      | 8      |
| CryptoEdPublicKey | `[0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD]`      | 8      |
| VersionUrl (v1)   | `http://%s.patch.battle.net:1119/%s/versions`           | 43     |
| VersionUrl (v2)   | `https://%s.version.battle.net/v2/products/%s/versions` | 53     |
| VersionUrl (v3)   | `https://%s.version.battle.net/v2/products/%s/%s`       | 48     |
| CdnsUrl           | `http://%s.patch.battle.net:1119/%s/cdns`               | 40     |
| CertBundle        | `{"Created":`                                           | 11     |

The CertBundle pattern is defined but never called from `execute_patch()`. Certificate bundle replacement is not implemented.

## Communication Guidelines

Use Markdown, no emojis. These guidelines apply to all communication: conversations, documentation, commit messages, changelogs, and code comments.

### Honesty and Accuracy

All statements must be realistic and factual. Provide honest assessments rather than making things sound like achievements.

- Do not glorify, overstate, or exaggerate capabilities.
- Describe what actually exists and works, not what might work or is planned.
- Avoid "complete" unless every feature is implemented and tested.
- Use accurate terms: "working", "functional", "pending", or "planned".
- State when you do not know something.
- Say when you consider something a bad plan rather than avoiding the topic.
- Be the devil's advocate when appropriate.

### Language Style

- Use simple, direct language.
- Write short sentences that state facts.
- Remove filler words and subjective qualifiers.
- Every sentence should convey necessary information.

### Avoid These Words

These restrictions apply to prose (conversations, documentation, comments, commit messages). They do not apply when words are used as programming language keywords, identifiers, or technical terms in code.

- Quality descriptors: "robust", "excellent", "comprehensive", "powerful"
- Subjective terms: "clean", "safe", "elegant", "beautiful"
- Unnecessary modifiers: "very", "really", "quite", "extremely"
- Marketing language: "cutting-edge", "state-of-the-art", "modern"

### Structure

- Lead with facts, not descriptions.
- Remove redundant explanations.
- Focus on what users need to know.
- List what exists, not its quality.

## Known Issues

### Certificate Bundle Pattern Unused

`cert_bundle_pattern()` is defined in `src/patterns/mod.rs` but is never called from `execute_patch()`. Certificate bundle replacement is not implemented.

### Version Extraction Stubs

`extract_version()` in `src/platform/mod.rs` parses binaries with goblin but returns `None` for both PE and Mach-O. Only the regex fallback (`extract_version_fallback`) works.

### Dead Code

- `platform::linux::find_wow_executable()` — never called externally.
- `platform::windows::find_wow_executable()` — never called externally.
- Error convenience constructors (`new_file_error`, `new_validation_error`, `new_patching_error`, `new_platform_error`) — never called from application code.

### Example Bug

`examples/custom_keys.rs` uses `"C".repeat(512)` and `"D".repeat(64)` which decode to all-identical bytes (`[0xCC; 256]` and `[0xDD; 32]`). These fail the `KeyConfig::validate()` entropy check.

## Implemented Features

1. Portal pattern: `.actual.battle.net` replacement with null bytes.
2. Three RSA modulus patterns: ConnectTo, Signature, and Crypto (with fallback chain). Full 256-byte replacement.
3. Ed25519 public key pattern: Crypto Ed25519 pattern. Full 32-byte replacement.
4. Version URL patching: three URL patterns (v1 HTTP, v2 HTTPS, v3 unified API) with Arctium CDN defaults.
5. CDNs URL patching: HTTP CDN pattern with Arctium CDN default.
6. macOS code signing removal via `codesign --remove-signature`.
7. Section validation: verifies patches target data sections, not code sections.
8. Client type detection: path-based heuristic for Retail, Classic, Classic Era.
9. Library API: builder-pattern `Patcher` struct with `WowPatcherError`, `KeyConfig` re-exports.
10. Custom key support: load from bytes, hex strings, or files.
11. Custom CDN support: override version and CDNs URLs via CLI or API.
12. Dry run mode: preview patches without writing files.
13. Build metadata: git commit, version, build date embedded at compile time.

## Library API

The primary API is the `Patcher` builder:

```rust
use wow_patcher::Patcher;

Patcher::new("Wow.exe")
    .output("Wow-patched.exe")
    .trinity_core_keys()           // or .custom_keys(), .custom_keys_from_hex()
    .custom_cdn("http://my.cdn")   // or .version_url(), .cdns_url()
    .dry_run(false)
    .strip_codesign(true)
    .verbose(true)
    .patch()?;
```

### KeyConfig

`KeyConfig` struct with validation supports loading keys from:

- TrinityCore defaults (`KeyConfig::trinity_core()`)
- Raw bytes (`KeyConfig::new()`, `KeyConfig::custom()`)
- Hex strings (`KeyConfig::from_hex()`)
- Files (`KeyConfig::from_files()`)

Validation rules:

- RSA must be 256 bytes.
- Ed25519 must be 32 bytes.
- Neither can be all zeros or all identical bytes (entropy check).

## Testing Approach

- **Unit tests**: inline with each module using `#[cfg(test)]`.
- **Integration tests**: in `tests/` directory, use `tempfile` for temporary files.
- **Test coverage**: ~69 tests across all modules.
- **Mock executables**: created in integration tests using `create_mock_executable()`.

When adding features:

1. Write unit tests for the implementation.
2. Add integration tests for end-to-end workflows.
3. Use `tempfile` for file-based tests.
4. Verify both success and error paths.

## Test Coverage

| Module                               | Tests                                         |
| ------------------------------------ | --------------------------------------------- |
| `patcher.rs`                         | 13 (builder API, defaults, output naming)     |
| `binary/mod.rs`                      | 10 (pattern matching, wildcards, edge cases)  |
| `binary/section.rs`                  | 3 (PE/Mach-O section detection)               |
| `patterns/mod.rs`                    | 12 (all patterns, distinctness, URL patterns) |
| `keys/mod.rs`                        | 7 (validation, hex, file loading)             |
| `trinity/mod.rs`                     | 7 (key integrity, URL generation)             |
| `errors/mod.rs`                      | 8 (error types, context, chaining)            |
| `platform/mod.rs`                    | 3 (client detection, ed25519 usage)           |
| `platform/{darwin,linux,windows}.rs` | 3 (platform-specific)                         |
| `tests/integration_test.rs`          | 3 (full workflow, real patterns, errors)      |

The integration test `test_patching_with_real_patterns` verifies the full 256-byte RSA modulus and 32-byte Ed25519 replacements landed correctly. Three regression tests in `binary::tests` (`test_patch_replacement_longer_than_pattern_writes_full_replacement`, `test_patch_ed25519_size_replacement`, `test_patch_replacement_past_end_is_error`) cover the corner cases of the fix.

## Features Not Implemented

### Certificate Bundle Replacement

Pattern is defined but patching logic is not implemented. Arctium replaces the Blizzard certificate bundle (a ~30KB JSON structure starting with `{"Created":`) with a custom certificate bundle containing self-signed certificates.

### Runtime-Only Features (planned for the `launch` subcommand)

Static binary patching cannot reach code in `.text` because Arxan encrypts it on disk. The reference implementation (Arctium WoW-Launcher) handles these via runtime patching after the Arxan TLS callback decrypts `.text` in memory. This crate's `launch` subcommand (in progress on `feat/runtime-patch-arctium`) ports the same approach:

- **Anti-tamper bypass**: patches integrity checks, certificate validation, and memory remap detection.
- **Certificate bundle replacement**: rewrites the embedded `{"Created":...}` cert bundle in memory after Arxan decrypts the surrounding code paths.
- **Certificate chain dev mode**: bypasses certificate chain validation for local/private IP connections so localhost servers can present non-Blizzard CAs.
- **Public-key pinning bypass**: replaces the libcurl-style pinned-public-key check site so non-Blizzard leaf certs are accepted.
- **Static auth seed** (planned, not yet started): injects assembly that derives a fixed auth seed from the RSA modulus location at runtime.

Out of scope for this crate (would belong in a separate tool):

- **Custom file loading (mod loader)**: hooks file-loading functions to redirect file IDs to custom paths.
- **DLL injection**: loads Classic-DLL for CASC hooks and Lua restriction removal.

### Other Missing Features

- **Cache management**: option to delete game cache before launch.
- **Registry redirection**: Windows registry path for launcher login configuration.

## Design Philosophy

The crate ships two complementary patching modes:

- **Static (default)**: on-disk byte rewrites in `.rdata`/`.data`. Runs anywhere a host filesystem and a binary parser exist. Limited to patches whose target sites are not Arxan-encrypted at rest. Works on native Windows, native macOS, and Linux (with the binary copied locally).
- **Runtime (`launch` subcommand)**: launches the client suspended, lets Arxan decrypt `.text`, then patches in-memory via `WriteProcessMemory`. Required for any patch site inside Arxan-encrypted code (cert bundle parser, cert chain check, public-key pinning, integrity checks). Runs on native Windows and on Linux+Wine. The `dump-text` subcommand has demonstrated the same Win32 API surface works under Wine.

Tradeoff: the static mode handles the simpler patches and works without launching the client. The runtime mode is required for the cert-pinning bypass and any code-section patch.

## Git Workflow

Follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

- `feat:` for new features
- `fix:` for bug fixes
- `refactor:` for code restructuring
- `chore:` for maintenance tasks
- `docs:` for documentation changes
- `test:` for test additions/changes

Use accurate terms: "add" for new features, "fix" for bug fixes, "update" for enhancements. Write short, factual commit messages without exaggeration.

## Configuration Files

- **No CI/CD**: no GitHub Actions or other CI pipelines configured.
- **No `rustfmt.toml` or `clippy.toml`**: uses default Rust formatting and linting.
- **No `rust-toolchain.toml`**: relies on edition 2024 and MSRV 1.92.
- **No `CHANGELOG.md`**: not present.
- **Markdown linting**: `.markdownlint.jsonc`, `.markdownlintignore` configured (uses `markdownlint-cli`).
- **Editor config**: `.editorconfig` with 4-space indent for Rust, LF line endings.
- **Build script**: `build.rs` sets `GIT_COMMIT`, `GIT_VERSION`, `BUILD_DATE`, `BUILT_BY` env vars.
- **Release profile**: LTO enabled, single codegen unit, stripped symbols.
- **5 examples**: `basic_usage`, `battlenet_agent`, `custom_cdn`, `custom_keys` (has bug), `dry_run`.

## Examples

Five example programs demonstrate library usage:

- `basic_usage.rs`: simple patching with TrinityCore defaults.
- `battlenet_agent.rs`: Battle.net agent string patching.
- `custom_cdn.rs`: custom CDN URL configuration.
- `custom_keys.rs`: custom RSA and Ed25519 keys (has bug with entropy).
- `dry_run.rs`: preview changes without modifying files.

When adding features, add or update examples accordingly.
