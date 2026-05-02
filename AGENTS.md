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
6. Apply patches in dependency order (each step's effect depends on the prior step's output):
   - **RSA modulus** (mandatory): tries ConnectTo → Signature → Crypto pattern. Error if none found. Defeats the cert-bundle signature pin.
   - **Ed25519 key** (optional, modern clients only).
   - **Cert bundle bytes** (optional, `--cert-bundle FILE`): inject signed bundle into the embedded `{"Created":` slot. 1.14.x / 2.5.3 only; skipped with note on other builds.
   - **Cert bundle URL** (optional, `--cert-bundle-url URL`): rewrite the 59-byte download URL slot. 1.13.2 / 1.14.x / 2.5.3 only; skipped with note on other builds.
   - **BGS portal** (mandatory): rewrites `.actual.battle.net` to `.actual.<bgs-portal-domain>`. Default domain `wowemu.dev`; configurable via `--bgs-portal-domain DOMAIN` or `WOW_BGS_PORTAL_DOMAIN` env var. Error if not found. See "Portal pattern NUL-collapse pitfall" below.
   - **Version URL** (optional): tries v1 → v2 → v3 patterns.
   - **CDNs URL** (optional, skipped if v3 unified API used).
7. Write output with 0o755 permissions on Unix.
8. Strip code signing on macOS if enabled.

### Logical groups (out of scope for current patcher)

The patcher's static `.rdata` rewrites only cover the auth-flow critical path. These additional groups exist as identified-but-not-implemented work:

- **`nydus-cosmetic`**: rewrite the 5 cosmetic `nydus.battle.net` URLs (driver-unsupported, trial-restriction, gametime, checkout, checkoutnav). NOT covered by `--bgs-portal-domain` -- it deliberately scopes only to `.actual.battle.net`. Future opt-in flag.
- **`launcher-login`**: redirect the Phoenix launcher-login registry-key path. Useful for running stock + patched clients side-by-side without WEB_TOKEN collision.
- **`cert-runtime`**: runtime memory-write patches (`.text` section) for cert-validation conditional branches: `CertBundle` JZ-NOP, `CertCommonName` MOV-1, `CertChain` flag flip. Arctium uses these in dev mode + 1.14+ legacy. We rely on the static RSA-modulus replacement instead.
- **`arxan-runtime`**: anti-crash + anti-tamper memory writes Arctium does at process launch. Requires the deferred runtime `launch` subcommand.

See `<management-repo>/src/reverse-engineering/wow-classic/_cross-build/patcher-coverage.md` for the canonical group catalog with per-build presence + Arctium-vs-us coverage matrix.

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

## Portal pattern NUL-collapse pitfall

The Portal pattern targets `.actual.battle.net` as 18 ASCII bytes in `.rdata`. The 1.13.x client constructs the BGS portal URL at runtime via NUL-terminated string concat:

```
"https://" + "<region>" + ".actual.battle.net" + "/client/login/external?targetRegion=<region>"
```

**Replacing `.actual.battle.net` with 18 NUL bytes (the obvious "empty fill") breaks this.** `strcat`/`strcpy`/`std::string::append` stop at the first NUL byte, so the assembled URL collapses to `https://<region>` — path silently dropped, DNS fails, the network module reports `ERROR_NETWORK_MODULE_SOCKET_CLOSED` (`BLZ51901016`) and the client shows the disconnect dialog before reaching auth.

The fix in this crate replaces with `.localhost` (10 bytes) followed by 8 NUL bytes via `Pattern::padded(b".localhost")`. The runtime concat then produces `https://<region>.localhost/client/login/external?...`, where `<region>.localhost` resolves to `127.0.0.1` via `nss-myhostname` (RFC 6761) on Linux without needing `/etc/hosts` edits.

Use `Pattern::padded(target)` instead of `Pattern::empty()` for any URL hostname / suffix replacement. The all-NUL form (`Pattern::empty()`) is appropriate only for fixed-length binary key replacements where the surrounding code reads the bytes via length-aware operations (the 256-byte RSA modulus replacement is one such case).

For RE context (the BLZ error code decoding, the live-test trace that uncovered this pitfall, and the broader URL-construction conventions in the 1.13.2 client) see the management repo's Serena memories `analysis/wow-1132-portal-patch-nul-bug` and `analysis/wow-1132-client-url-catalog`.

## Pre-login HTTP probes (scope expansion, not yet implemented)

Live testing 2026-04-30 against an unmodified WoW Classic 1.13.2 client revealed that **the client makes blocking HTTP probes to legacy Blizzard endpoints before the BGS auth flow even begins**. Both endpoints accept TCP but never respond, so the in-game network module raises `ERROR_NETWORK_MODULE_SOCKET_CLOSED` (BLZ51901016) and the client surfaces "You have been disconnected" before the user can click Login.

The two probes captured on the wire (HTTP/1.1 with `User-Agent: Blizzard Web Client`):

| Hostname                            | Path        | Purpose                                  |
| ----------------------------------- | ----------- | ---------------------------------------- |
| `launcher.worldofwarcraft.com`      | `/alert`    | Maintenance / news alert banner          |
| `support.worldofwarcraft.com`       | `/kb/`      | Support knowledge base reachability check |

Regional siblings exist for both (`launcher.wow-europe.com`, `launcher.worldofwarcraft.co.kr`, `support.wow-europe.com`, `support.worldofwarcraft.co.kr`).

Critical detail: **`/etc/hosts` redirects on the host alone do not fix this**. Wine's nss honors the hosts file (verified via `wine cmd /c "ping ..."`), but `Wow.exe` itself bypasses the system resolver for these hostnames — almost certainly via libcurl with `c-ares` or a Windows DNS API path that does not consult Wine's hosts shim. The connection still goes to the real Blizzard IP (`137.221.106.103`, RIPE-NL) even with the hosts entry present.

**Static-patching scope (verified empirically against the 1.13.2 dump):**

- `support.worldofwarcraft.com/kb/`, `support.wow-europe.com/kb/`, `support.worldofwarcraft.co.kr/kb/`, `support.worldofwarcraft.co.kr/kbtw/` — **all four are flat ASCII strings in `.rdata`** (clustered at offset `0x1c7e978` in the decrypted dump). These are patchable via the existing pattern infrastructure. New pattern: `SUPPORT_KB_URL_PATTERN` (or four sibling patterns; either shape works since they sit contiguously).
- `launcher.worldofwarcraft.com/alert` — **NOT in the binary anywhere** as a flat string. Verified across `.text` (decrypted dump), `.rdata`, `.rsrc`, and UTF-16 forms; zero hits for the hostname, the `/alert` path, the `http://launcher.` prefix, or any obvious template form like `launcher.%s`. The hostname materialises only on the wire. The static patcher cannot rewrite this URL because there is no string to find.

That means a configurable URL flag is straightforward for the support endpoints (`--support-kb-url`, with regional siblings) but **the launcher alert hostname requires a different mechanism**:

1. **Runtime-mode hooking** — same path as the deferred Arctium-style runtime patcher. After Arxan unpacks, hook the URL constructor before the libcurl call.
2. **Transparent network redirection** — iptables redirect 80/443 egress to localhost. Belongs in operator tooling, not the patcher.
3. **Find the constructor and patch its inputs** — open question for future Ghidra work. The constructor probably reads from a config the client fetches early (one of the `*.battle.net` BPSV files or similar) or assembles the URL from compiled-in pieces split across multiple constant loads.

Until one of those lands, the recommended workaround for live testing is: **/etc/hosts redirect + a port-80 stub server** to absorb the launcher alert and support probes. The hosts-file redirect is unreliable for the launcher URL specifically (Wow.exe bypasses it for that hostname — likely libcurl with c-ares), but it is reliable for the support hostnames. Combining hosts redirects with a stub on 80 covers both.

The corresponding server side belongs in the **PoC's BGS reimplementation**, not here. The patcher's job is just the URL substitution.

For the broader RE context (BLZ error code decoding, the Lua glue chain that drives the disconnect dialog, why we believed it was an auth failure when it was really a pre-auth probe failure), see the management repo's Serena memories `analysis/wow-1132-pre-login-http-probes` and `analysis/wow-1132-blz-error-codes`.

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

1. Portal pattern: `.actual.battle.net` replacement with `.localhost` (NUL-padded to 18 bytes). See "Portal pattern NUL-collapse pitfall" below.
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

### Runtime-mode features (deferred; not on the critical path)

Empirical verification of Arctium's pattern catalogue against four
WoW Classic builds (1.13.2.31650, 2.5.3.42328, 3.4.3.53788,
4.4.2.60895) showed:

- The four data-only Common patterns (Portal + 3 RSA moduli for
  pre-Wrath; Portal + ConnectTo + Ed25519 for Wrath+) hit cleanly
  in their applicable builds. These all sit in `.rdata`, which is
  not Arxan-encrypted, so they are reachable via static patching.
- The Windows-specific code patterns (`CertBundle`, `CertCommonName`,
  `CertChain`, `Integrity`, `Remap`) do **not** match any of the
  four Classic builds. Arctium's byte sequences are tuned for the
  current retail compiler output; older Classic builds need their
  own patterns derived per build.
- The libcurl public-key-pinning check uses the stock RSA modulus
  in `.rdata` as its source of truth. Replacing the modulus (now
  correctly written end-to-end after the truncation fix in commit
  `5363c0e`) defeats the pin check without touching code in `.text`.

Conclusion: the static patcher, with the truncation bug fixed, is
sufficient to redirect Classic clients onto custom servers. Runtime
patching becomes valuable only when:

- A future Classic build adds new integrity checks or anti-tamper
  guards in `.text` that the static patcher cannot reach.
- We need to bypass `VerifyServerCertificateWithBundle` directly
  (e.g. to ship a leaf cert whose CA is not in the embedded bundle
  AND whose modulus differs from the replaced stock modulus).
- Mod-loading or DLL-injection features are added.

Verification details and per-build pattern hit counts are recorded
in the management repo's Serena memory `analysis/wow-patcher-pattern-verification`.

The `feat/runtime-patch-arctium` branch contains the partially-built
runtime infrastructure:

- `src/patterns/runtime/{common,windows}.rs`: ported Arctium patterns
  with 11 unit tests. These remain useful when runtime mode is
  revived; the Common patterns are universal and the Windows ones
  serve as retail-current defaults.
- `src/binary/mod.rs`: truncation fix + 3 regression tests + bounds
  check. **This is the load-bearing change** and is on the branch
  even though the rest of the runtime work is deferred.
- `AGENTS.md`: runtime-mode design notes; this section.

Out of scope for this crate (would belong in a separate tool):

- **Custom file loading (mod loader)**: hooks file-loading functions
  to redirect file IDs to custom paths.
- **DLL injection**: loads Classic-DLL for CASC hooks and Lua
  restriction removal.

#### When to revive the runtime work

Three triggers:

1. A specific Classic build cannot be bypassed via the static patcher
   (manifests as login-portal connections being rejected at the TLS
   layer despite all four Common data patches landing). At that
   point, derive Windows code patterns per build using the existing
   Ghidra databases for `Wow.exe` / `WowClassic.exe`.
2. We need cert-chain dev-mode bypass (e.g., presenting a
   different-CN leaf to satisfy the client's hostname matching).
3. Mod-loading or auth-seed assembly injection becomes a goal.

Until then: ship static patches only, verify via the per-build
smoke-test framework in the management repo's PoC.

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
