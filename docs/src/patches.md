# Patches

## What Gets Modified

The patcher replaces specific byte patterns in the WoW executable. These patterns represent embedded configuration.

## Mandatory Patches

### Portal URL

**Pattern**: `.actual.battle.net` (18 bytes)

**Replacement**: `.localhost` (10 bytes) followed by 8 NUL bytes.

The `.localhost` hostname resolves to `127.0.0.1` via `nss-myhostname`
(RFC 6761) without `/etc/hosts` edits. Using all NUL bytes would break
the URL assembly (NUL terminates C strings, dropping the path).

**Purpose**: Redirects the BGS login portal connection to a host you control

**Status**: Must be found for patching to succeed

**Note**: Override the target domain with `--bgs-portal-domain` (default:
`wowemu.dev`).

### RSA Modulus

**Patterns** (tried in order):

1. ConnectTo pattern (8 bytes signature)
2. Signature pattern (8 bytes signature)
3. Crypto pattern (8 bytes signature)

**Replacement**: Your 256-byte RSA modulus

**Purpose**: Verifies the cert bundle's PKCS#1 v1.5 signature.
The client uses this modulus to confirm the bundle file is authentic
before trusting the CA fingerprints listed inside it.

**Status**: Must be found for patching to succeed

**Note**: The patcher searches for 8-byte signatures to locate the full
256-byte RSA modulus in the binary.

## Optional Patches

### Cert Bundle (embedded)

**Pattern**: `{"Created":` (11 bytes)

**Replacement**: Your signed cert bundle JSON + signature (≤ 32761 bytes)

**Purpose**: Injects a custom certificate bundle into builds that ship one
embedded in `.rdata` (1.14.x / 2.5.3). The bundle's `RootCAPublicKeys`
lists which TLS CAs the client trusts.

**Status**: Optional, skipped on builds without an embedded bundle

**Note**: For builds that download the bundle at startup (1.13.2), use
`--cert-bundle-url` to redirect the download URL instead. See the
[certificate bundle guide](./custom-cert-bundle.md) for generation instructions.

### Cert Bundle URL

**Pattern**: `http://nydus.battle.net/Bnet/zxx/client/bgs-key-fingerprint`
(59 bytes)

**Replacement**: Your custom download URL (≤ 59 bytes)

**Purpose**: Redirects the cert bundle download to a host you control
(1.13.2, 1.14.x, 2.5.3 builds that fetch the bundle at startup).

**Status**: Optional, skipped on builds without a bundle URL pattern

**Note**: See the [certificate bundle guide](./custom-cert-bundle.md) for
bundle generation and serving instructions.

### Ed25519 Public Key

**Pattern**: Crypto Ed25519 signature (8 bytes)

**Replacement**: Your 32-byte Ed25519 public key

**Purpose**: Alternative signature verification

**Status**: Optional, warning if not found

### Version URL

**Patterns** (tried in order):

1. v1: `http://%s.patch.battle.net:1119/%s/versions` (43 bytes)
2. v2: `https://%s.version.battle.net/v2/products/%s/versions` (53 bytes)
3. v3: `https://%s.version.battle.net/v2/products/%s/%s` (48 bytes)

**Replacement**: Your custom version URL (or Arctium default)

**Purpose**: Changes where the client fetches version information

**Status**: Optional, warning if not found

### CDNs URL

**Pattern**: `http://%s.patch.battle.net:1119/%s/cdns` (40 bytes)

**Replacement**: Your custom CDN URL (or Arctium default)

**Purpose**: Changes where the client fetches CDN configuration

**Status**: Optional, warning if not found

**Note**: Skipped if v3 unified API is detected (the v3 pattern handles both).

## Patch Locations

The patcher verifies that all patterns are found in patchable sections of the binary:

| Binary Format | Patchable Sections |
|---------------|--------------------|
| PE (Windows) | `.rdata`, `.data` |
| Mach-O (macOS) | `__DATA`, `__DATA_CONST`, `__TEXT.__const` |
| ELF (Linux) | `.data` |

Patterns found in code sections (`.text`, `__TEXT`) are rejected. This prevents accidental code modification.

## Dry Run

Preview what will change before patching:

```bash
wow-patcher --dry-run -l Wow.exe -o Wow-patched.exe
```

Dry run shows:

- Client type and detected version
- All patterns found and their locations
- Replacement values that will be written

## What Is Not Patched

- **Runtime code patches** (cert chain check bypass, integrity guards,
  anti-tamper): These live in Arxan-encrypted `.text` and require the
  deferred `launch` subcommand. The static patcher only modifies data
  sections (`.rdata` / `.data`).
- **Cosmetic nydus URLs** (driver-unsupported, trial-restriction,
  gametime, checkout, checkoutnav): Not rewritten. `--bgs-portal-domain`
  only affects the `.actual.battle.net` suffix.

## Verification

After patching, verify the output file:

1. **Size**: Should be identical to input (patcher does not add or remove bytes)
2. **Permissions**: Unix executables have `0o755` permissions
3. **Code Signing**: macOS binaries preserve signatures unless `strip_codesign` is enabled
