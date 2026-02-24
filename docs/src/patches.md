# Patches

## What Gets Modified

The patcher replaces specific byte patterns in the WoW executable. These patterns represent embedded configuration.

## Mandatory Patches

### Portal URL

**Pattern**: `.actual.battle.net` (18 bytes)

**Replacement**: Null bytes (`0x00` repeated)

**Purpose**: Disables connection to Blizzard's portal server

**Status**: Must be found for patching to succeed

## RSA Modulus

**Patterns** (tried in order):

1. ConnectTo pattern (8 bytes signature)
2. Signature pattern (8 bytes signature)
3. Crypto pattern (8 bytes signature)

**Replacement**: Your 256-byte RSA modulus

**Purpose**: Changes which server certificates are trusted

**Status**: Must be found for patching to succeed

**Note**: The patcher searches for 8-byte signatures to locate the full 256-byte RSA modulus in the binary.

## Optional Patches

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

These patterns are defined in the code but not used:

- **Certificate Bundle**: The patcher does not replace Blizzard's certificate bundle with custom certificates. This feature from the reference implementation (Arctium) requires runtime patching.

## Verification

After patching, verify the output file:

1. **Size**: Should be identical to input (patcher does not add or remove bytes)
2. **Permissions**: Unix executables have `0o755` permissions
3. **Code Signing**: macOS binaries preserve signatures unless `strip_codesign` is enabled
