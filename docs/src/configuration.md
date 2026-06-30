# Configuration

## Keys

### What Keys Do

wow-patcher replaces cryptographic keys embedded in the WoW executable.
The RSA modulus verifies the cert bundle signature; the bundle itself
lists which TLS CAs the client trusts. The Ed25519 key is used for
alternative signature verification.

### Key Types

#### RSA Modulus

- **Size**: 256 bytes
- **Purpose**: Verifies the cert bundle's PKCS#1 v1.5 signature.
  The client uses this modulus to confirm the bundle file is
  authentic before trusting the CA fingerprints inside it.
- **Required**: Yes

#### Ed25519 Public Key

- **Size**: 32 bytes
- **Purpose**: Alternative signature verification for some protocols
- **Required**: For Retail and Classic (optional for Classic Era)

### Key Sources

#### TrinityCore Defaults

The patcher includes default keys for TrinityCore servers. Use these if your server uses standard TrinityCore configuration:

```rust
Patcher::new("Wow.exe")
    .trinity_core_keys()
    .patch()?;
```

#### Custom Keys

Generate keys for your server:

```bash
# RSA private key (TrinityCore uses this)
openssl genrsa -out server.key 2048

# Extract public modulus (256 bytes)
openssl rsa -in server.key -modulus -noout | sed 's/Modulus=//' | xxd -r -p
```

For Ed25519:

```bash
# Generate Ed25519 key pair
openssl genpkey -algorithm ed25519 -out ed25519.key

# Extract public key (32 bytes)
openssl pkey -in ed25519.key -pubout -outform DER | tail -c 32
```

#### Key Validation

All keys must pass these checks:

- Correct size (256 bytes for RSA, 32 bytes for Ed25519)
- Not all zeros
- Not all identical bytes (entropy check)

Invalid keys cause a validation error before patching begins.

### Key Storage

CLI accepts keys from files:

```bash
wow-patcher -l Wow.exe \
  --rsa-file /path/to/rsa.key \
  --ed25519-file /path/to/ed25519.key
```

Library accepts keys via `Patcher` builder methods:

- Bytes: `.custom_keys(&rsa, &ed25519)?`
- Hex strings: `.custom_keys_from_hex(rsa_hex, ed25519_hex)?`
- Files: `.custom_keys_from_files(rsa_path, ed25519_path)?`

`KeyConfig` is also available for direct key management via `KeyConfig::new()`, `KeyConfig::from_hex()`, and `KeyConfig::from_files()`.

## Portal Domain

### What the Portal Domain Does

The patcher rewrites the BGS login portal hostname suffix from
`.actual.battle.net` to `.actual.<your-domain>`. The default target
is `wowemu.dev` (byte-identical length to `battle.net`, so no NUL
padding is needed). Shorter domains up to 10 bytes work via NUL
padding. This is controlled by `--bgs-portal-domain` (or the
`WOW_BGS_PORTAL_DOMAIN` env var).

## Cert Bundle

### What the Cert Bundle Does

The cert bundle is a signed JSON file that tells the client which
TLS certificate authorities to trust (`RootCAPublicKeys`). Two
patching mechanisms exist depending on client version:

- **Embedded (1.14.x / 2.5.3)**: The bundle is baked into `.rdata`.
  `--cert-bundle` replaces those bytes directly.
- **Remote (1.13.2)**: The client downloads the bundle at startup.
  `--cert-bundle-url` rewrites the download URL.

Both mechanisms require the RSA modulus to be patched via `--rsa-file`
so the client trusts the bundle's signature.

Generate a bundle with `scripts/gen-cert-bundle.py`. See
`docs/custom-cert-bundle.md` for the full guide.

### URL Types

#### Portal URL

The patcher redirects the portal connection by rewriting the
`.actual.battle.net` suffix. The default target domain is
`wowemu.dev`.

#### Version URL

- **Default**: `https://us.version.battle.net/v2/products/wow/versions`
- **Purpose**: Fetches version information
- **Required**: No (optional)

#### CDNs URL

- **Default**: `https://us.cdn.battle.net/1119/wow/cdns`
- **Purpose**: Fetches CDN configuration
- **Required**: No (optional)

### Default URLs

When no custom URLs are provided, the patcher uses Arctium CDN defaults:

```rust
let version_url = "http://cdn.arctium.io/versions";
let cdns_url = "http://cdn.arctium.io/cdns";
```

### Custom URLs

Set your own CDN:

```bash
wow-patcher -l Wow.exe \
  --version-url "https://my-cdn.example.com/versions" \
  --cdns-url "https://my-cdn.example.com/cdns"
```

Or via library:

```rust
Patcher::new("Wow.exe")
    .version_url("https://my-cdn.example.com/versions")
    .cdns_url("https://my-cdn.example.com/cdns")
    .patch()?;
```

### Unified API (v3)

Newer WoW clients use a unified version API. If detected, the patcher uses the v3 pattern and ignores the separate CDNs URL.
