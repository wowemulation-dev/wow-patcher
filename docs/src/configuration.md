# Configuration

## Keys

### What Keys Do

wow-patcher replaces cryptographic keys embedded in the WoW executable. These keys are used to verify server certificates and establish encrypted connections.

### Key Types

#### RSA Modulus

- **Size**: 256 bytes
- **Purpose**: Verifies server certificate during TLS handshake
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
  --rsa-key /path/to/rsa.key \
  --ed25519-key /path/to/ed25519.key
```

Library accepts keys from:

- Bytes: `KeyConfig::new(rsa, ed25519)`
- Hex strings: `KeyConfig::from_hex(rsa_hex, ed25519_hex)`
- Files: `KeyConfig::from_files(rsa_path, ed25519_path)`

## CDN URLs

### What CDNs Do

CDN URLs tell the client where to download game updates and configuration files.

### URL Types

#### Portal URL

- **Default**: `https://us.actual.battle.net`
- **Replaced with**: Null bytes (disabled)
- **Required**: Yes

The patcher disables the portal URL to prevent the client from connecting to Blizzard's servers.

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
