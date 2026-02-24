# Library API

## Cargo.toml

Add to your `Cargo.toml`:

```toml
[dependencies]
wow-patcher = "0.1"
```

Enable CLI feature if needed:

```toml
wow-patcher = { version = "0.1", features = ["cli"] }
```

## Basic Usage

```rust
use wow_patcher::Patcher;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Patcher::new("Wow.exe")
        .patch()?;

    Ok(())
}
```

## Builder API

### Input and Output

```rust
Patcher::new("Wow.exe")
    .output("Wow-patched.exe")  // Optional, auto-generated if not set
    .patch()?;
```

### Keys

#### TrinityCore Defaults

```rust
Patcher::new("Wow.exe")
    .trinity_core_keys()
    .patch()?;
```

#### Custom Keys from Bytes

```rust
let rsa_key: Vec<u8> = /* 256 bytes */;
let ed25519_key: Vec<u8> = /* 32 bytes */;

Patcher::new("Wow.exe")
    .custom_keys(&rsa_key, &ed25519_key)?
    .patch()?;
```

#### Custom Keys from Hex

```rust
Patcher::new("Wow.exe")
    .custom_keys_from_hex(
        "AA00BB11...",  // RSA (512 hex chars = 256 bytes)
        "CC22DD33...",  // Ed25519 (64 hex chars = 32 bytes)
    )?
    .patch()?;
```

#### Custom Keys from Files

```rust
Patcher::new("Wow.exe")
    .custom_keys_from_files(
        "/path/to/rsa.bin",
        "/path/to/ed25519.bin",
    )?
    .patch()?;
```

### CDN URLs

```rust
Patcher::new("Wow.exe")
    .version_url("https://my-cdn.example.com/versions")
    .cdns_url("https://my-cdn.example.com/cdns")
    .patch()?;
```

### Options

```rust
Patcher::new("Wow.exe")
    .dry_run(true)              // Preview changes
    .strip_codesign(true)        // Remove macOS code signature
    .verbose(true)               // Print details
    .patch()?;
```

## Error Handling

```rust
use wow_patcher::{Patcher, WowPatcherError};

fn patch() -> Result<(), WowPatcherError> {
    match Patcher::new("Wow.exe").patch() {
        Ok(_) => println!("Success"),
        Err(e) => eprintln!("Error: {}", e),
    }
    Ok(())
}
```

## Key Validation

Keys must meet these requirements:

| Key | Size | Restrictions |
|------|------|--------------|
| RSA | 256 bytes | Not all zeros, not all identical bytes |
| Ed25519 | 32 bytes | Not all zeros, not all identical bytes |

Validation occurs when `KeyConfig` is created or loaded.
