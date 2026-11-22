# How to add support for a new retail or Forever build

This guide describes the steps needed to add a verified recipe for a new WoW 12.x or later client build (including World of Warcraft: Forever / Classic Beta). The process requires reverse engineering the target binary on Windows x64.

## Prerequisites

- A working Windows x64 environment (native or Wine)
- The target `Wow.exe` (or `WowB.exe` for Forever) and its matching `Wow_loader.dll`
- Ghidra, IDA Pro, or another disassembler with x64 support
- The `wow-patcher` source tree checked out

## Step 1: Record build metadata

Extract the file version from the executable. This is the four-component version string (major.minor.patch.build) that the client reports at startup. Store it as `Version { major, minor, patch, build }`.

## Step 2: Compute SHA-256 hashes

Compute the SHA-256 hash of both the executable and its loader DLL. These are used for identity validation — the recipe rejects any binary whose hash does not match.

```bash
sha256sum Wow.exe Wow_loader.dll
```

Record both hashes in the `Recipe` struct as `image_hash` and `loader_hash`.

## Step 3: Verify PE layout

Confirm the executable is a PE32+ x64 image with a `.text` section. Record the `.text` section's virtual address (must be `0x1000`) and virtual size. The virtual size determines how much of the encrypted code page must be swept to make it readable.

```rust
// In recipe.rs
Recipe {
    version: Version { major, minor, patch, build },
    text_size: 0xXXXXXXXX, // .text virtual size
    // ... other fields
}
```

## Step 4: Find the five code-site RVAs

The runtime installs five code patches at specific addresses in `.text`. Each site has a unique instruction signature that must match after Arxan decryption. Reverse engineer these addresses from the decrypted in-memory image.

### Method: dump-text or launch with verbose output

1. Launch the client suspended and let Arxan decrypt `.text` (use `dump-text` or the runtime `launch` command).
2. Disassemble the `.text` section and search for each signature pattern.

### Signature patterns

| Site | Purpose | Signature template |
|---|---|---|
| **resolver** | Certificate file-path resolver | `48 89 5C 24 08 57 48 83 EC 20 48 8B F9 48 ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? 74 ?? 48 ?? CD` |
| **gate** | Certificate validation branch | `41 F6 C5 01 74 ?? 85 ED 74 ?? 48 8B 0D ?? ?? ?? ?? 8B D5 E8` (older) or `41 F6 C5 01 74 5C 85 ED 74 16 48 8B 0D 3C 71 01 01 8B D5 E8` (newer, holds-entry builds) |
| **helper** | Zero-return helper function | `48 89 5C 24 18 57 48 83 EC 40 80 79 5D 00 48 8B F9` |
| **result_bl** | Force BL register to 1 | `?? ?? EB 02 B3 01 48 8B CE FF 15 FB 10 25 00` (older) or `32 DB EB 02 B3 01 48 8B CE FF 15 8B 4D F8 00` (newer, holds-entry builds) |
| **result_edi** | Force EDI result to 1 | `?? ?? ?? ?? ?? ?? ?? B6 F0 84 C0 0F 85 ED 02 00 00` (older) or `E8 4A 3C 00 00 44 0F B6 F0 84 C0 0F 85 E5 02 00 00` (newer, holds-entry builds) |

Record each RVA and add it to the `Recipe` struct:

```rust
Recipe {
    resolver: 0xXXXXXXXX,
    gate: 0xXXXXXXXX,
    helper: 0xXXXXXXXX,
    result_bl: 0xXXXXXXXX,
    result_edi: 0xXXXXXXXX,
}
```

### Verifying signatures

After finding candidate addresses, verify each signature matches the template exactly (wildcard `??` bytes can be anything). The runtime validates these before installing patches — a mismatch aborts the launch.

## Step 5: Determine the sweep layout

The code-page preparation step makes Arxan-encrypted `.text` readable. There are two layouts:

### Split sweep (older builds, e.g. 68887)

- Executes a temporary reader from empty storage after `.text`, skipping 100 fixed pages.
- The `SKIP` array in `sweep_ranges()` lists the page offsets to skip (in units of 0x1000).
- Set `holds_entry() = false`.

### Entry-hold sweep (newer builds, e.g. 69587)

- Temporarily holds the entry point (`EB FE` at a specific RVA), then sweeps the entire `.text` from borrowed data storage.
- The borrowed storage is at a specific `.rdata` RVA (e.g. `0x3785000`).
- Set `holds_entry() = true`, record `stub_rva()` and verify the 64 original entry bytes.

To determine which layout applies:

1. Check if the build's entry point handler uses the entry-hold approach (the newer builds temporarily overwrite the entry with `EB FE` to prevent execution during sweep).
2. If the entry point is at a known RVA and the `.rdata` section has a large reserved area after `.text`, it is likely an entry-hold build.

## Step 6: Find data-slot RVAs

These are in `.rdata` or `.data` sections and are patched before process resume:

| Slot | Purpose | How to find |
|---|---|---|
| **Ed25519 key** | Public key for signature verification | Search for the 8-byte prefix `15 D6 18 BD 7D B5 77 BD` in `.rdata`/`.data` |
| **Portal suffix** | `.actual.battle.net` hostname | Search for the literal string `.actual.battle.net\0` (19 bytes including NUL) |
| **Version URL [0]** | First NGDP version URL template | Search for `https://cn.version.battlenet.com.cn/v2/products/%s/%s` or similar |
| **Version URL [1]** | Second NGDP version URL template | Search for `https://%s.version.battle.net/v2/products/%s/%s` |

Record each RVA:

```rust
Recipe {
    ed25519: 0xXXXXXXXX,
    portal: 0xXXXXXXXX,
    urls: [0xXXXXXXXX, 0xXXXXXXXX],
}
```

## Step 7: Add the recipe entry

Add a new `Recipe` to the `RECIPES` array in `src/cmd/retail/recipe.rs`:

```rust
pub(super) const RECIPES: [Recipe; N] = [
    // ... existing recipes
    Recipe {
        version: Version { major, minor, patch, build },
        text_size: 0xXXXXXXXX,
        resolver: 0xXXXXXXXX,
        gate: 0xXXXXXXXX,
        helper: 0xXXXXXXXX,
        result_bl: 0xXXXXXXXX,
        result_edi: 0xXXXXXXXX,
        ed25519: 0xXXXXXXXX,
        portal: 0xXXXXXXXX,
        urls: [0xXXXXXXXX, 0xXXXXXXXX],
        image_hash: "SHA256_HEX_OF_EXE",
        loader_hash: "SHA256_HEX_OF_LOADER",
    },
];
```

Update the `validate_retail_recipe()` function in `src/cmd/launch_strategy.rs` to accept the new version:

```rust
pub(crate) fn validate_retail_recipe(version: Version) -> Result<(), String> {
    if matches!(
        (version.major, version.minor, version.patch, version.build),
        (12, 0, 7, 68887)
        | (12, 1, 0, 69587)
        | (NEW_MAJOR, NEW_MINOR, NEW_PATCH, NEW_BUILD)
    ) {
        Ok(())
    } else {
        Err(format!(...))
    }
}
```

## Step 8: Test the recipe

### Dry-run validation

```bash
wow-patcher launch -l /path/to/Wow.exe \
  --server-cert /path/to/server.pem \
  --dry-run -v
```

This checks version, hashes, image layout, data-slot original bytes, and string bounds without starting a process.

### Live validation

```bash
wow-patcher launch -l /path/to/Wow.exe \
  --server-cert /path/to/server.pem \
  --portal-suffix "" -v
```

Verify:
- The client starts and remains responsive (check startup time).
- All five code patches survive in memory (the runtime reads them back after installation).
- Data replacements persist across the launch sequence.
- The executable and loader hashes are unchanged on disk.
- Temporary bytes (entry bytes, borrowed storage) are restored to their original values.

### Regression test

Run a second launch from a cold start to confirm consistency. Compare startup times between runs.

## Step 9: Add tests

Add the new version to the test in `src/cmd/launch_strategy.rs`:

```rust
#[test]
fn retail_recipe_requires_all_four_version_components() {
    // ... existing assertions
    assert_eq!(
        validate_retail_recipe(Version::new(NEW_MAJOR, NEW_MINOR, NEW_PATCH, NEW_BUILD)),
        Ok(())
    );
}
```

## Common pitfalls

- **Wrong sweep layout**: Using split-sweep for an entry-hold build (or vice versa) causes the code-page preparation to fail or corrupt memory. Verify by checking whether the entry point is temporarily overwritten.
- **Borrowed storage not empty**: For entry-hold builds, the `.rdata` cave after `.text` may contain live data. Do not assume it is zero-filled — save and restore its contents.
- **Signature mismatch**: The instruction signatures are build-specific. A signature that matches 68887 will not necessarily match a newer build even if the addresses are close. Always verify against the actual decrypted bytes.
- **NGDP URL templates change**: Newer builds may use different URL templates than `https://%s.version.battle.net/v2/products/%s/%s`. Search for the actual strings in `.rdata` rather than assuming a pattern.
- **File ID 7725530 is stable**: The certificate-path hook targets file ID 7725530. This has been stable across builds but verify it has not changed in the target build by checking the resolver's comparison instruction.

## Reference: existing recipes

| Build | text_size | sweep layout | Entry-hold |
|---|---|---|---|
| 12.0.7.68887 | `0x35C0B4C` | Split (skip 100 pages) | No |
| 12.1.0.69587 | `0x3783B4C` | Full sweep from borrowed storage | Yes |
| 12.1.5.70961 | `0x3AC1E7C` | Full sweep from borrowed storage | Yes |

Use these as templates for address discovery and layout determination. The Forever client (Classic Beta, build 70009) is based on the same retail engine and follows the same patterns — it just needs its own recipe entry once the addresses are reverse-engineered.
