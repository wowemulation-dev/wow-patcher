# Runtime usage for WoW 12.1.5.70961

This guide covers the Windows x64 `launch` command added for client
**12.1.5.70961**. It includes separate examples for Eracolgar and a local
TrinityCore-compatible server.

The patcher changes the new client process in memory. It does not modify
`Wow.exe` or `wow_loader.dll` on disk. Launch through the patcher each time;
closing the client discards the runtime patches.

The client patcher is only one part of the connection setup. It does not add
12.1.5.70961 protocol support to TrinityCore, create accounts, configure realms,
serve game content, or sign metadata.

## 1. Build the patcher

From PowerShell in this repository:

```powershell
Set-Location G:\okwinza\aviana\wow-patcher
cargo build --release
$Patcher = "$PWD\target\release\wow-patcher.exe"
```

The examples below reuse `$Patcher` in the same PowerShell session. Without that
variable, substitute the full path to `wow-patcher.exe`.

The 70961 recipe accepts only these file identities:

```text
Wow.exe SHA-256:
75eaa7d66a4b02019d120cd9de4f6ed441a137a3289d49db95610c0349b4a11c

wow_loader.dll SHA-256:
72f7dacd10f936fbc225624fbbe8b9dadc6b8b4e4a8b32b410c22ad01ffe2e13
```

Keep `wow_loader.dll` beside `Wow.exe`. Close any running copy of that client
before launching another one.

## 2. Runtime arguments

| Argument | Purpose |
| --- | --- |
| `-l FILE` | Path to the exact `Wow.exe`. |
| `--server-cert FILE` | Public PEM certificate supplied to the client through file ID 7725530. Required. |
| `--ed25519-file FILE` | Raw 32-byte Ed25519 public key for metadata verification. |
| `--ed25519-hex HEX` | The same public key as 64 hexadecimal characters. |
| `--version-url URL` | Replaces both embedded NGDP templates. Optional. |
| `--portal-suffix ""` | Removes `.actual.battle.net`, so the full `SET portal` hostname is used verbatim. |
| `--config Config.wtf` | Selects an existing file under `WTF`. This is the default. |
| `--timeout 60` | Changes each startup-phase timeout from the default 30 seconds. Optional. |
| `--dry-run` | Validates inputs without creating a process or writing files. |
| `-v` | Prints the detected version, recipe, and patch plan. |

Use only one of `--ed25519-file` and `--ed25519-hex`. If neither is present, the
patcher uses its built-in TrinityCore Ed25519 public key.

For this retail runtime strategy, do not use `--rsa-file`, `--rsa-hex`,
`--cert-bundle`, `--cert-bundle-url`, `--cdns-url`, `--bgs-portal-domain`, or
`--patches`. Those options belong to other patching strategies.

All client and certificate paths must be ASCII because the installed file hook
passes a narrow path to the client.

## 3. Eracolgar: tested launch

The configuration must contain exactly one portal line. For the installation
used during development, `G:\GAMES\Eracolgar\_retail_\WTF\Config.wtf` contains:

```text
SET portal "auth.eracolgar.su"
```

Run:

```powershell
& $Patcher launch `
  -l "G:\GAMES\Eracolgar\_retail_\Wow.exe" `
  --server-cert "G:\GAMES\Eracolgar\_retail_\7725530" `
  --ed25519-hex "02596f0d0c061a8b30745988fd72c59e29ec367fb0f341f28e0f08d037bafc69" `
  --version-url "https://version.eracolgar.su/70961/%s/%s/%s" `
  --portal-suffix "" `
  --config Config.wtf `
  -v
```

This uses Eracolgar's public metadata key, metadata URL, and local certificate.
The empty portal suffix lets the client use `auth.eracolgar.su` directly from
`Config.wtf`.

Add `--dry-run` to check the same inputs without launching. A successful launch
prints `70961 patches installed and verified` and leaves the game running. This
checks client startup and patch integrity, not account login or world entry.

## 4. Local TrinityCore-compatible server

### 4.1 Server prerequisites

Before debugging the patcher, confirm that the server side supports this exact
client:

- A TrinityCore fork or compatible auth/realm/world implementation with
  **12.1.5.70961 protocol support**. Mainline TrinityCore does not gain that
  support from this patcher.
- An authentication service reachable from the client, normally on port 1119.
- Realm and world services configured for build 70961 and a reachable advertised
  realm address. `127.0.0.1` works only for a client on the same machine.
- Matching client game data.
- The server-side private key corresponding to the public certificate given to
  the patcher.
- If using custom NGDP metadata: correctly formed `versions` and `cdns` tables,
  a working content source, and signatures made with the matching private key.

For a same-machine test, this guide uses the hostname
`local.gameservers.trinitycore.org`. Map it to loopback in
`C:\Windows\System32\drivers\etc\hosts`:

```text
127.0.0.1 local.gameservers.trinitycore.org
```

Then put exactly one portal line in the client's `WTF\Config.wtf`:

```text
SET portal "local.gameservers.trinitycore.org"
```

Do not put `https://`, a metadata hostname, or a URL path in `SET portal`. If
you use another hostname, use it consistently in the portal and certificate CN.

### 4.2 Generate the server certificate and private key

Install OpenSSL 3.x and check that it is available:

```powershell
openssl version
```

Create a working directory outside the game installation:

```powershell
New-Item -ItemType Directory -Force .\local-tc
Set-Location .\local-tc
```

Generate an Ed25519 X.509 certificate and its separate private key:

```powershell
openssl req -x509 -newkey ED25519 -nodes -days 3650 `
  -keyout tc-server-private.pem `
  -out tc-server-public.pem `
  -subj "/CN=local.gameservers.trinitycore.org/O=TrinityCore/C=US"
```

The files have different owners:

- `tc-server-public.pem`: public certificate passed to `--server-cert`.
- `tc-server-private.pem`: private key retained by the auth/server deployment.
  Never pass it to the patcher or distribute it with the client.

Configure the compatible server to use this certificate/keypair. The exact
configuration directives depend on the server fork; they are not provided by
this patcher. If the portal hostname changes, regenerate the certificate with a
matching CN or use an appropriate SAN-bearing certificate supported by that
server and client combination.

### 4.3 First local launch without custom metadata

For a fully installed client and a server using the built-in TrinityCore
metadata key configuration, start with the smallest command:

```powershell
& $Patcher launch `
  -l "D:\Games\WoW\_retail_\Wow.exe" `
  --server-cert "$PWD\tc-server-public.pem" `
  --portal-suffix "" `
  --config Config.wtf `
  -v
```

Change `-l` to the actual client path. This command uses the built-in
TrinityCore Ed25519 public key and does not redirect the NGDP version service.

Do not add a generated metadata key or `--version-url` unless the corresponding
metadata service is configured. Changing only the client-side key can break
metadata signature verification.

### 4.4 Optional: generate a custom metadata signing keypair

This keypair is separate from the X.509 server certificate/keypair generated
above. It is needed only when operating a custom NGDP metadata service.

Generate the private key and its DER-encoded public key:

```powershell
openssl genpkey -algorithm ED25519 -out ngdp-private.pem
openssl pkey -in ngdp-private.pem -pubout -outform DER -out ngdp-public.der
```

Ed25519 SubjectPublicKeyInfo DER ends with the raw 32-byte public key. Extract it
in PowerShell:

```powershell
$der = [IO.File]::ReadAllBytes("$PWD\ngdp-public.der")
$raw = $der[($der.Length - 32)..($der.Length - 1)]
[IO.File]::WriteAllBytes("$PWD\ngdp-public.bin", $raw)
$hex = [BitConverter]::ToString($raw).Replace("-", "").ToLowerInvariant()
```

The outputs are:

- `ngdp-private.pem`: retained by the metadata signing service.
- `ngdp-public.bin`: raw 32-byte public key for `--ed25519-file`.
- `$hex`: the same public key for `--ed25519-hex`.
- `ngdp-public.der`: intermediate DER file; not the format expected by
  `--ed25519-file`.

Check the extracted key:

```powershell
(Get-Item .\ngdp-public.bin).Length  # Must be 32.
$hex.Length                          # Must be 64.
$hex
```

The patcher does not implement the metadata signing pipeline. The server must
sign the expected responses with `ngdp-private.pem` using the canonicalization
and signature transport required by this client. Possessing only a public key,
including Eracolgar's public key, does not allow signing.

### 4.5 Launch with custom metadata

Only after the metadata service is working, add the public key and build-pinned
URL:

```powershell
& $Patcher launch `
  -l "D:\Games\WoW\_retail_\Wow.exe" `
  --server-cert "$PWD\tc-server-public.pem" `
  --ed25519-file "$PWD\ngdp-public.bin" `
  --version-url "https://version.localhost/70961/%s/%s/%s" `
  --portal-suffix "" `
  --config Config.wtf `
  -v
```

To pass the same key as hex instead, replace the file argument with:

```powershell
  --ed25519-hex $hex `
```

The three `%s` fields are used for region, product, and table. With the example
URL, requests have paths such as:

```text
/70961/eu/wow/versions
/70961/eu/wow/cdns
```

For 70961, each replacement occupies a 48-byte inline slot including its NUL
terminator. The URL must therefore be ASCII and at most 47 bytes. Do not shorten
or relocate it by truncating placeholders.

The version service and content CDN are different components. Setting
`--version-url` does not create a CDN or rewrite the hosts listed inside the
`cdns` response.

## 5. Troubleshooting

- **No verified retail recipe:** the four-part file version is not exactly
  12.1.5.70961. Do not force another recipe.
- **Unverified executable or loader:** the SHA-256 differs. Use the matching
  client/loader pair; do not disable identity checks.
- **Portal still reaches Blizzard:** pass `--portal-suffix ""` and check that
  `Config.wtf` contains exactly one intended `SET portal` line.
- **PEM validation error:** pass the public certificate containing
  `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`, not a private
  key.
- **Ed25519 length error:** pass the raw 32-byte public key, not PEM or the
  44-byte DER wrapper. The hex form must contain exactly 64 hex characters.
- **Metadata signature failure:** check the metadata service's private key,
  signature format, response bodies, and the public key passed to the patcher.
- **Window opens but login fails:** investigate auth protocol support,
  certificate configuration, realm advertisement, metadata, and content. A game
  window alone does not prove server compatibility.
- **Unexpected code or loader-state mismatch:** stop. Do not copy RVAs from
  another build or patch the encrypted executable on disk.

See `docs/retail-runtime.md` for the patch sequence, hash tables, and validation
scope.
