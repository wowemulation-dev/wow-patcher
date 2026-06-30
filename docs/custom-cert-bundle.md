# Generating a Custom Certificate Bundle

This guide walks through generating a signed BGS certificate bundle that
the WoW Classic client will trust after patching. A single script does
everything: CA generation, leaf certificate, bundle-signing key, and the
signed bundle JSON.

## Prerequisites

- Python 3.10+ with the `cryptography` library

```bash
pip install cryptography
```

## How the client uses certificates

The WoW client needs to trust two things before it will connect to your
server: the server itself, and the file that tells it which servers to
trust. It handles these as two separate checks.

### Verifying the server (TLS)

When the client connects to the login server, the server presents a
certificate -- like showing an ID card. The client looks up which
certificate authorities it trusts and checks whether the server's
certificate was signed by one of them.

The list of trusted authorities lives in the **cert bundle**, a small file
containing the fingerprint of your TLS CA. The bundle tells the client:
"allow connections to servers whose certificate was issued by this CA."

### Verifying the bundle itself (signature)

This creates a chicken-and-egg problem: how does the client know the bundle
file is genuine? If anyone could swap in a different CA fingerprint, they
could trick the client into trusting a malicious server.

The solution is a second, separate check. The bundle file carries a digital
signature at the end -- like a tamper-proof seal. The client verifies this
signature against a key that is **hardcoded in the game binary**. By
replacing this key during patching, you make the client accept bundles
signed by you instead of Blizzard.

### How the client gets the bundle

Older builds (1.13.2) **download** the bundle from a Blizzard URL at
startup. Patching rewrites that URL to point at your own server. You serve
the bundle file over HTTP.

Newer builds (1.14.x / 2.5.3) have the bundle **embedded** directly inside
the game executable. Patching replaces those bytes in-place. No HTTP
serving needed.

In both cases the signature check happens the same way: the client
verifies the bundle against the modulus injected into the binary via
`--rsa-file`.

## Key architecture: two separate keys

The cert bundle uses two distinct keypairs that serve different purposes
and must not be conflated:

| Key | Purpose | Injected into binary? |
|-----|---------|-----------------------|
| **TLS CA** (`ca.pem` / `ca-key.pem`) | Signs the leaf server cert presented by your BGS server. The client trusts this CA because its SPKI hash is listed in the bundle's `RootCAPublicKeys`. | No. Embedded inside the bundle JSON as `SigningCertificates[0].RawData` and referenced by SPKI hash. |
| **Bundle-signing key** (`bundle-signing-key.pem`) | Signs the bundle JSON itself (`PKCS#1 v1.5 / SHA-256`). The client verifies this signature against the modulus injected into the binary. | Yes. The modulus replaces the stock RSA modulus via `--rsa-file`. |

The TLS CA is the root of trust for **TLS server authentication** (is the
BGS server who it claims to be?). The bundle-signing key is the root of
trust for **bundle authenticity** (is this bundle file from a trusted
source?). They are independent: you can keep the same TLS CA and rotate
the bundle-signing key (re-patching the binary each time), or vice versa.

## Overview

The signed JSON bundle has the following wire format:

```text
+------------------------------+
| JSON document (UTF-8)        |  <-- variable length
+------------------------------+
| "NGIS"  (4 bytes, ASCII)     |  <-- magic, marks signature start
+------------------------------+
| Signature (256 bytes, LE)    |  <-- RSA-2048 PKCS#1 v1.5, byte-reversed
+------------------------------+
```

The signature is RSA-2048 PKCS#1 v1.5 over `SHA-256(JSON || "Blizzard
Certificate Bundle")`, with the signature bytes reversed to little-endian
(matching Blizzard's internal BigNumber representation).

For the full technical specification, see
`management/src/reverse-engineering/wow-classic/1.13.2/31650/bgs/cert-bundle-signature-format.md`.

## Step 1: Run the bundle generator

Run the script from the project root. It generates everything — CA, leaf
cert, bundle-signing key, and signed bundle — in one pass:

```bash
cd "$(git rev-parse --show-toplevel)"

# Default: wowemu.dev domain, leaf CN *.actual.wowemu.dev
python3 scripts/gen-cert-bundle.py

# Custom portal domain (must be <= 10 bytes, same as 'battle.net')
python3 scripts/gen-cert-bundle.py --portal-domain bgs.corp

# Custom leaf CN (set to the IP or hostname the BGS server listens on)
python3 scripts/gen-cert-bundle.py --leaf-cn '127.0.0.1'

# Custom output directory
python3 scripts/gen-cert-bundle.py --output-dir /tmp/my-certs
```

The script is idempotent: the bundle-signing key is generated once and
reused across runs. Only the bundle JSON changes (the `Created` timestamp
is updated). This means `wow-patcher --rsa-file` stays valid across
regenerations.

**To regenerate the bundle-signing key** (requires re-patching the binary):

```bash
python3 scripts/gen-cert-bundle.py --force
```

## Step 2: Patch the WoW client

The script prints a ready-to-use `wow-patcher` invocation at the end:

```text
>> wow-patcher invocation:
  wow-patcher -l /path/to/WowClassic.exe \
    --rsa-file data/tls/bundle-signing-modulus.bin \
    --cert-bundle data/cert-bundle/bgs-key-fingerprint \
    --bgs-portal-domain wowemu.dev \
    --cert-bundle-url http://wowemu.dev/bnet/bundle \
    -v
```

Run it. The two relevant binary patches:

- **RSA modulus**: the bundle-signing key's modulus replaces the stock
  Blizzard modulus in `.rdata`. The client uses this modulus to verify
  the PKCS#1 v1.5 signature on the bundle JSON.
- **Cert bundle**: the bundle file replaces the embedded Blizzard bundle
  (for 1.14.x / 2.5.3 builds). The client reads `RootCAPublicKeys` to
  determine which CAs to trust for TLS.

## Step 3: Serve the cert bundle

The patched client fetches the bundle from the URL you specified
(`http://wowemu.dev/bnet/bundle`). Set up a simple HTTP server:

```bash
# Quick test with Python
cd data/cert-bundle
python3 -m http.server 80

# Or nginx, or any HTTP server. The file is:
#   data/cert-bundle/bgs-key-fingerprint
```

## Step 4: Install the CA in the OS trust store

The client needs the CA to verify the leaf cert. The script prints
platform-specific commands. Example:

```bash
# Fedora/RHEL
sudo install -m 0644 data/tls/ca.pem /usr/share/pki/ca-trust-source/anchors/wow-patcher-ca.crt && sudo update-ca-trust

# Debian/Ubuntu
sudo install -m 0644 data/tls/ca.pem /usr/local/share/ca-certificates/wow-patcher-ca.crt && sudo update-ca-certificates
```

## Step 5: DNS resolution

The patched client connects to `.actual.wowemu.dev` (or your custom
portal domain). Add to `/etc/hosts` for local testing:

```bash
echo "127.0.0.1 wowemu.dev" >> /etc/hosts
```

Or set up a real DNS entry pointing to your BGS server.

## Step 6: Start your BGS server

Your BGS server must:

1. Listen on port 443 with TLS.
2. Present `data/tls/leaf.pem` and `data/tls/leaf-key.pem`.
3. Accept connections from the patched client.

## File layout

```text
data/tls/
  ca.pem                       - TLS CA certificate
  ca-key.pem                   - TLS CA private key (NEVER share)
  leaf.pem                     - Leaf server cert (deploy on BGS server)
  leaf-key.pem                 - Leaf private key (deploy on BGS server)
  bundle-signing-key.pem       - Bundle signing private key (NEVER share)
  bundle-signing-pub.pem       - Bundle signing public key
  bundle-signing-modulus.bin   - LE 256-byte modulus (for --rsa-file)

data/cert-bundle/
  bgs-key-fingerprint          - Signed bundle (serve via HTTP)
```

## Regenerating the bundle

The script is idempotent: the bundle-signing key is generated once and
reused. To change the TLS CA (no re-patch needed):

```bash
python3 scripts/gen-cert-bundle.py
```

The bundle JSON is rebuilt with the fresh CA but the same signing key, so
`--rsa-file` stays valid.

To rotate the bundle-signing key (re-patch required):

```bash
python3 scripts/gen-cert-bundle.py --force
```

This generates a new signing keypair and modulus. Re-run `wow-patcher`
with the new modulus.
