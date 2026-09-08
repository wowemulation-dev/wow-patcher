# Retail runtime patching

`launch` reads the executable's file version and selects its runtime strategy.
It leaves the executable on disk unchanged. Strategy selection and availability
of a build-specific patch recipe are separate checks:

| File version | Selected strategy |
| --- | --- |
| 12.x and later major versions | New retail strategy; verified recipes for **12.0.7.68887** and **12.1.0.69587** |
| 1.13.x, 1.14.x | Existing runtime strategy |
| 2.5.0–2.5.4, 3.4.0–3.4.4, 4.4.0–4.4.2 | Existing runtime strategy |
| 9.x, 10.x | Existing runtime strategy |
| Other versions or unreadable version metadata | Rejected before launch |

There is no fallback from an unverified retail build to the older strategy.
For example, 12.0.0.65655 and 13.x select the retail strategy but stop before
starting a process because their recipes are not verified. Each recipe uses its own recorded addresses and startup sequence.
Executable and loader SHA-256 hashes must match the selected recipe before
any process is created; modified or mismatched inputs are rejected. The client filename does not
select a strategy; Classic's version text takes precedence over fixed engine
version fields, and build numbers retain all 32 bits.

The older ranges retain their existing patch implementation and its validation
limits. They are not new claims of successful login for every build. In
particular, `--legacy-cert-mode` is rejected on 1.13.x. Retail-only options are
rejected on older versions. Runtime `--dry-run` currently works only for the
retail strategy; requesting it for an older version stops without launching.
The default static-patching command remains unchanged.

## Usage

The client needs its matching `Wow_loader.dll` and game data. Configure the
desired portal in `WTF/Config.wtf` before launching. Supply the server's public
certificate in PEM format; private keys remain with the server.

```powershell
wow-patcher launch -l C:\Games\WoW\Wow.exe `
  --server-cert C:\certificates\server.pem --portal-suffix "" --dry-run

wow-patcher launch -l C:\Games\WoW\Wow.exe `
  --server-cert C:\certificates\server.pem --portal-suffix "" -v
```

An explicit empty `--portal-suffix` lets the client use a full hostname from
`SET portal "host:port"` verbatim. Omit the option to retain the original
suffix. A supplied suffix must fit in 18 ASCII bytes plus its terminator.
The certificate path must also be ASCII because the client consumes a narrow
file path. The certificate file must remain available while the client runs.

`--ed25519-file` and `--ed25519-hex` select a custom 32-byte public key.
Otherwise the existing default key is used. The server must sign with the
matching private key. This retail recipe does not replace an RSA modulus or
inject a signed JSON certificate bundle.

`--config NAME` selects an existing file under `WTF` without editing it.
The game may update that file itself. `--timeout` bounds each startup phase
(3–300 seconds, default 30); each temporary reader thread has a five-second
limit. Failed preparation terminates only the process created by this command.

For streamed installations, `--version-url URL` replaces both embedded NGDP
templates. Supply an endpoint pinned to the selected client build and retain the `%s`
placeholders expected by that service. No endpoint is selected automatically.
Fetching another build's data can cause a StartupFiles schema error even when
all runtime patches were installed. This command does not download a client or
make mismatched game data compatible.

A dry run checks the version, executable/loader hashes, image layout, input files, string lengths and
original data bytes. It starts no process and writes no files. Decrypted code
signatures can only be checked during a live launch.

## Runtime sequence

1. Create a suspended client, resolve its relocated image base, and verify and
   write the Ed25519 key and any requested portal/NGDP replacements. For 69587,
   verify 64 original entry bytes and temporarily write `EB FE` at RVA `0x1D9E10`.
2. Resume until the loader is present and the entry page is protected. Locate
   exactly seven threads whose start addresses lie inside that loader, stop
   them, and suspend the remaining client threads.
3. Prepare code pages with the selected build's procedure:
   - **68887:** execute a temporary reader from empty storage after `.text`,
     omitting 100 fixed pages, then restore the original zero bytes.
   - **69587:** restore and verify the 64 entry bytes, save 51 existing bytes at
     `.rdata` RVA `0x3785000`, make that page executable, and run one reader over
     `[0x1000, 0x3784B4C)`. Restore and verify the saved bytes and page protection.
     This storage contains live data and must not be treated as an empty cave.
4. Resume and wait for plaintext signatures at all five code sites. Suspend,
   revalidate, and install the certificate-path hook and four code replacements.
5. Verify every write and the earlier data replacements, then resume the client.

The 69587 sites are resolver `0x35C1AB0`, path branch `0x35B7F87`, zero-return
helper `0x27F0380`, and result writes `0x28003D6` and `0x27FDAC1`. The latter
seven-byte write replaces a call and the first two bytes of `movzx r14d,al`;
remaining bytes `B6 F0` decode as `mov dh,0xF0`. This measured boundary is
preserved, without claiming that it replaces whole original instructions or
proves the surrounding certificate semantics.

The hook returns the supplied PEM filename for file ID **7725530**. Every other
ID uses the original resolver through a trampoline. The copied prologue is 13
bytes of complete instructions without relative addressing. Memory writes
restore the prior page protection and flush the instruction cache.

These operations are separate recipes for the two recorded builds. Worker removal and the
individual certificate-result changes have not each been isolated in full
authentication tests. They should not be generalized to other builds merely
because an address is readable.

## Validation scope

Automated tests cover version-range boundaries, future retail routing,
file-version precedence, option rejection, string bounds, path normalization,
signature mismatch, binary identity rejection, reader ranges, executed certificate-handler routing,
memory protection restoration and failed-launch process cleanup.

Live validation checks successful startup and persistent in-memory patches.
It does not establish successful server authentication, character selection or
world entry. Those require a compatible server and protocol implementation.

On 2026-09-08, a Windows x64 test through the version-selected `launch` command
remained responsive at **144.1 seconds**.
All five code writes and the certificate handler were readable and intact;
the 51 temporary bytes were restored. The executable, loader and original
configuration hashes were unchanged. The test used a separate configuration
and an explicit build-pinned NGDP override, then terminated its test process.

| Tested input | SHA-256 |
| --- | --- |
| `Wow.exe` | `F8F4FDEE3C6FA291FC77F661B0C3F47B633332894223A4997AC167441FBF95FA` |
| `Wow_loader.dll` | `D739A6C4B55CBE2960123120358DA82D7AB561DD017D9598C1A262AB6FF567C7` |

Build 69587 remained responsive at **161.1 seconds**, with all five code patches
intact, using a separate configuration without an NGDP override. The entry bytes were independently read back after launch;
the launcher verified restoration of borrowed data bytes and protection.
A copied executable with an invalid loader was rejected before process creation.
A fresh 68887 regression launch remained responsive at **108.4 seconds** with
all five code patches intact after the original split sweep. Both test processes
were then stopped; executable, loader and original configuration hashes were
unchanged for both builds.

| Additional tested input | SHA-256 |
| --- | --- |
| 69587 `Wow.exe` | `B773093EDF986C8085FDC990649BFCB33DF5F692C244BE7FDDF46C49B413923E` |
| 69587 `wow_loader.dll` | `BC06969951614D168081F7EBEC9513BBCEFEFFDC483BF0AFCD65915DBB29FFC4` |
