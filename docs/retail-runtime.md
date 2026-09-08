# Retail runtime patching

`launch-retail` is an opt-in Windows x64 command for **12.0.7.68887**.
It leaves the executable on disk unchanged. Other retail builds, including
12.0.0.65655, are rejected until their layouts and startup sequences are tested.
The existing static patcher and `launch` command keep their existing behavior.

## Usage

The client needs its matching `Wow_loader.dll` and game data. Configure the
desired portal in `WTF/Config.wtf` before launching. Supply the server's public
certificate in PEM format; private keys remain with the server.

```powershell
wow-patcher launch-retail -l C:\Games\WoW\Wow.exe `
  --server-cert C:\certificates\server.pem --portal-suffix "" --dry-run

wow-patcher launch-retail -l C:\Games\WoW\Wow.exe `
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
templates. Supply an endpoint pinned to build 68887 and retain the `%s`
placeholders expected by that service. No endpoint is selected automatically.
Fetching another build's data can cause a StartupFiles schema error even when
all runtime patches were installed. This command does not download a client or
make mismatched game data compatible.

A dry run checks the version, image layout, input files, string lengths and
original data bytes. It starts no process and writes no files. Decrypted code
signatures can only be checked during a live launch.

## Runtime sequence

1. Create a suspended client, resolve its relocated image base, and verify and
   write the Ed25519 key and any requested portal/NGDP replacements.
2. Resume until the loader is present and the entry page is protected. Locate
   exactly seven threads whose start addresses lie inside that loader, stop
   them, and suspend the remaining client threads.
3. Execute a temporary reader from the empty space immediately after `.text`.
   Read the validated ranges, omitting 100 fixed pages, then restore and verify
   the original temporary bytes. Executing the reader from a private allocation
   does not expose the required pages in the tested build.
4. Resume and wait for plaintext signatures at all five code sites. Suspend,
   revalidate, and install a certificate-path hook, its conditional gate change,
   a zero-return certificate helper, and two certificate-result replacements.
5. Verify every write and the earlier data replacements, then resume the client.

The hook returns the supplied PEM filename for file ID **7725530**. Every other
ID uses the original resolver through a trampoline. The copied prologue is 13
bytes of complete instructions without relative addressing. Memory writes
restore the prior page protection and flush the instruction cache.

These operations are a tested recipe for one build. Worker removal and the
individual certificate-result changes have not each been isolated in full
authentication tests. They should not be generalized to other builds merely
because an address is readable.

## Validation scope

Automated tests cover option rejection, string bounds, path normalization,
signature mismatch, reader ranges, executed certificate-handler routing,
memory protection restoration and failed-launch process cleanup.

Live validation checks successful startup and persistent in-memory patches.
It does not establish successful server authentication, character selection or
world entry. Those require a compatible server and protocol implementation.

On 2026-09-08, a Windows x64 test remained responsive at **173.6 seconds**.
All five code writes and the certificate handler were readable and intact;
the 51 temporary bytes were restored. The executable, loader and original
configuration hashes were unchanged. The test used a separate configuration
and an explicit build-pinned NGDP override, then terminated its test process.

| Tested input | SHA-256 |
| --- | --- |
| `Wow.exe` | `F8F4FDEE3C6FA291FC77F661B0C3F47B633332894223A4997AC167441FBF95FA` |
| `Wow_loader.dll` | `D739A6C4B55CBE2960123120358DA82D7AB561DD017D9598C1A262AB6FF567C7` |
