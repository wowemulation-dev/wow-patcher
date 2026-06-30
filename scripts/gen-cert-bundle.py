#!/usr/bin/env python3
# Generate a full certificate chain and signed BGS cert bundle.
#
# The script generates everything needed to patch a WoW Classic client for
# use with a private BGS server:
#
#   1. A self-signed TLS root CA
#   2. A leaf server cert signed by that CA (for the BGS server)
#   3. A bundle-signing RSA-2048 keypair (idempotent -- generated once,
#      reused on subsequent runs so the wow-patcher modulus stays valid)
#   4. The signed cert bundle JSON (trusting the CA, signed by the
#      bundle-signing key)
#
# Outputs in data/tls/:
#
#   ca.pem                  - TLS CA certificate
#   ca-key.pem              - TLS CA private key (NEVER share)
#   leaf.pem                - Leaf server certificate (deploy on BGS server)
#   leaf-key.pem            - Leaf private key (deploy on BGS server)
#   bundle-signing-key.pem  - Bundle signing private key (NEVER share)
#   bundle-signing-pub.pem  - Bundle signing public key
#   bundle-signing-modulus.bin - Bundle signing modulus, LE 256 bytes
#                                (for wow-patcher --rsa-file)
#
# Output in data/cert-bundle/:
#
#   bgs-key-fingerprint     - The signed bundle (serve via HTTP, for
#                             wow-patcher --cert-bundle)
#
# Usage:
#
#   # Default: wowemu.dev domain, leaf CN *.actual.wowemu.dev
#   python3 scripts/gen-cert-bundle.py
#
#   # Custom portal domain
#   python3 scripts/gen-cert-bundle.py --portal-domain bgs.corp
#
#   # Custom leaf CN
#   python3 scripts/gen-cert-bundle.py --leaf-cn '127.0.0.1'
#
# The script prints a ready-to-use wow-patcher invocation at the end.
#
# Key architecture -- two separate keypairs:
#
#   TLS CA (ca.pem / ca-key.pem)
#     Signs the leaf server cert the BGS server presents.  Trusted by
#     the client via RootCAPublicKeys in the bundle.  NEVER injected
#     into the binary.
#
#   Bundle-signing key (bundle-signing-key.pem)
#     Signs the bundle JSON itself (PKCS#1 v1.5 / SHA-256).  Trusted
#     because ITS modulus is injected into the binary (--rsa-file).
#
# Bundle wire format:
#
#   [JSON][NGIS magic][256-byte signature, byte-reversed]
#
# The signature is RSA-2048 PKCS#1 v1.5 over SHA-256(json ||
# "Blizzard Certificate Bundle"), reversed for Blizzard's BigNumber
# convention.
#
# Requires: cryptography (pip install cryptography).

from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import os
import sys
import time
from pathlib import Path

import cryptography.x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

# Re-export for the ExtendedKeyUsage import below
ServerAuthOID = cryptography.x509.ExtendedKeyUsageOID.SERVER_AUTH
from cryptography.x509 import (  # noqa: E402 -- re-export above is deliberate
    CertificateBuilder,
    CertificateSigningRequestBuilder,
    DNSName,
    ExtendedKeyUsage,
    IPAddress,
    KeyUsage,
    Name,
    NameAttribute,
    BasicConstraints,
    SubjectAlternativeName,
    load_pem_x509_certificate,
    random_serial_number,
)
from cryptography.x509.oid import NameOID

SIGN_CONTEXT = b"Blizzard Certificate Bundle"

BUNDLE_FILE_NAME = "bgs-key-fingerprint"
MODULUS_FILE_NAME = "bundle-signing-modulus.bin"

DEFAULT_PORTAL_DOMAIN = "wowemu.dev"

# Cert-bundle hostname entries.  Arctium uses the wildcard "*.*" to cover
# every hostname the client may dial, regardless of domain or region.
# This matches the official Arctium bundle's approach (Uri: "*.*") and
# avoids maintaining a per-domain list that would need updating for every
# portal-domain change.
PINNED_HOSTNAMES = ["*.*"]

# Placeholder used in LEAF_DNS_SANS.  Non-brace delimiters to avoid
# linters normalising double braces.
_MARKER = "__PORTAL_DOMAIN__"

LEAF_DNS_SANS = [
    _MARKER,
    f"*.{_MARKER}",
    f"*.actual.{_MARKER}",
    f"us.actual.{_MARKER}",
    f"eu.actual.{_MARKER}",
    f"kr.actual.{_MARKER}",
    f"tw.actual.{_MARKER}",
    f"cn.actual.{_MARKER}",
    f"nydus.{_MARKER}",
    "localhost",
]

LEAF_IP_SANS = ["127.0.0.1", "::1"]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate CA, leaf cert, and signed BGS cert bundle"
    )
    parser.add_argument(
        "--portal-domain",
        default=DEFAULT_PORTAL_DOMAIN,
        help=f"BGS portal domain (default: {DEFAULT_PORTAL_DOMAIN})",
    )
    parser.add_argument(
        "--leaf-cn",
        default=None,
        help="Leaf certificate CN (default: *.actual.<portal-domain>)",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output dir (default: <repo>/data, via git root or script parent)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate bundle-signing key even if one exists",
    )
    return parser.parse_args(argv)


def resolve_output_dir(cli_dir: str | None) -> Path:
    if cli_dir:
        return Path(cli_dir).resolve()
    try:
        import subprocess

        git_root = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        return Path(git_root) / "data"
    except Exception:
        pass
    return Path(__file__).resolve().parent.parent / "data"


def generate_ca(output_dir: Path) -> tuple[Path, Path]:
    tls_dir = output_dir / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    ca_key_path = tls_dir / "ca-key.pem"
    ca_cert_path = tls_dir / "ca.pem"

    print(">> generating TLS CA key + self-signed cert", flush=True)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    subject = issuer = Name(
        [
            NameAttribute(NameOID.COUNTRY_NAME, "US"),
            NameAttribute(NameOID.ORGANIZATION_NAME, "WoWEmulation"),
            NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME,
                "WoWEmulation Certificate Authority",
            ),
            NameAttribute(
                NameOID.COMMON_NAME, "WoWEmulation Battle.net Aurora Root CA"
            ),
        ]
    )

    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2045, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_key_path.chmod(0o600)
    ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ca_cert_path.chmod(0o644)
    return ca_key_path, ca_cert_path


def generate_leaf_cert(
    ca_key_path: Path,
    ca_cert_path: Path,
    portal_domain: str,
    leaf_cn: str | None,
    output_dir: Path,
) -> tuple[Path, Path]:
    tls_dir = output_dir / "tls"
    ca_key_obj: RSAPrivateKey = serialization.load_pem_private_key(
        ca_key_path.read_bytes(),
        password=None,
    )
    ca_cert_obj = load_pem_x509_certificate(ca_cert_path.read_bytes())

    if leaf_cn is None:
        leaf_cn = f"*.actual.{portal_domain}"

    print(f">> generating leaf key + CSR (CN={leaf_cn})", flush=True)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    dns_sans = [DNSName(h.replace(_MARKER, portal_domain)) for h in LEAF_DNS_SANS]
    ip_sans = [IPAddress(ipaddress.ip_address(ip)) for ip in LEAF_IP_SANS]

    csr = (
        CertificateSigningRequestBuilder()
        .subject_name(Name([NameAttribute(NameOID.COMMON_NAME, leaf_cn)]))
        .add_extension(
            SubjectAlternativeName(dns_sans + ip_sans),
            critical=False,
        )
        .sign(leaf_key, hashes.SHA256())
    )

    leaf_cert = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert_obj.subject)
        .public_key(csr.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=825)
        )
        .add_extension(
            SubjectAlternativeName(dns_sans + ip_sans),
            critical=False,
        )
        .add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ExtendedKeyUsage([ServerAuthOID]), critical=True)
        .sign(ca_key_obj, hashes.SHA256())
    )

    leaf_key_path = tls_dir / "leaf-key.pem"
    leaf_cert_path = tls_dir / "leaf.pem"
    leaf_key_path.write_bytes(
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    leaf_key_path.chmod(0o600)
    leaf_cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    leaf_cert_path.chmod(0o644)
    return leaf_key_path, leaf_cert_path


def load_or_generate_signing_key(output_dir: Path, force: bool) -> RSAPrivateKey:
    tls_dir = output_dir / "tls"
    sign_key_path = tls_dir / "bundle-signing-key.pem"
    sign_pub_path = tls_dir / "bundle-signing-pub.pem"

    if sign_key_path.exists() and not force:
        key = serialization.load_pem_private_key(
            sign_key_path.read_bytes(), password=None
        )
        if not isinstance(key, RSAPrivateKey) or key.key_size != 2048:
            sys.exit(f"{sign_key_path}: expected RSA-2048 key")
        print(f">> reusing existing bundle-signing key ({sign_key_path})", flush=True)
        return key

    print(
        ">> regenerating bundle-signing keypair"
        if force
        else f">> generating new bundle-signing keypair ({sign_key_path})",
        flush=True,
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tls_dir.mkdir(parents=True, exist_ok=True)
    sign_key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    sign_key_path.chmod(0o600)
    sign_pub_path.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    sign_pub_path.chmod(0o644)
    return key


def ca_spki_sha256(ca_cert_path: Path) -> str:
    cert = load_pem_x509_certificate(ca_cert_path.read_bytes())
    spki = cert.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(spki).hexdigest().upper()


def build_bundle_json(ca_cert_path: Path) -> bytes:
    ca_pem_text = ca_cert_path.read_text()
    raw_data = ca_pem_text.replace("\n", "")
    ca_hash = ca_spki_sha256(ca_cert_path)

    bundle = {
        "Created": int(time.time()),
        "Certificates": [
            {"Uri": h, "ShaHashPublicKeyInfo": ca_hash} for h in PINNED_HOSTNAMES
        ],
        "PublicKeys": [
            {"Uri": h, "ShaHashPublicKeyInfo": ca_hash} for h in PINNED_HOSTNAMES
        ],
        "SigningCertificates": [{"RawData": raw_data}],
        "RootCAPublicKeys": [ca_hash],
    }
    return json.dumps(bundle, separators=(",", ":")).encode()


def sign_bundle(json_bytes: bytes, signing_key: RSAPrivateKey) -> bytes:
    sig_be = signing_key.sign(
        json_bytes + SIGN_CONTEXT,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if len(sig_be) != 256:
        sys.exit(f"signature length {len(sig_be)}; want 256")
    return json_bytes + b"NGIS" + sig_be[::-1]


def verify_bundle_roundtrip(blob: bytes, signing_key: RSAPrivateKey) -> None:
    ngis = blob.rfind(b"NGIS")
    if ngis < 0:
        sys.exit("verify: no NGIS magic")
    json_bytes = blob[:ngis]
    sig_le = blob[ngis + 4 :]
    if len(sig_le) != 256:
        sys.exit(f"verify: signature length {len(sig_le)}; want 256")
    signing_key.public_key().verify(
        sig_le[::-1],
        json_bytes + SIGN_CONTEXT,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    if "RootCAPublicKeys" not in json.loads(json_bytes):
        sys.exit("verify: bundle missing RootCAPublicKeys")


def write_modulus_file(signing_key: RSAPrivateKey, path: Path) -> None:
    modulus_be = signing_key.public_key().public_numbers().n.to_bytes(256, "big")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(modulus_be[::-1])
    path.chmod(0o644)


def print_patch_command(
    modulus_path: Path,
    bundle_path: Path,
    portal_domain: str,
) -> None:
    rsa = os.path.relpath(modulus_path, Path.cwd())
    bundle = os.path.relpath(bundle_path, Path.cwd())
    print(
        "\n>> wow-patcher invocation:\n"
        f"  wow-patcher -l /path/to/WowClassic.exe \\\n"
        f"    --rsa-file {rsa} \\\n"
        f"    --cert-bundle {bundle} \\\n"
        f"    --bgs-portal-domain {portal_domain} \\\n"
        f"    --cert-bundle-url http://{portal_domain}/bnet/bundle \\\n"
        f"    -v",
        flush=True,
    )


def print_install_ca_cmd(ca_cert_path: Path) -> None:
    ca_rel = os.path.relpath(ca_cert_path, Path.cwd())
    print(
        "\n>> Install CA in the OS trust store:"
        "\n  Fedora/RHEL: "
        f"sudo install -m 0644 {ca_rel} "
        "/usr/share/pki/ca-trust-source/anchors/wow-patcher-ca.crt "
        "&& sudo update-ca-trust"
        "\n  Debian/Ubuntu: "
        f"sudo install -m 0644 {ca_rel} "
        "/usr/local/share/ca-certificates/wow-patcher-ca.crt "
        "&& sudo update-ca-certificates",
        flush=True,
    )


def list_tls_files(tls_dir: Path) -> None:
    print("\n>> Files in TLS directory:", flush=True)
    for f in sorted(tls_dir.iterdir()):
        if f.is_file():
            print(f"  {f.name}  ({f.stat().st_size} bytes)", flush=True)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    out = resolve_output_dir(args.output_dir)
    tls_dir = out / "tls"
    cert_bundle_dir = out / "cert-bundle"
    cert_bundle_dir.mkdir(parents=True, exist_ok=True)

    print(f">> output directory: {out}", flush=True)
    print(f">> portal domain:    {args.portal_domain}", flush=True)
    print(flush=True)

    ca_key_path, ca_cert_path = generate_ca(out)
    leaf_key_path, leaf_cert_path = generate_leaf_cert(
        ca_key_path,
        ca_cert_path,
        args.portal_domain,
        args.leaf_cn,
        out,
    )
    signing_key = load_or_generate_signing_key(out, args.force)

    modulus_path = tls_dir / MODULUS_FILE_NAME
    write_modulus_file(signing_key, modulus_path)

    ca_hash = ca_spki_sha256(ca_cert_path)
    print(f">> CA SPKI SHA-256 = {ca_hash}", flush=True)
    print(f">> CA certificate:  {ca_cert_path}", flush=True)
    print(f">> leaf:            {leaf_cert_path}", flush=True)
    print(f">> leaf key:        {leaf_key_path}", flush=True)

    json_bytes = build_bundle_json(ca_cert_path)
    blob = sign_bundle(json_bytes, signing_key)
    verify_bundle_roundtrip(blob, signing_key)

    bundle_path = cert_bundle_dir / BUNDLE_FILE_NAME
    bundle_path.write_bytes(blob)
    bundle_path.chmod(0o644)

    print(
        f">> wrote signed bundle: {bundle_path}  ({len(blob)} bytes)\n"
        f"   JSON length:        {len(json_bytes)}\n"
        f"   verified:           OK (PKCS#1 v1.5 / SHA-256)\n"
        f">> wrote LE modulus:   {modulus_path}  (256 bytes)",
        flush=True,
    )

    print_patch_command(modulus_path, bundle_path, args.portal_domain)
    print_install_ca_cmd(ca_cert_path)
    list_tls_files(tls_dir)


if __name__ == "__main__":
    main()
