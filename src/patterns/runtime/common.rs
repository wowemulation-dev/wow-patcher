//! Cross-platform Arctium patterns. Mirrors `Patterns/Common.cs`.

use crate::binary::Pattern;

/// First 8 bytes of the stock ConnectTo / ChangeProtocol RSA
/// modulus. Used to locate the modulus in memory for replacement
/// with the server's own modulus.
///
/// Stock value is the well-known Battle.net `0x91, 0xD5, 0x9B, 0xB7,
/// 0xD4, 0xE1, 0x83, 0xA5...` modulus.
#[must_use]
pub fn connect_to_modulus_pattern() -> Pattern {
    vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5]
}

/// First 8 bytes of the stock signature-verification RSA modulus.
/// Distinct from the ConnectTo modulus; both must be replaced.
#[must_use]
pub fn signature_modulus_pattern() -> Pattern {
    vec![0x35, 0xFF, 0x17, 0xE7, 0x33, 0xC4, 0xD3, 0xD4]
}

/// First 8 bytes of the stock crypto RSA modulus used by the warden /
/// crypto subsystem.
#[must_use]
pub fn crypto_rsa_modulus_pattern() -> Pattern {
    vec![0x71, 0xFD, 0xFA, 0x60, 0x14, 0x0D, 0xF2, 0x05]
}

/// First 8 bytes of the stock Ed25519 public key. Newer clients use
/// this in addition to the RSA moduli; classic clients may skip it
/// (see `crypto_ed_public_key_used()`).
#[must_use]
pub fn crypto_ed_public_key_pattern() -> Pattern {
    vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD]
}

/// Header of the embedded JSON certificate bundle in `.rdata`.
/// The bundle is a `{"Created": "...", "Certs": [...]}` JSON document
/// containing the trusted root CAs the client uses to validate server
/// certificates. The runtime mode replaces it with a custom bundle
/// that includes the local CA.
///
/// Mirrors `Patterns/Common.cs` `CertBundle = "{\"Created\":".ToPattern()`.
#[must_use]
pub fn cert_bundle_header_pattern() -> Pattern {
    super::pattern_from_str("{\"Created\":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_to_modulus_is_eight_bytes_and_matches_known_prefix() {
        let p = connect_to_modulus_pattern();
        assert_eq!(p.len(), 8);
        assert_eq!(p[0], 0x91);
        assert_eq!(p[7], 0xA5);
    }

    #[test]
    fn signature_modulus_distinct_from_connect_to() {
        assert_ne!(connect_to_modulus_pattern(), signature_modulus_pattern());
    }

    #[test]
    fn crypto_rsa_modulus_known_prefix() {
        assert_eq!(
            crypto_rsa_modulus_pattern(),
            vec![0x71, 0xFD, 0xFA, 0x60, 0x14, 0x0D, 0xF2, 0x05]
        );
    }

    #[test]
    fn crypto_ed_public_key_known_prefix() {
        assert_eq!(
            crypto_ed_public_key_pattern(),
            vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD]
        );
    }

    #[test]
    fn cert_bundle_header_is_pure_string() {
        let p = cert_bundle_header_pattern();
        let expected: Vec<i16> = "{\"Created\":".bytes().map(i16::from).collect();
        assert_eq!(p, expected);
    }
}
