#[cfg(test)]
use crate::binary::PatternExt;
use crate::binary::{Pattern, string_to_pattern};
use std::sync::OnceLock;

pub static PORTAL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CONNECT_TO_MODULUS_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static SIGNATURE_MODULUS_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CRYPTO_RSA_MODULUS_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CRYPTO_ED_PUBLIC_KEY_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static VERSION_URL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static VERSION_URL_V2_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static VERSION_URL_V3_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CDNS_URL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CERT_BUNDLE_PATTERN: OnceLock<Pattern> = OnceLock::new();

pub fn portal_pattern() -> &'static Pattern {
    PORTAL_PATTERN.get_or_init(|| string_to_pattern(".actual.battle.net"))
}

pub fn connect_to_modulus_pattern() -> &'static Pattern {
    CONNECT_TO_MODULUS_PATTERN.get_or_init(|| vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5])
}

pub fn signature_modulus_pattern() -> &'static Pattern {
    SIGNATURE_MODULUS_PATTERN.get_or_init(|| vec![0x35, 0xFF, 0x17, 0xE7, 0x33, 0xC4, 0xD3, 0xD4])
}

pub fn crypto_rsa_modulus_pattern() -> &'static Pattern {
    CRYPTO_RSA_MODULUS_PATTERN.get_or_init(|| vec![0x71, 0xFD, 0xFA, 0x60, 0x14, 0x0D, 0xF2, 0x05])
}

pub fn crypto_ed_public_key_pattern() -> &'static Pattern {
    CRYPTO_ED_PUBLIC_KEY_PATTERN
        .get_or_init(|| vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD])
}

pub fn version_url_pattern() -> &'static Pattern {
    VERSION_URL_PATTERN
        .get_or_init(|| string_to_pattern("http://%s.patch.battle.net:1119/%s/versions"))
}

pub fn version_url_v2_pattern() -> &'static Pattern {
    VERSION_URL_V2_PATTERN
        .get_or_init(|| string_to_pattern("https://%s.version.battle.net/v2/products/%s/versions"))
}

/// Unified Battle.net API URL pattern used in WoW Classic 1.15.8+
/// Format: https://{region}.version.battle.net/v2/products/{product}/{endpoint}
/// This single URL handles both versions and cdns requests (endpoint = "versions" or "cdns")
/// Replaces the separate version_url and cdns_url patterns in newer clients
pub fn version_url_v3_pattern() -> &'static Pattern {
    VERSION_URL_V3_PATTERN
        .get_or_init(|| string_to_pattern("https://%s.version.battle.net/v2/products/%s/%s"))
}

pub fn cdns_url_pattern() -> &'static Pattern {
    CDNS_URL_PATTERN.get_or_init(|| string_to_pattern("http://%s.patch.battle.net:1119/%s/cdns"))
}

pub fn cert_bundle_pattern() -> &'static Pattern {
    CERT_BUNDLE_PATTERN.get_or_init(|| string_to_pattern("{\"Created\":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_portal_pattern() {
        let expected = string_to_pattern(".actual.battle.net");
        assert_eq!(*portal_pattern(), expected);

        let expected_string = ".actual.battle.net";
        assert_eq!(portal_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(portal_pattern()[i], ch as i16);
        }
    }

    #[test]
    fn test_connect_to_modulus_pattern() {
        let expected = vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];
        assert_eq!(*connect_to_modulus_pattern(), expected);
        assert_eq!(connect_to_modulus_pattern().len(), 8);

        for &val in connect_to_modulus_pattern().iter() {
            assert!(val >= 0 && val <= 255);
        }
    }

    #[test]
    fn test_crypto_ed_public_key_pattern() {
        let expected = vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD];
        assert_eq!(*crypto_ed_public_key_pattern(), expected);
        assert_eq!(crypto_ed_public_key_pattern().len(), 8);

        for &val in crypto_ed_public_key_pattern().iter() {
            assert!(val >= 0 && val <= 255);
        }
    }

    #[test]
    fn test_patterns_are_distinct() {
        assert_ne!(*portal_pattern(), *connect_to_modulus_pattern());
        assert_ne!(*portal_pattern(), *crypto_ed_public_key_pattern());
        assert_ne!(
            *connect_to_modulus_pattern(),
            *crypto_ed_public_key_pattern()
        );
    }

    #[test]
    fn test_portal_pattern_empty() {
        let empty = portal_pattern().empty();
        assert_eq!(empty.len(), portal_pattern().len());

        for &b in &empty {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_version_url_pattern() {
        let expected = string_to_pattern("http://%s.patch.battle.net:1119/%s/versions");
        assert_eq!(*version_url_pattern(), expected);

        let expected_string = "http://%s.patch.battle.net:1119/%s/versions";
        assert_eq!(version_url_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(version_url_pattern()[i], ch as i16);
        }
    }

    #[test]
    fn test_version_url_v2_pattern() {
        let expected = string_to_pattern("https://%s.version.battle.net/v2/products/%s/versions");
        assert_eq!(*version_url_v2_pattern(), expected);

        let expected_string = "https://%s.version.battle.net/v2/products/%s/versions";
        assert_eq!(version_url_v2_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(version_url_v2_pattern()[i], ch as i16);
        }
    }

    #[test]
    fn test_version_url_v3_pattern() {
        let expected = string_to_pattern("https://%s.version.battle.net/v2/products/%s/%s");
        assert_eq!(*version_url_v3_pattern(), expected);

        let expected_string = "https://%s.version.battle.net/v2/products/%s/%s";
        assert_eq!(version_url_v3_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(version_url_v3_pattern()[i], ch as i16);
        }
    }

    #[test]
    fn test_cdns_url_pattern() {
        let expected = string_to_pattern("http://%s.patch.battle.net:1119/%s/cdns");
        assert_eq!(*cdns_url_pattern(), expected);

        let expected_string = "http://%s.patch.battle.net:1119/%s/cdns";
        assert_eq!(cdns_url_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(cdns_url_pattern()[i], ch as i16);
        }
    }

    #[test]
    fn test_url_patterns_are_distinct() {
        // All version URL patterns should be distinct from each other
        assert_ne!(*version_url_pattern(), *version_url_v2_pattern());
        assert_ne!(*version_url_pattern(), *version_url_v3_pattern());
        assert_ne!(*version_url_v2_pattern(), *version_url_v3_pattern());

        // Version patterns should be distinct from other URL patterns
        assert_ne!(*version_url_pattern(), *cdns_url_pattern());
        assert_ne!(*version_url_pattern(), *portal_pattern());
        assert_ne!(*version_url_v2_pattern(), *cdns_url_pattern());
        assert_ne!(*version_url_v2_pattern(), *portal_pattern());
        assert_ne!(*version_url_v3_pattern(), *cdns_url_pattern());
        assert_ne!(*version_url_v3_pattern(), *portal_pattern());
        assert_ne!(*cdns_url_pattern(), *portal_pattern());
    }

    #[test]
    fn test_signature_modulus_pattern() {
        let expected = vec![0x35, 0xFF, 0x17, 0xE7, 0x33, 0xC4, 0xD3, 0xD4];
        assert_eq!(*signature_modulus_pattern(), expected);
        assert_eq!(signature_modulus_pattern().len(), 8);

        for &val in signature_modulus_pattern().iter() {
            assert!(val >= 0 && val <= 255);
        }
    }

    #[test]
    fn test_crypto_rsa_modulus_pattern() {
        let expected = vec![0x71, 0xFD, 0xFA, 0x60, 0x14, 0x0D, 0xF2, 0x05];
        assert_eq!(*crypto_rsa_modulus_pattern(), expected);
        assert_eq!(crypto_rsa_modulus_pattern().len(), 8);

        for &val in crypto_rsa_modulus_pattern().iter() {
            assert!(val >= 0 && val <= 255);
        }
    }

    #[test]
    fn test_all_rsa_patterns_are_distinct() {
        // Ensure all three RSA patterns are unique
        assert_ne!(*connect_to_modulus_pattern(), *signature_modulus_pattern());
        assert_ne!(*connect_to_modulus_pattern(), *crypto_rsa_modulus_pattern());
        assert_ne!(*signature_modulus_pattern(), *crypto_rsa_modulus_pattern());
    }

    #[test]
    fn test_cert_bundle_pattern() {
        let expected = string_to_pattern("{\"Created\":");
        assert_eq!(*cert_bundle_pattern(), expected);

        let expected_string = "{\"Created\":";
        assert_eq!(cert_bundle_pattern().len(), expected_string.len());

        for (i, ch) in expected_string.chars().enumerate() {
            assert_eq!(cert_bundle_pattern()[i], ch as i16);
        }
    }
}
