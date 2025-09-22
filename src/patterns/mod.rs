#[cfg(test)]
use crate::binary::PatternExt;
use crate::binary::{Pattern, string_to_pattern};
use std::sync::OnceLock;

pub static PORTAL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CONNECT_TO_MODULUS_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CRYPTO_ED_PUBLIC_KEY_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static VERSION_URL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CDNS_URL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static AUTH_SEED_PATTERN: OnceLock<Pattern> = OnceLock::new();

pub fn portal_pattern() -> &'static Pattern {
    PORTAL_PATTERN.get_or_init(|| string_to_pattern(".actual.battle.net"))
}

pub fn connect_to_modulus_pattern() -> &'static Pattern {
    CONNECT_TO_MODULUS_PATTERN.get_or_init(|| vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5])
}

pub fn crypto_ed_public_key_pattern() -> &'static Pattern {
    CRYPTO_ED_PUBLIC_KEY_PATTERN
        .get_or_init(|| vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD])
}

pub fn version_url_pattern() -> &'static Pattern {
    VERSION_URL_PATTERN
        .get_or_init(|| string_to_pattern("http://%s.patch.battle.net:1119/%s/versions"))
}

pub fn cdns_url_pattern() -> &'static Pattern {
    CDNS_URL_PATTERN.get_or_init(|| string_to_pattern("http://%s.patch.battle.net:1119/%s/cdns"))
}

pub fn auth_seed_pattern() -> &'static Pattern {
    AUTH_SEED_PATTERN.get_or_init(|| {
        let mut pattern = vec![0x57, 0x6F, 0x57, 0x00, 0xE8];
        pattern.extend_from_slice(&[-1; 4]);
        pattern.extend_from_slice(&[0x48, 0x8D]);
        pattern
    })
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
        assert_ne!(*version_url_pattern(), *cdns_url_pattern());
        assert_ne!(*version_url_pattern(), *portal_pattern());
        assert_ne!(*cdns_url_pattern(), *portal_pattern());
    }

    #[test]
    fn test_auth_seed_pattern() {
        let pattern = auth_seed_pattern();
        assert_eq!(pattern.len(), 11);

        assert_eq!(pattern[0], 0x57);
        assert_eq!(pattern[1], 0x6F);
        assert_eq!(pattern[2], 0x57);
        assert_eq!(pattern[3], 0x00);
        assert_eq!(pattern[4], 0xE8);

        for i in 5..9 {
            assert_eq!(pattern[i], -1);
        }

        assert_eq!(pattern[9], 0x48);
        assert_eq!(pattern[10], 0x8D);
    }
}
