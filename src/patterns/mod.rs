#[cfg(test)]
use crate::binary::PatternExt;
use crate::binary::{string_to_pattern, Pattern};
use std::sync::OnceLock;

pub static PORTAL_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CONNECT_TO_MODULUS_PATTERN: OnceLock<Pattern> = OnceLock::new();
pub static CRYPTO_ED_PUBLIC_KEY_PATTERN: OnceLock<Pattern> = OnceLock::new();

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
        assert_ne!(*connect_to_modulus_pattern(), *crypto_ed_public_key_pattern());
    }

    #[test]
    fn test_portal_pattern_empty() {
        let empty = portal_pattern().empty();
        assert_eq!(empty.len(), portal_pattern().len());

        for &b in &empty {
            assert_eq!(b, 0);
        }
    }
}
