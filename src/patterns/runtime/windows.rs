//! Windows-specific Arctium patterns. Mirrors `Patterns/Windows.cs`.
//!
//! Patterns here use `-1` as a wildcard. They were derived against
//! recent retail builds of `Wow.exe`; older builds (Classic 1.13.x,
//! 2.5.x, 3.4.x, 4.4.x) may need build-specific variants. Per-build
//! coverage is tracked alongside the smoke-test framework.

use crate::binary::Pattern;

const WC: i16 = -1; // wildcard

/// Sentinel used to detect the C runtime initializer that must
/// have completed before patches are applied. Matches the
/// `mov dword ptr [rip+disp32], 1` then `lea` sequence that follows
/// Arxan's TLS callback.
#[must_use]
pub fn init_pattern() -> Pattern {
    vec![
        0xC7, 0x05, WC, WC, WC, WC, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8D, WC, WC, WC, WC, WC, 0x48,
        0x8D, WC, WC, WC, WC, WC, 0xE8, WC, WC, WC, WC, 0x85,
    ]
}

/// Anti-tamper / integrity check site. Replaced with `ret`-style
/// stub so the function returns success without doing the check.
#[must_use]
pub fn integrity_pattern() -> Pattern {
    vec![
        0x44, 0x89, WC, 0x24, WC, 0x44, 0x89, WC, 0x24, WC, 0x89, WC, 0x24, WC, 0x48, 0x89, WC,
        0x24, WC, 0x53, 0x56, 0x57,
    ]
}

/// Alternative integrity-check encoding present in some builds.
#[must_use]
pub fn integrity_pattern_alt() -> Pattern {
    vec![
        0x44, 0x89, WC, 0x24, WC, 0x44, 0x89, WC, 0x24, WC, 0x89, WC, 0x24, WC, 0x48, 0x89, WC,
        0x24, WC, 0x53, 0x57,
    ]
}

/// Detects the section-remap check (Arxan integrity guards page
/// permissions; this pattern is at the JZ that decides whether to
/// abort).
#[must_use]
pub fn remap_pattern() -> Pattern {
    vec![0x48, WC, WC, 0x1E, 0x0F, 0x83]
}

/// Code site that branches on success of the cert-bundle parse.
/// Patched so the success branch is always taken.
#[must_use]
pub fn cert_bundle_branch_pattern() -> Pattern {
    vec![0x75, 0x06, 0x48, WC, WC, 0x60, 0x5F, 0xC3]
}

/// Code site that compares the certificate Common Name. Patched
/// so the comparison is treated as a match.
#[must_use]
pub fn cert_common_name_pattern() -> Pattern {
    vec![0x80, WC, 0x2A, 0x75, WC, 0x32, 0xC0, 0x48]
}

/// Cert-chain validation -- the developer-mode bypass. Patched so
/// validation is unconditionally accepted.
#[must_use]
pub fn cert_chain_pattern() -> Pattern {
    vec![
        0x32, 0xDB, 0xEB, 0x02, 0xB3, 0x01, 0x48, 0x83, WC, WC, 0x00, 0x00, 0x00, 0x00,
    ]
}

/// Auth-seed function entry. The string `"WoW\0"` followed by a
/// `call` instruction is the canonical anchor.
///
/// Used by the static-auth-seed feature (planned, not yet ported).
#[must_use]
pub fn auth_seed_pattern() -> Pattern {
    vec![0x57, 0x6F, 0x57, 0x00, 0xE8, WC, WC, WC, WC, 0x48, 0x8D]
}

/// File-by-id loader hook anchor (custom file/mod loader).
/// Out of scope for the cert+portal subset but kept for completeness.
#[must_use]
pub fn load_by_file_id_pattern() -> Pattern {
    vec![
        0x41, WC, WC, 0x01, 0x0F, 0x84, WC, 0x00, 0x00, 0x00, 0x48, 0x8B, WC, WC, WC, WC, WC, 0x8B,
    ]
}

#[must_use]
pub fn load_by_file_id_alt_pattern() -> Pattern {
    vec![
        0x01, 0x0F, 0x84, WC, WC, WC, WC, 0x48, 0x8B, WC, WC, WC, WC, WC, 0x8B, WC, 0xE8,
    ]
}

#[must_use]
pub fn load_by_file_path_pattern() -> Pattern {
    vec![
        0x01, 0x0F, 0x84, WC, WC, WC, WC, 0x48, 0x8B, WC, WC, WC, WC, WC, 0x44, 0x89, WC, WC, WC,
        0x48, 0x85, 0xC9,
    ]
}

#[must_use]
pub fn load_by_file_path_alt_pattern() -> Pattern {
    vec![
        0x01, 0x0F, 0x84, WC, WC, WC, WC, 0x48, 0x8B, WC, WC, WC, WC, WC, 0x44, 0x89, WC, WC, WC,
        0x00, 0x00, 0x00, 0x48, 0x85, 0xC9,
    ]
}

#[must_use]
pub fn custom_file_id_hook_pattern() -> Pattern {
    vec![
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, WC, 0x48, WC, WC,
        0x48, WC, WC, WC, WC, WC, WC, 0xE8, WC, WC, WC, WC, 0x48, WC, WC, WC, WC, WC, WC, 0x48, WC,
        WC, 0x74, WC, 0x48, WC, 0xCD,
    ]
}

/// Registry path used by the `-launcherlogin` flow (Path B).
/// `Software\Blizzard Entertainment\Battle.net\Launch Options\`
#[must_use]
pub fn launcher_login_registry_path_pattern() -> Pattern {
    super::pattern_from_str("Software\\Blizzard Entertainment\\Battle.net\\Launch Options\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_pattern_has_expected_length() {
        assert_eq!(init_pattern().len(), super::super::INIT_PATTERN_LEN);
    }

    #[test]
    fn integrity_patterns_are_distinct() {
        // The alternate encoding is one byte shorter (drops one of
        // the `0x56` bytes), so a sanity check on lengths verifies
        // we copied them correctly.
        let p = integrity_pattern();
        let alt = integrity_pattern_alt();
        assert_ne!(p, alt);
        assert!(p.len() > alt.len());
    }

    #[test]
    fn cert_bundle_branch_is_eight_bytes() {
        assert_eq!(cert_bundle_branch_pattern().len(), 8);
    }

    #[test]
    fn cert_chain_pattern_starts_with_xor() {
        // 0x32 0xDB = `xor bl, bl` -- the canonical anchor for the
        // dev-mode bypass site.
        let p = cert_chain_pattern();
        assert_eq!(p[0], 0x32);
        assert_eq!(p[1], 0xDB);
    }

    #[test]
    fn auth_seed_starts_with_wow_string() {
        let p = auth_seed_pattern();
        assert_eq!(&p[0..4], &[0x57, 0x6F, 0x57, 0x00]); // "WoW\0"
    }

    #[test]
    fn launcher_login_registry_path_is_pure_string() {
        let p = launcher_login_registry_path_pattern();
        assert!(p.iter().all(|&b| (0..=255).contains(&b)));
        // Sanity: contains the literal "Battle.net".
        let bytes: Vec<u8> = p.iter().map(|&b| b as u8).collect();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("Battle.net"));
    }
}
