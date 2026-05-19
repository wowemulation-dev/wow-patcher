//! BGS-portal-domain configuration for the `.actual.battle.net` rewrite.
//!
//! The 1.13.x-4.4.x WoW Classic clients construct the BGS Aurora-RPC
//! portal hostname by concatenating a region prefix with the literal
//! `.actual.battle.net` at runtime. We rewrite the suffix to substitute
//! a domain we control, defaulting to `wowemu.dev` (same length as
//! `battle.net` -- 10 bytes -- so no NUL padding is required).
//!
//! For local testing, callers can override via `--bgs-portal-domain`
//! (CLI) or the `WOW_BGS_PORTAL_DOMAIN` env var to use any other
//! domain such as `bgs.corp`. Domains shorter than `battle.net` work
//! via NUL padding; domains longer than `battle.net` are rejected
//! because they would exceed the pattern slot.
//!
//! Scope: this module governs ONLY the BGS portal suffix. The
//! cert-bundle download URL is handled by `cert_bundle::CertBundleConfig`
//! (with `--cert-bundle-url`), which targets the specific 59-byte URL
//! literal rather than the host substring. The 5 cosmetic
//! `nydus.battle.net` URLs (driver-unsupported, trial-restriction,
//! gametime, checkout, checkoutnav) are intentionally NOT rewritten by
//! this module -- they belong to a future `nydus-cosmetic` group.

use crate::errors::{ErrorCategory, WowPatcherError};

/// Maximum replacement length, equal to `b"battle.net".len()`.
///
/// The patcher's pattern-replacement infrastructure (`Pattern::padded`)
/// requires the replacement to fit within the matched pattern's byte
/// span. Since both rewrite sites embed `battle.net` as the trailing
/// component, the new domain must be no longer than that.
pub const MAX_PORTAL_DOMAIN_LEN: usize = 10;

/// Default public domain for shipping patcher output.
///
/// Blizzard's `battle.net` is 10 bytes. `wowemu.dev` is also 10 bytes,
/// so the replacement is bytewise drop-in: no NUL padding, no offset
/// shifts, no risk of NUL-collapsed concatenation.
pub const DEFAULT_PORTAL_DOMAIN: &str = "wowemu.dev";

/// Parsed and validated portal-domain configuration.
#[derive(Debug, Clone)]
pub struct PortalDomain {
    raw: String,
}

impl PortalDomain {
    /// Default: the public-facing domain shipped with this patcher.
    pub fn default_public() -> Self {
        // Default is constant-validated; unwrap is safe.
        Self::parse(DEFAULT_PORTAL_DOMAIN).expect("default domain is valid")
    }

    /// Parse and validate a user-supplied domain.
    ///
    /// Rules:
    /// - ASCII only
    /// - Characters: alphanumeric, `.`, `-`
    /// - At least 3 chars (covers minimal `a.b`)
    /// - At most `MAX_PORTAL_DOMAIN_LEN` chars (10, the length of `battle.net`)
    /// - Must not start or end with `.` or `-`
    /// - Must contain at least one `.`
    pub fn parse(raw: &str) -> Result<Self, WowPatcherError> {
        // Structural / format checks first: more useful errors than a
        // bare "too long" message when the user pastes something obviously
        // malformed.
        if !raw.is_ascii() {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "portal domain must be ASCII",
            ));
        }
        if raw.len() < 3 {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "portal domain too short (minimum 3 chars, e.g. 'a.b')",
            ));
        }
        if !raw.contains('.') {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "portal domain must contain at least one '.' (e.g. 'wowemu.dev')",
            ));
        }
        let first = raw.chars().next().unwrap();
        let last = raw.chars().next_back().unwrap();
        if first == '.' || first == '-' || last == '.' || last == '-' {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                "portal domain must not start or end with '.' or '-'",
            ));
        }
        for c in raw.chars() {
            if !(c.is_ascii_alphanumeric() || c == '.' || c == '-') {
                return Err(WowPatcherError::new(
                    ErrorCategory::ValidationError,
                    format!(
                        "portal domain '{}' contains invalid character '{}' (allowed: alphanumeric, '.', '-')",
                        raw, c
                    ),
                ));
            }
        }
        // Length check last so format errors surface first.
        if raw.len() > MAX_PORTAL_DOMAIN_LEN {
            return Err(WowPatcherError::new(
                ErrorCategory::ValidationError,
                format!(
                    "portal domain '{}' is {} bytes; max is {} (length of 'battle.net')",
                    raw,
                    raw.len(),
                    MAX_PORTAL_DOMAIN_LEN
                ),
            ));
        }
        Ok(Self {
            raw: raw.to_string(),
        })
    }

    /// The raw domain string (e.g. `"wowemu.dev"`).
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Replacement bytes for the `portal_pattern()` slot.
    ///
    /// The pattern is `.actual.battle.net` (18 bytes). We replace it with
    /// `.actual.<domain>`, NUL-padded to 18 bytes by the caller via
    /// `Pattern::padded()`. For the default `wowemu.dev`, this is exactly
    /// `.actual.wowemu.dev` (18 bytes, no padding).
    pub fn portal_replacement(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.raw.len());
        out.extend_from_slice(b".actual.");
        out.extend_from_slice(self.raw.as_bytes());
        out
    }
}

impl Default for PortalDomain {
    fn default() -> Self {
        Self::default_public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_wowemu_dev() {
        assert_eq!(PortalDomain::default().as_str(), "wowemu.dev");
    }

    #[test]
    fn default_replacement_matches_pattern_length() {
        let d = PortalDomain::default();
        // .actual.battle.net is 18 bytes; .actual.wowemu.dev is also 18
        assert_eq!(d.portal_replacement().len(), 18);
        assert_eq!(&d.portal_replacement(), b".actual.wowemu.dev");
    }

    #[test]
    fn shorter_domain_validates_and_pads_at_use_site() {
        // bgs.corp is 8 bytes; replacement is 16 bytes (".actual.bgs.corp"),
        // and the patch caller NUL-fills to fit the 18-byte portal slot.
        let d = PortalDomain::parse("bgs.corp").unwrap();
        assert_eq!(d.as_str(), "bgs.corp");
        assert_eq!(d.portal_replacement(), b".actual.bgs.corp");
    }

    #[test]
    fn rejects_too_long() {
        // 11 bytes -- one over the limit
        let err = PortalDomain::parse("12345678.ab").unwrap_err();
        assert!(format!("{}", err).contains("max is 10"));
    }

    #[test]
    fn rejects_no_dot() {
        let err = PortalDomain::parse("wowemudev").unwrap_err();
        assert!(format!("{}", err).contains("at least one '.'"));
    }

    #[test]
    fn rejects_leading_dot() {
        let err = PortalDomain::parse(".wowemu.dev").unwrap_err();
        assert!(format!("{}", err).contains("start or end"));
    }

    #[test]
    fn rejects_trailing_dot() {
        let err = PortalDomain::parse("wowemu.dev.").unwrap_err();
        assert!(format!("{}", err).contains("start or end"));
    }

    #[test]
    fn rejects_invalid_chars() {
        let err = PortalDomain::parse("a@b.c").unwrap_err();
        assert!(format!("{}", err).contains("invalid character"));
    }

    #[test]
    fn rejects_too_short() {
        let err = PortalDomain::parse("ab").unwrap_err();
        assert!(format!("{}", err).contains("too short"));
    }

    #[test]
    fn accepts_alphanumeric_and_hyphen() {
        let d = PortalDomain::parse("a-1.b-2").unwrap();
        assert_eq!(d.as_str(), "a-1.b-2");
    }

    #[test]
    fn rejects_non_ascii() {
        let err = PortalDomain::parse("wö.dev").unwrap_err();
        // Catches via byte-length OR ASCII check; either is fine.
        let msg = format!("{}", err);
        assert!(msg.contains("ASCII") || msg.contains("max is 10"));
    }
}
