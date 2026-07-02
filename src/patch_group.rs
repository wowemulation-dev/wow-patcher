//! Selectable patch groups for fine-grained control over what the
//! patcher modifies.
//!
//! Each variant maps to a specific patch site in the binary. Use
//! [`PatchGroup::all()`] for the default set (everything except
//! cert-bundle-injection and cert-bundle-url, which are input-gated).

use bitflags::bitflags;

bitflags! {
    /// Which modifications to apply to the target binary.
    ///
    /// Used by both the static patcher and the runtime `launch`
    /// subcommand. Groups not selected are silently skipped.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct PatchGroup: u16 {
        /// RSA modulus replacement via ConnectToModulus pattern.
        const RSA = 1 << 0;
        /// Ed25519 public key replacement (modern clients only).
        const ED25519 = 1 << 1;
        /// BGS Aurora-RPC portal hostname suffix (`.actual.battle.net`).
        const PORTAL = 1 << 2;
        /// Version URL rewrite (TACT versions endpoint).
        const VERSION = 1 << 3;
        /// CDNs URL rewrite (TACT CDN list endpoint).
        const CDNS = 1 << 4;
        /// Inject a signed cert bundle into the `{"Created":` envelope slot.
        ///
        /// Only effective when `--cert-bundle FILE` is also provided.
        const CERT_BUNDLE = 1 << 5;
        /// Rewrite the cert-bundle download URL literal.
        ///
        /// Only effective when `--cert-bundle-url URL` is also provided.
        const CERT_BUNDLE_URL = 1 << 6;
    }
}

impl PatchGroup {
    /// The set applied when the user doesn't specify `--patches`.
    /// This is all groups; the cert-bundle groups are input-gated
    /// and won't fire without `--cert-bundle` / `--cert-bundle-url`.
    pub fn default_set() -> Self {
        Self::all()
    }
}

impl std::str::FromStr for PatchGroup {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_lowercase();
        match lower.as_str() {
            "all" => Ok(Self::all()),
            "rsa" => Ok(Self::RSA),
            "ed25519" => Ok(Self::ED25519),
            "portal" => Ok(Self::PORTAL),
            "version" => Ok(Self::VERSION),
            "cdns" => Ok(Self::CDNS),
            "cert-bundle" => Ok(Self::CERT_BUNDLE),
            "cert-bundle-url" => Ok(Self::CERT_BUNDLE_URL),
            other => Err(format!(
                "unknown patch group '{}'. Valid groups: all, rsa, ed25519, portal, version, cdns, cert-bundle, cert-bundle-url",
                other
            )),
        }
    }
}

impl std::fmt::Display for PatchGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::all() {
            return write!(f, "all");
        }
        let mut parts: Vec<&str> = Vec::new();
        if self.contains(Self::RSA) {
            parts.push("rsa");
        }
        if self.contains(Self::ED25519) {
            parts.push("ed25519");
        }
        if self.contains(Self::PORTAL) {
            parts.push("portal");
        }
        if self.contains(Self::VERSION) {
            parts.push("version");
        }
        if self.contains(Self::CDNS) {
            parts.push("cdns");
        }
        if self.contains(Self::CERT_BUNDLE) {
            parts.push("cert-bundle");
        }
        if self.contains(Self::CERT_BUNDLE_URL) {
            parts.push("cert-bundle-url");
        }
        write!(f, "{}", parts.join(","))
    }
}

/// Parse a comma-separated list of group names into a [`PatchGroup`]
/// bitflag.
///
/// Returns `PatchGroup::all()` for empty input.
pub fn parse_patch_groups(input: &str) -> Result<PatchGroup, String> {
    if input.trim().is_empty() {
        return Ok(PatchGroup::all());
    }
    let mut flags = PatchGroup::empty();
    for part in input.split(',') {
        flags |= part.parse::<PatchGroup>()?;
    }
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_contains_every_variant() {
        let all = PatchGroup::all();
        assert!(all.contains(PatchGroup::RSA));
        assert!(all.contains(PatchGroup::ED25519));
        assert!(all.contains(PatchGroup::PORTAL));
        assert!(all.contains(PatchGroup::VERSION));
        assert!(all.contains(PatchGroup::CDNS));
        assert!(all.contains(PatchGroup::CERT_BUNDLE));
        assert!(all.contains(PatchGroup::CERT_BUNDLE_URL));
    }

    #[test]
    fn parse_all() {
        assert_eq!("all".parse::<PatchGroup>().unwrap(), PatchGroup::all());
    }

    #[test]
    fn parse_individual() {
        assert_eq!("rsa".parse::<PatchGroup>().unwrap(), PatchGroup::RSA);
        assert_eq!(
            "ed25519".parse::<PatchGroup>().unwrap(),
            PatchGroup::ED25519
        );
        assert_eq!("portal".parse::<PatchGroup>().unwrap(), PatchGroup::PORTAL);
        assert_eq!(
            "version".parse::<PatchGroup>().unwrap(),
            PatchGroup::VERSION
        );
        assert_eq!("cdns".parse::<PatchGroup>().unwrap(), PatchGroup::CDNS);
        assert_eq!(
            "cert-bundle".parse::<PatchGroup>().unwrap(),
            PatchGroup::CERT_BUNDLE
        );
        assert_eq!(
            "cert-bundle-url".parse::<PatchGroup>().unwrap(),
            PatchGroup::CERT_BUNDLE_URL
        );
    }

    #[test]
    fn parse_unknown() {
        assert!("unknown".parse::<PatchGroup>().is_err());
    }

    #[test]
    fn parse_comma_list() {
        let flags = parse_patch_groups("rsa,portal").unwrap();
        assert!(flags.contains(PatchGroup::RSA));
        assert!(flags.contains(PatchGroup::PORTAL));
        assert!(!flags.contains(PatchGroup::ED25519));
        assert!(!flags.contains(PatchGroup::VERSION));
        assert!(!flags.contains(PatchGroup::CDNS));
    }

    #[test]
    fn parse_comma_list_spaces() {
        let flags = parse_patch_groups(" rsa , portal ").unwrap();
        assert!(flags.contains(PatchGroup::RSA));
        assert!(flags.contains(PatchGroup::PORTAL));
    }

    #[test]
    fn parse_empty_is_all() {
        assert_eq!(parse_patch_groups("").unwrap(), PatchGroup::all());
    }

    #[test]
    fn display_all() {
        assert_eq!(PatchGroup::all().to_string(), "all");
    }

    #[test]
    fn display_subset() {
        let flags = PatchGroup::RSA | PatchGroup::PORTAL;
        let s = flags.to_string();
        assert!(s.contains("rsa"));
        assert!(s.contains("portal"));
        assert!(!s.contains("ed25519"));
    }

    #[test]
    fn display_single() {
        assert_eq!(PatchGroup::VERSION.to_string(), "version");
    }

    #[test]
    fn bitwise_ops() {
        let a = PatchGroup::RSA | PatchGroup::PORTAL;
        let b = PatchGroup::PORTAL | PatchGroup::CDNS;
        assert_eq!(a & b, PatchGroup::PORTAL);
        assert_eq!(
            a | b,
            PatchGroup::RSA | PatchGroup::PORTAL | PatchGroup::CDNS
        );
    }
}
