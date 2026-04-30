//! Pattern catalogue used by the `launch` (runtime-patch) subcommand.
//!
//! These mirror the patterns in `Arctium.WoW.Launcher`'s
//! `Patterns/Common.cs` and `Patterns/Windows.cs`. Each pattern is a
//! `Pattern` (alias for `Vec<i16>`) where values 0..=255 match a
//! literal byte and `-1` is a wildcard matching any byte. The runtime
//! mode scans every committed memory region of the suspended process
//! using `ReadProcessMemory` and `VirtualQueryEx` and applies a patch
//! at the first match.
//!
//! Pattern naming follows Arctium so cross-references stay clean. Some
//! patterns are unused at this stage of the port; they remain in the
//! catalogue so subsequent commits do not need to round-trip through
//! the C# source again.

use crate::binary::{Pattern, string_to_pattern};
use std::sync::OnceLock;

mod common;
mod windows;

pub use common::*;
pub use windows::*;

/// Length of the `Init` pattern (Windows-only). Used as a sanity
/// check by the launch flow before pattern scanning starts.
pub const INIT_PATTERN_LEN: usize = 30;

/// Helper for one-shot lazy initialisation of static patterns.
fn pattern_from_bytes(bytes: &'static [i16]) -> Pattern {
    bytes.to_vec()
}

fn pattern_from_str(s: &str) -> Pattern {
    string_to_pattern(s)
}

// Re-export for tests.
#[doc(hidden)]
pub fn _testing_pattern_from_bytes(bytes: &'static [i16]) -> Pattern {
    pattern_from_bytes(bytes)
}

#[doc(hidden)]
pub fn _testing_pattern_from_str(s: &str) -> Pattern {
    pattern_from_str(s)
}

// Memo-cells for any pattern callers want as a `&'static Pattern`.
// Most consumers can use the `*_pattern()` accessors below; the
// memo-cells are here for cases where patterns are referenced
// repeatedly in tight loops and the per-call clone matters.
static PORTAL_RUNTIME_PATTERN: OnceLock<Pattern> = OnceLock::new();

/// Runtime portal pattern. Includes the trailing NUL so the match
/// only fires on the C-string literal, not on substrings of longer
/// hostnames.
#[must_use]
pub fn portal_runtime_pattern() -> &'static Pattern {
    PORTAL_RUNTIME_PATTERN.get_or_init(|| pattern_from_str(".actual.battle.net\0"))
}
