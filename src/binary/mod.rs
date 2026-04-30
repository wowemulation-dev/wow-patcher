use crate::errors::{ErrorCategory, WowPatcherError};

pub mod section;
pub use section::{SectionInfo, check_offset_section, validate_patch_offsets};

pub type Pattern = Vec<i16>;

pub fn string_to_pattern(s: &str) -> Pattern {
    s.bytes().map(|b| b as i16).collect()
}

pub trait PatternExt {
    fn empty(&self) -> Vec<u8>;
    fn padded(&self, target: &[u8]) -> Vec<u8>;
}

impl PatternExt for Pattern {
    fn empty(&self) -> Vec<u8> {
        vec![0; self.len()]
    }

    /// Build a length-preserving replacement: `target` followed by NUL
    /// padding to match the pattern's length.
    ///
    /// Use this for hostname / URL fragments embedded in `.rdata` that
    /// the client assembles at runtime via NUL-terminated string
    /// concatenation. Replacing with all-NUL truncates the assembled
    /// URL at the embedded NUL and silently drops the rest of the
    /// concatenation. A target like `b".localhost"` for the
    /// `.actual.battle.net` slot lets the runtime concat produce
    /// `<region>.localhost`, which resolves to 127.0.0.1 via
    /// `nss-myhostname` (RFC 6761) without needing /etc/hosts.
    ///
    /// Panics if `target.len() > self.len()`.
    fn padded(&self, target: &[u8]) -> Vec<u8> {
        assert!(
            target.len() <= self.len(),
            "padded replacement target ({} bytes) exceeds pattern length ({} bytes)",
            target.len(),
            self.len()
        );
        let mut out = vec![0u8; self.len()];
        out[..target.len()].copy_from_slice(target);
        out
    }
}

pub trait DataExt {
    fn find_pattern(&self, pattern: &Pattern) -> Option<usize>;
}

impl DataExt for Vec<u8> {
    fn find_pattern(&self, pattern: &Pattern) -> Option<usize> {
        find_pattern(self, pattern)
    }
}

impl DataExt for [u8] {
    fn find_pattern(&self, pattern: &Pattern) -> Option<usize> {
        find_pattern(self, pattern)
    }
}

/// Locate `find` in `data` and overwrite starting at the match.
///
/// Writes `replace.len()` bytes into `data` starting at the matched
/// position. The match is located via `find_pattern`, which honors
/// `-1` wildcards in `find`.
///
/// # Replacement length semantics
///
/// - If `replace.len() <= find.len()`: writes `replace.len()` bytes;
///   any trailing bytes of the matched pattern remain unchanged.
/// - If `replace.len() > find.len()`: writes all `replace.len()`
///   bytes, overwriting `replace.len() - find.len()` bytes past the
///   end of the matched pattern. This is the intended behaviour for
///   key replacement, where the find pattern is an 8-byte prefix
///   anchor and the replacement is the full key (256 bytes for RSA,
///   32 bytes for Ed25519).
///
/// # Errors
///
/// - `data` is empty.
/// - `find` is longer than `data`.
/// - `find` is not present in `data`.
/// - `replace.len()` is longer than the bytes available from the
///   match position to the end of `data`.
pub fn patch(data: &mut [u8], find: &Pattern, replace: &[u8]) -> Result<(), WowPatcherError> {
    if data.is_empty() {
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "cannot patch empty data",
        ));
    }

    if find.len() > data.len() {
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "pattern longer than data",
        ));
    }

    let Some(pos) = find_pattern(data, find) else {
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "pattern not found in data",
        ));
    };

    let end = pos.checked_add(replace.len()).ok_or_else(|| {
        WowPatcherError::new(
            ErrorCategory::PatchingError,
            "replacement length overflows usize when added to match position",
        )
    })?;
    if end > data.len() {
        return Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "replacement extends past the end of data",
        ));
    }

    data[pos..end].copy_from_slice(replace);
    Ok(())
}

fn find_pattern(data: &[u8], pattern: &Pattern) -> Option<usize> {
    if pattern.is_empty() || data.len() < pattern.len() {
        return None;
    }

    'outer: for i in 0..=data.len() - pattern.len() {
        for (j, &p) in pattern.iter().enumerate() {
            if p != -1 && data[i + j] as i16 != p {
                continue 'outer;
            }
        }
        return Some(i);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_pattern() {
        assert_eq!(string_to_pattern(""), Pattern::new());
        assert_eq!(string_to_pattern("hello"), vec![104, 101, 108, 108, 111]);
        assert_eq!(
            string_to_pattern(".actual.battle.net"),
            vec![
                46, 97, 99, 116, 117, 97, 108, 46, 98, 97, 116, 116, 108, 101, 46, 110, 101, 116
            ]
        );
    }

    #[test]
    fn test_pattern_empty() {
        let pattern = Pattern::new();
        assert_eq!(pattern.empty(), vec![]);

        let pattern = vec![1, 2, 3, 4, 5];
        assert_eq!(pattern.empty(), vec![0, 0, 0, 0, 0]);

        let pattern = vec![1, -1, 3, -1, 5];
        assert_eq!(pattern.empty(), vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_pattern_padded_target_fits() {
        // 18-byte pattern (.actual.battle.net) + 10-byte target (.localhost)
        let pattern = string_to_pattern(".actual.battle.net");
        let target = b".localhost";
        let padded = pattern.padded(target);
        assert_eq!(padded.len(), pattern.len(), "preserves pattern length");
        assert_eq!(&padded[..target.len()], target, "starts with target");
        assert!(
            padded[target.len()..].iter().all(|&b| b == 0),
            "tail is NUL-padded"
        );
    }

    #[test]
    fn test_pattern_padded_exact_fit() {
        // Target same length as pattern: no NUL padding.
        let pattern = string_to_pattern("abcdef");
        let padded = pattern.padded(b"abcdef");
        assert_eq!(padded, b"abcdef");
    }

    #[test]
    #[should_panic(expected = "exceeds pattern length")]
    fn test_pattern_padded_target_too_long() {
        let pattern = string_to_pattern("short");
        let _ = pattern.padded(b"way too long for the pattern");
    }

    #[test]
    fn test_patch() {
        let mut data = b"hello world".to_vec();
        let find = vec![104, 101, 108, 108, 111]; // "hello"
        let replace = b"HELLO";

        assert!(patch(&mut data, &find, replace).is_ok());
        assert_eq!(&data, b"HELLO world");
    }

    #[test]
    fn test_patch_no_match() {
        let mut data = b"hello world".to_vec();
        let find = vec![120, 121, 122]; // "xyz"
        let replace = b"ABC";

        let result = patch(&mut data, &find, replace);
        assert!(result.is_err());
        assert_eq!(&data, b"hello world");
    }

    #[test]
    fn test_patch_wildcard() {
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let find = vec![0x01, -1, 0x03];
        let replace = vec![0xFF, 0xFE, 0xFD];

        assert!(patch(&mut data, &find, &replace).is_ok());
        assert_eq!(data, vec![0xFF, 0xFE, 0xFD, 0x04, 0x05]);
    }

    #[test]
    fn test_patch_multiple_wildcards() {
        let mut data = vec![0x10, 0x20, 0x30, 0x40, 0x50];
        let find = vec![0x10, -1, -1, 0x40];
        let replace = vec![0xAA, 0xBB, 0xCC, 0xDD];

        assert!(patch(&mut data, &find, &replace).is_ok());
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x50]);
    }

    #[test]
    fn test_patch_at_end() {
        let mut data = b"prefix_suffixX".to_vec();
        let find = vec![115, 117, 102, 102, 105, 120]; // "suffix"
        let replace = b"SUFFIX";

        assert!(patch(&mut data, &find, replace).is_ok());
        assert_eq!(&data, b"prefix_SUFFIXX");
    }

    #[test]
    fn test_patch_shorter_replacement() {
        let mut data = b"hello world".to_vec();
        let find = vec![104, 101, 108, 108, 111]; // "hello"
        let replace = b"hi";

        assert!(patch(&mut data, &find, replace).is_ok());
        assert_eq!(&data, b"hillo world");
    }

    #[test]
    fn test_patch_with_real_patterns() {
        let mut data = b"prefix.actual.battle.net.suffix".to_vec();
        let find = string_to_pattern(".actual.battle.net");
        let replace = vec![0; 18];

        assert!(patch(&mut data, &find, &replace).is_ok());
        assert_eq!(
            &data,
            b"prefix\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00.suffix"
        );
    }

    #[test]
    fn test_patch_binary_pattern() {
        let mut data = vec![0x00, 0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5, 0xFF];
        let find = vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];
        let replace = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];

        assert!(patch(&mut data, &find, &replace).is_ok());
        assert_eq!(
            data,
            vec![0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0xFF]
        );
    }

    #[test]
    fn test_patch_edge_cases() {
        // Empty input
        let mut data = vec![];
        let find = vec![1, 2, 3];
        let replace = vec![4, 5, 6];

        let result = patch(&mut data, &find, &replace);
        assert!(result.is_err());
        assert!(data.is_empty());

        // Pattern longer than input
        let mut data = vec![1, 2];
        let find = vec![1, 2, 3, 4, 5];
        let replace = vec![6, 7, 8, 9, 10];

        let result = patch(&mut data, &find, &replace);
        assert!(result.is_err());
        assert_eq!(data, vec![1, 2]);

        // Nil replacement
        let mut data = vec![1, 2, 3];
        let find = vec![1, 2, 3];
        let replace = vec![];

        let result = patch(&mut data, &find, &replace);
        assert!(result.is_ok());
        assert_eq!(data, vec![1, 2, 3]);
    }

    /// Regression test for the RSA / Ed25519 key truncation bug.
    ///
    /// The find pattern is the 8-byte prefix anchor of a Battle.net
    /// RSA modulus, but the replacement is the full 256-byte modulus.
    /// Before the fix, only the first 8 bytes of the replacement
    /// were copied. After the fix, all 256 bytes are written,
    /// overwriting the 248 bytes that follow the matched pattern.
    #[test]
    fn test_patch_replacement_longer_than_pattern_writes_full_replacement() {
        // Layout: 16 bytes of leading filler, the 8-byte stock
        // ConnectTo modulus prefix, 248 more bytes of filler -- total
        // 272 bytes. After patching, the 256 bytes starting at
        // offset 16 should equal the replacement; the leading 16
        // bytes are untouched.
        let mut data = vec![0xCC; 16];
        data.extend_from_slice(&[0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5]);
        data.extend_from_slice(&[0xDE; 248]);
        assert_eq!(data.len(), 272);

        let find = vec![0x91, 0xD5, 0x9B, 0xB7, 0xD4, 0xE1, 0x83, 0xA5];
        let replace: Vec<u8> = (0..=255).collect(); // 256 distinct bytes

        patch(&mut data, &find, &replace).unwrap();

        // Leading filler unchanged.
        assert!(data[..16].iter().all(|&b| b == 0xCC));
        // The full 256-byte replacement landed.
        assert_eq!(&data[16..272], replace.as_slice());
    }

    /// Companion test for Ed25519 (32-byte replacement, 8-byte
    /// pattern). Same root cause as the RSA case but exercises a
    /// shorter excess.
    #[test]
    fn test_patch_ed25519_size_replacement() {
        let mut data = vec![0xCC; 8];
        data.extend_from_slice(&[0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD]);
        data.extend_from_slice(&[0xDE; 32]);
        assert_eq!(data.len(), 48);

        let find = vec![0x15, 0xD6, 0x18, 0xBD, 0x7D, 0xB5, 0x77, 0xBD];
        let replace: Vec<u8> = (0u8..32).collect();

        patch(&mut data, &find, &replace).unwrap();

        assert!(data[..8].iter().all(|&b| b == 0xCC));
        assert_eq!(&data[8..40], replace.as_slice());
        assert!(data[40..].iter().all(|&b| b == 0xDE));
    }

    /// The replacement may extend past the end of `data`. In that
    /// case we should report an error rather than silently truncate
    /// or panic.
    #[test]
    fn test_patch_replacement_past_end_is_error() {
        // Pattern lives at the very end of data; a 4-byte
        // replacement against a 2-byte pattern would write 2 bytes
        // past the end.
        let mut data = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let find = vec![0xCC, 0xDD]; // matches at offset 2
        let replace = vec![0x11, 0x22, 0x33, 0x44];

        let result = patch(&mut data, &find, &replace);
        assert!(
            result.is_err(),
            "should error rather than silently truncate or panic"
        );
        // Data should be unchanged on error.
        assert_eq!(data, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }
}
