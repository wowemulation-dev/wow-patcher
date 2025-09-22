use crate::errors::{ErrorCategory, WowPatcherError};

pub type Pattern = Vec<i16>;

pub fn string_to_pattern(s: &str) -> Pattern {
    s.bytes().map(|b| b as i16).collect()
}

pub trait PatternExt {
    fn empty(&self) -> Vec<u8>;
}

impl PatternExt for Pattern {
    fn empty(&self) -> Vec<u8> {
        vec![0; self.len()]
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

    let position = find_pattern(data, find);

    match position {
        Some(pos) => {
            let replace_len = replace.len().min(find.len());
            data[pos..(replace_len + pos)].copy_from_slice(&replace[..replace_len]);
            Ok(())
        }
        None => Err(WowPatcherError::new(
            ErrorCategory::PatchingError,
            "pattern not found in data",
        )),
    }
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
}
