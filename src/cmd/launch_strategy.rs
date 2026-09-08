use crate::platform::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LaunchStrategy {
    Legacy,
    Retail,
}

pub(crate) fn select_strategy(version: Version) -> Result<LaunchStrategy, String> {
    if version.major >= 12 && version.build != 0 {
        return Ok(LaunchStrategy::Retail);
    }

    // Retain the existing launcher for its documented version families. Newer
    // Classic versions must not inherit a recipe solely from their major number.
    if version.build != 0
        && matches!(
            (version.major, version.minor, version.patch),
            (1, 13..=14, _) | (2, 5, 0..=4) | (3, 4, 0..=4) | (4, 4, 0..=2) | (9..=10, _, _)
        )
    {
        return Ok(LaunchStrategy::Legacy);
    }

    Err(format!(
        "No launch strategy for {version}. Supported families: 1.13.x, 1.14.x, \
         2.5.0-2.5.4, 3.4.0-3.4.4, 4.4.0-4.4.2, 9.x, 10.x; \
         the new retail recipe requires exactly 12.0.7.68887. No process started."
    ))
}

pub(crate) fn validate_retail_recipe(version: Version) -> Result<(), String> {
    if version == Version::new(12, 0, 7, 68887) {
        Ok(())
    } else {
        Err(format!(
            "No verified retail recipe for {version}; the current recipe requires exactly \
             12.0.7.68887. No process started."
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retail_strategy_starts_at_major_12_and_includes_future_majors() {
        for version in [
            Version::new(12, 0, 0, 65655),
            Version::new(12, 0, 7, 68887),
            Version::new(12, 1, 0, 68914),
            Version::new(13, 0, 0, 70000),
            Version::new(u16::MAX, 0, 0, u32::MAX),
        ] {
            assert_eq!(
                select_strategy(version),
                Ok(LaunchStrategy::Retail),
                "{version}"
            );
        }
        assert!(select_strategy(Version::new(11, 2, 7, 65000)).is_err());
        assert!(select_strategy(Version::new(12, 0, 0, 0)).is_err());
    }

    #[test]
    fn retail_recipe_requires_all_four_version_components() {
        assert_eq!(
            validate_retail_recipe(Version::new(12, 0, 7, 68887)),
            Ok(())
        );
        for version in [
            Version::new(12, 0, 0, 65655),
            Version::new(12, 0, 7, 68886),
            Version::new(12, 0, 7, 68888),
            Version::new(12, 0, 6, 68887),
            Version::new(12, 0, 8, 68887),
            Version::new(12, 1, 7, 68887),
            Version::new(11, 0, 7, 68887),
            Version::new(13, 0, 7, 68887),
        ] {
            assert!(validate_retail_recipe(version).is_err(), "{version}");
        }
    }

    #[test]
    fn legacy_ranges_include_their_documented_endpoints() {
        for (major, minor, patch) in [
            (1, 13, 0),
            (1, 13, 7),
            (1, 14, 0),
            (1, 14, 4),
            (2, 5, 0),
            (2, 5, 4),
            (3, 4, 0),
            (3, 4, 4),
            (4, 4, 0),
            (4, 4, 2),
            (9, 0, 0),
            (9, 2, 7),
            (10, 0, 0),
            (10, 2, 7),
        ] {
            let version = Version::new(major, minor, patch, 50000);
            assert_eq!(
                select_strategy(version),
                Ok(LaunchStrategy::Legacy),
                "{version}"
            );
        }
    }

    #[test]
    fn versions_outside_legacy_ranges_do_not_fall_back() {
        for (major, minor, patch) in [
            (0, 0, 0),
            (1, 12, 1),
            (1, 15, 0),
            (2, 4, 3),
            (2, 5, 5),
            (2, 6, 0),
            (3, 3, 5),
            (3, 4, 5),
            (3, 5, 0),
            (3, 80, 0),
            (4, 3, 4),
            (4, 4, 3),
            (4, 5, 0),
            (5, 5, 0),
            (8, 3, 7),
            (11, 0, 0),
        ] {
            let version = Version::new(major, minor, patch, 68887);
            assert!(select_strategy(version).is_err(), "{version}");
        }
        assert!(select_strategy(Version::new(1, 13, 2, 0)).is_err());
    }
}
