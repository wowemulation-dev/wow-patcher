pub const RSA_MODULUS: &[u8] = &[
    0x5F, 0xD6, 0x80, 0x0B, 0xA7, 0xFF, 0x01, 0x40, 0xC7, 0xBC, 0x8E, 0xF5, 0x6B, 0x27, 0xB0, 0xBF,
    0xF0, 0x1D, 0x1B, 0xFE, 0xDD, 0x0B, 0x1F, 0x3D, 0xB6, 0x6F, 0x1A, 0x48, 0x0D, 0xFB, 0x51, 0x08,
    0x65, 0x58, 0x4F, 0xDB, 0x5C, 0x6E, 0xCF, 0x64, 0xCB, 0xC1, 0x6B, 0x2E, 0xB8, 0x0F, 0x5D, 0x08,
    0x5D, 0x89, 0x06, 0xA9, 0x77, 0x8B, 0x9E, 0xAA, 0x04, 0xB0, 0x83, 0x10, 0xE2, 0x15, 0x4D, 0x08,
    0x77, 0xD4, 0x7A, 0x0E, 0x5A, 0xB0, 0xBB, 0x00, 0x61, 0xD7, 0xA6, 0x75, 0xDF, 0x06, 0x64, 0x88,
    0xBB, 0xB9, 0xCA, 0xB0, 0x18, 0x8B, 0x54, 0x13, 0xE2, 0xCB, 0x33, 0xDF, 0x17, 0xD8, 0xDA, 0xA9,
    0xA5, 0x60, 0xA3, 0x1F, 0x4E, 0x27, 0x05, 0x98, 0x6F, 0xAA, 0xEE, 0x14, 0x3B, 0xF3, 0x97, 0xA8,
    0x12, 0x02, 0x94, 0x0D, 0x84, 0xDC, 0x0E, 0xF1, 0x76, 0x23, 0x95, 0x36, 0x13, 0xF9, 0xA9, 0xC5,
    0x48, 0xDB, 0xDA, 0x86, 0xBE, 0x29, 0x22, 0x54, 0x44, 0x9D, 0x9F, 0x80, 0x7B, 0x07, 0x80, 0x30,
    0xEA, 0xD2, 0x83, 0xCC, 0xCE, 0x37, 0xD1, 0xD1, 0xCF, 0x85, 0xBE, 0x91, 0x25, 0xCE, 0xC0, 0xCC,
    0x55, 0xC8, 0xC0, 0xFB, 0x38, 0xC5, 0x49, 0x03, 0x6A, 0x02, 0xA9, 0x9F, 0x9F, 0x86, 0xFB, 0xC7,
    0xCB, 0xC6, 0xA5, 0x82, 0xA2, 0x30, 0xC2, 0xAC, 0xE6, 0x98, 0xDA, 0x83, 0x64, 0x43, 0x7F, 0x0D,
    0x13, 0x18, 0xEB, 0x90, 0x53, 0x5B, 0x37, 0x6B, 0xE6, 0x0D, 0x80, 0x1E, 0xEF, 0xED, 0xC7, 0xB8,
    0x68, 0x9B, 0x4C, 0x09, 0x7B, 0x60, 0xB2, 0x57, 0xD8, 0x59, 0x8D, 0x7F, 0xEA, 0xCD, 0xEB, 0xC4,
    0x60, 0x9F, 0x45, 0x7A, 0xA9, 0x26, 0x8A, 0x2F, 0x85, 0x0C, 0xF2, 0x19, 0xC6, 0x53, 0x92, 0xF7,
    0xF0, 0xB8, 0x32, 0xCB, 0x5B, 0x66, 0xCE, 0x51, 0x54, 0xB4, 0xC3, 0xD3, 0xD4, 0xDC, 0xB3, 0xEE,
];

pub const CRYPTO_ED25519_PUBLIC_KEY: &[u8] = &[
    0x02, 0x59, 0x6F, 0x0D, 0x0C, 0x06, 0x1A, 0x8B, 0x30, 0x74, 0x59, 0x88, 0xFD, 0x72, 0xC5, 0x9E,
    0x29, 0xEC, 0x36, 0x7F, 0xB0, 0xF3, 0x41, 0xF2, 0x8E, 0x0F, 0x08, 0xD0, 0x37, 0xBA, 0xFC, 0x69,
];

/// Default replacement for version URL - using the Arctium CDN endpoint
/// The %s placeholders are kept for runtime replacement with region and product
pub fn get_version_url(build: Option<u32>, region: Option<&str>, product: Option<&str>) -> String {
    let region = region.unwrap_or("%s");
    let product = product.unwrap_or("%s");

    if let Some(build) = build {
        format!(
            "http://ngdp.arctium.io/{}/{}/{}/versions",
            region, product, build
        )
    } else {
        // Fallback to default pattern if build is unknown
        format!(
            "http://ngdp.arctium.io/{}/{}/latest/versions",
            region, product
        )
    }
}

/// Default replacement for CDNs URL - using the Arctium CDN endpoint
pub fn get_cdns_url() -> String {
    "http://ngdp.arctium.io/customs/wow/cdns".to_string()
}

/// Creates a padded byte array for URL replacement
/// Since URLs must fit within the original space, we pad with null bytes
pub fn create_url_replacement(url: &str, original_len: usize) -> Vec<u8> {
    let mut result = url.as_bytes().to_vec();

    // Ensure we don't exceed original length
    if result.len() > original_len {
        result.truncate(original_len);
    } else {
        // Pad with null bytes to match original length
        result.resize(original_len, 0);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_modulus() {
        assert_eq!(RSA_MODULUS.len(), 256);

        // All u8 values are by definition <= 255
        for &_b in RSA_MODULUS {
            // Type system ensures this
        }

        assert_eq!(RSA_MODULUS[0], 0x5F);
        assert_eq!(RSA_MODULUS[1], 0xD6);
        assert_eq!(RSA_MODULUS[2], 0x80);
        assert_eq!(RSA_MODULUS[3], 0x0B);
        assert_eq!(RSA_MODULUS[255], 0xEE);
    }

    #[test]
    fn test_crypto_ed25519_public_key() {
        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY.len(), 32);

        // All u8 values are by definition <= 255
        for &_b in CRYPTO_ED25519_PUBLIC_KEY {
            // Type system ensures this
        }

        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY[0], 0x02);
        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY[1], 0x59);
        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY[2], 0x6F);
        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY[3], 0x0D);
        assert_eq!(CRYPTO_ED25519_PUBLIC_KEY[31], 0x69);
    }

    #[test]
    fn test_cryptographic_key_integrity() {
        // Test that RSA modulus is not all zeros
        let all_zeros = RSA_MODULUS.iter().all(|&b| b == 0);
        assert!(!all_zeros, "RSA_MODULUS contains all zeros");

        // Test that Ed25519 key is not all zeros
        let all_zeros = CRYPTO_ED25519_PUBLIC_KEY.iter().all(|&b| b == 0);
        assert!(!all_zeros, "CRYPTO_ED25519_PUBLIC_KEY contains all zeros");

        // Test that RSA modulus has reasonable entropy
        let first_byte = RSA_MODULUS[0];
        let all_same = RSA_MODULUS.iter().all(|&b| b == first_byte);
        assert!(!all_same, "RSA_MODULUS contains all identical bytes");

        // Test that Ed25519 key has reasonable entropy
        let first_byte = CRYPTO_ED25519_PUBLIC_KEY[0];
        let all_same = CRYPTO_ED25519_PUBLIC_KEY.iter().all(|&b| b == first_byte);
        assert!(
            !all_same,
            "CRYPTO_ED25519_PUBLIC_KEY contains all identical bytes"
        );
    }

    #[test]
    fn test_keys_are_immutable() {
        // Make copies and verify they match
        let rsa_copy: Vec<u8> = RSA_MODULUS.to_vec();
        let ed25519_copy: Vec<u8> = CRYPTO_ED25519_PUBLIC_KEY.to_vec();

        assert_eq!(rsa_copy.as_slice(), RSA_MODULUS);
        assert_eq!(ed25519_copy.as_slice(), CRYPTO_ED25519_PUBLIC_KEY);
    }

    #[test]
    fn test_get_version_url() {
        // Test with all parameters
        let url = get_version_url(Some(12345), Some("EU"), Some("wow"));
        assert_eq!(url, "http://ngdp.arctium.io/EU/wow/12345/versions");

        // Test with placeholders
        let url = get_version_url(Some(12345), None, None);
        assert_eq!(url, "http://ngdp.arctium.io/%s/%s/12345/versions");

        // Test without build
        let url = get_version_url(None, Some("EU"), Some("wow"));
        assert_eq!(url, "http://ngdp.arctium.io/EU/wow/latest/versions");

        // Test fallback pattern
        let url = get_version_url(None, None, None);
        assert_eq!(url, "http://ngdp.arctium.io/%s/%s/latest/versions");
    }

    #[test]
    fn test_get_cdns_url() {
        let url = get_cdns_url();
        assert_eq!(url, "http://ngdp.arctium.io/customs/wow/cdns");
    }

    #[test]
    fn test_create_url_replacement() {
        // Test exact length
        let url = "http://test.com";
        let replacement = create_url_replacement(url, url.len());
        assert_eq!(replacement.len(), url.len());
        assert_eq!(&replacement, url.as_bytes());

        // Test padding
        let replacement = create_url_replacement(url, 20);
        assert_eq!(replacement.len(), 20);
        assert_eq!(&replacement[..url.len()], url.as_bytes());
        for &b in &replacement[url.len()..] {
            assert_eq!(b, 0);
        }

        // Test truncation
        let replacement = create_url_replacement(url, 10);
        assert_eq!(replacement.len(), 10);
        assert_eq!(&replacement, &url.as_bytes()[..10]);
    }
}
