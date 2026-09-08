use super::Result;
use crate::platform::Version;

pub(super) struct Recipe {
    pub version: Version,
    pub text_size: usize,
    pub resolver: usize,
    pub gate: usize,
    pub helper: usize,
    pub result_bl: usize,
    pub result_edi: usize,
    pub ed25519: usize,
    pub portal: usize,
    pub urls: [usize; 2],
    pub image_hash: &'static str,
    pub loader_hash: &'static str,
}

pub(super) const RECIPES: [Recipe; 2] = [
    Recipe {
        version: Version {
            major: 12,
            minor: 0,
            patch: 7,
            build: 68887,
        },
        text_size: 0x35c0b4c,
        resolver: 0x33ff200,
        gate: 0x33f5543,
        helper: 0x265fc80,
        result_bl: 0x337105e,
        result_edi: 0x336e721,
        ed25519: 0x35ebf30,
        portal: 0x37cdaa0,
        urls: [0x3993770, 0x39937b0],
        image_hash: "F8F4FDEE3C6FA291FC77F661B0C3F47B633332894223A4997AC167441FBF95FA",
        loader_hash: "D739A6C4B55CBE2960123120358DA82D7AB561DD017D9598C1A262AB6FF567C7",
    },
    Recipe {
        version: Version {
            major: 12,
            minor: 1,
            patch: 0,
            build: 69587,
        },
        text_size: 0x3783b4c,
        resolver: 0x35c1ab0,
        gate: 0x35b7f83,
        helper: 0x27f0380,
        result_bl: 0x28003d6,
        result_edi: 0x27fdac1,
        ed25519: 0x37af250,
        portal: 0x3989578,
        urls: [0x3b4b100, 0x3b4b140],
        image_hash: "B773093EDF986C8085FDC990649BFCB33DF5F692C244BE7FDDF46C49B413923E",
        loader_hash: "BC06969951614D168081F7EBEC9513BBCEFEFFDC483BF0AFCD65915DBB29FFC4",
    },
];

impl Recipe {
    pub fn from_version(version: Version) -> Result<&'static Self> {
        RECIPES
            .iter()
            .find(|recipe| recipe.version == version)
            .ok_or_else(|| format!("No verified retail recipe for {version}").into())
    }

    pub fn holds_entry(&self) -> bool {
        self.version.build == 69587
    }

    pub fn stub_rva(&self) -> usize {
        if self.holds_entry() {
            0x3785000
        } else {
            super::TEXT_START + self.text_size
        }
    }
}

fn sha256(bytes: &[u8]) -> Result<String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptHash,
        BCryptOpenAlgorithmProvider,
    };
    let size = u32::try_from(bytes.len())?;
    let mut algorithm = std::ptr::null_mut();
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, std::ptr::null(), 0)
    };
    if status < 0 {
        return Err(format!("Opening SHA-256 provider failed: 0x{status:08X}").into());
    }
    let mut hash = [0; 32];
    let status = unsafe {
        BCryptHash(
            algorithm,
            std::ptr::null(),
            0,
            bytes.as_ptr(),
            size,
            hash.as_mut_ptr(),
            32,
        )
    };
    unsafe {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if status < 0 {
        return Err(format!("SHA-256 failed: 0x{status:08X}").into());
    }
    Ok(hex::encode_upper(hash))
}

pub(super) fn verify_identity(bytes: &[u8], expected: &str, name: &str) -> Result<()> {
    if sha256(bytes)? != expected {
        return Err(format!("Unverified {name}: SHA-256 does not match the selected retail recipe; no process started").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_validation_rejects_changed_bytes() {
        let expected = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        assert!(verify_identity(b"abc", expected, "test input").is_ok());
        assert!(verify_identity(b"abd", expected, "test input").is_err());
    }

    #[test]
    fn available_recipes_match_version_dispatch() {
        for recipe in &RECIPES {
            assert!(crate::cmd::launch_strategy::validate_retail_recipe(recipe.version).is_ok());
            assert_eq!(
                Recipe::from_version(recipe.version).unwrap().resolver,
                recipe.resolver
            );
        }
        assert!(Recipe::from_version(Version::new(12, 1, 0, 69588)).is_err());
    }
}
