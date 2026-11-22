use std::ptr;

use windows_sys::Win32::{
    Foundation::ERROR_FILE_NOT_FOUND,
    System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
        RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    },
};

const CUSTOM_ROOT: &str = r"Software\Custom Game Server Dev\Battle.net\Launch Options";
const BLIZZARD_ROOT: &str = r"Software\Blizzard Entertainment\Battle.net\Launch Options";

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn create(path: &str) -> Result<Key, String> {
    let path = wide(path);
    let mut key = ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("RegCreateKeyExW failed with Win32 error {status}"));
    }
    Ok(Key(key))
}

fn open(path: &str) -> Option<Key> {
    let path = wide(path);
    let mut key = ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut key) };
    (status == 0).then_some(Key(key))
}

fn copy_value(source: &Key, destination: &Key, name: &str) {
    let name = wide(name);
    let mut kind = 0;
    let mut size = 0;
    let status = unsafe {
        RegQueryValueExW(
            source.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            ptr::null_mut(),
            &mut size,
        )
    };
    if status != 0 {
        return;
    }
    let mut value = vec![0u8; size as usize];
    if unsafe {
        RegQueryValueExW(
            source.0,
            name.as_ptr(),
            ptr::null(),
            &mut kind,
            value.as_mut_ptr(),
            &mut size,
        )
    } == 0
    {
        unsafe {
            RegSetValueExW(destination.0, name.as_ptr(), 0, kind, value.as_ptr(), size);
        }
    }
}

fn set_string(key: &Key, name: &str, value: &str) -> Result<(), String> {
    let name = wide(name);
    let value = wide(value);
    let status = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            value.as_ptr().cast(),
            (value.len() * 2) as u32,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(format!("RegSetValueExW failed with Win32 error {status}"))
    }
}

fn default_string(key: &Key, name: &str, value: &str) -> Result<(), String> {
    let wide_name = wide(name);
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide_name.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        set_string(key, name, value)?;
    }
    Ok(())
}

pub(super) fn prepare() -> Result<(), String> {
    let root = create(CUSTOM_ROOT)?;
    let wow = create(&format!(r"{CUSTOM_ROOT}\WoW"))?;
    let bna = create(&format!(r"{CUSTOM_ROOT}\BNA"))?;
    if let Some(source) = open(BLIZZARD_ROOT) {
        copy_value(&source, &root, "URI_TOKEN");
    }
    if let Some(source) = open(&format!(r"{BLIZZARD_ROOT}\WoW")) {
        for name in [
            "LOCALE",
            "LOCALE_AUDIO",
            "REGION",
            "GAME_ACCOUNT",
            "LAUNCH_64BIT",
        ] {
            copy_value(&source, &wow, name);
        }
    }
    for (name, value) in [
        ("CONNECTION_STRING", ""),
        ("LOCALE", "ruRU"),
        ("LOCALE_AUDIO", "ruRU"),
        ("REGION", "EU"),
    ] {
        default_string(&wow, name, value)?;
    }
    for region in ["EU", "US", "KR", "CN", "XX", "CXX"] {
        set_string(&bna, &format!("CONNECTION_STRING_{region}"), "")?;
    }
    Ok(())
}
