use std::sync::OnceLock;

static VERSION: OnceLock<String> = OnceLock::new();
static COMMIT: OnceLock<String> = OnceLock::new();
static DATE: OnceLock<String> = OnceLock::new();
static BUILT_BY: OnceLock<String> = OnceLock::new();

pub fn version() -> &'static str {
    VERSION.get_or_init(|| option_env!("CARGO_PKG_VERSION").unwrap_or("dev").to_string())
}

pub fn commit() -> &'static str {
    COMMIT.get_or_init(|| option_env!("GIT_COMMIT").unwrap_or("unknown").to_string())
}

pub fn date() -> &'static str {
    DATE.get_or_init(|| option_env!("BUILD_DATE").unwrap_or("unknown").to_string())
}

pub fn built_by() -> &'static str {
    BUILT_BY.get_or_init(|| option_env!("BUILT_BY").unwrap_or("unknown").to_string())
}

pub fn info() -> String {
    format!(
        "wow-patcher {} ({}) built on {} by {}",
        version(),
        commit(),
        date(),
        built_by()
    )
}

pub fn detailed_info() -> String {
    format!(
        r#"wow-patcher - World of Warcraft Binary Patcher
Version:      {}
Git Commit:   {}
Build Date:   {}
Built By:     {}
Rust Version: {}
OS/Arch:      {}/{}"#,
        version(),
        commit(),
        date(),
        built_by(),
        option_env!("RUSTC_VERSION").unwrap_or("unknown"),
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

pub fn short() -> &'static str {
    version()
}
