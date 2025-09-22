use std::collections::HashMap;
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    FileOperationError,
    ValidationError,
    PatchingError,
    PlatformError,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCategory::FileOperationError => write!(f, "File Operation"),
            ErrorCategory::ValidationError => write!(f, "Validation"),
            ErrorCategory::PatchingError => write!(f, "Patching"),
            ErrorCategory::PlatformError => write!(f, "Platform"),
        }
    }
}

#[derive(Debug)]
pub struct WowPatcherError {
    pub category: ErrorCategory,
    pub message: String,
    pub cause: Option<Box<dyn Error + Send + Sync>>,
    pub context: HashMap<String, Box<dyn std::any::Any + Send + Sync>>,
}

impl WowPatcherError {
    pub fn new(category: ErrorCategory, message: impl Into<String>) -> Self {
        Self {
            category,
            message: message.into(),
            cause: None,
            context: HashMap::new(),
        }
    }

    pub fn wrap(
        category: ErrorCategory,
        message: impl Into<String>,
        cause: impl Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            category,
            message: message.into(),
            cause: Some(Box::new(cause)),
            context: HashMap::new(),
        }
    }

    pub fn with_context(
        mut self,
        key: impl Into<String>,
        value: impl std::any::Any + Send + Sync + 'static,
    ) -> Self {
        self.context.insert(key.into(), Box::new(value));
        self
    }

    pub fn get_context(&self, key: &str) -> Option<&(dyn std::any::Any + Send + Sync)> {
        self.context.get(key).map(|v| v.as_ref())
    }
}

impl fmt::Display for WowPatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.category, self.message)?;
        if let Some(cause) = &self.cause {
            write!(f, ": {}", cause)?;
        }
        Ok(())
    }
}

impl Error for WowPatcherError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

pub fn new_file_error(
    message: impl Into<String>,
    cause: impl Error + Send + Sync + 'static,
    file_path: impl Into<String>,
) -> WowPatcherError {
    WowPatcherError::wrap(ErrorCategory::FileOperationError, message, cause)
        .with_context("file_path", file_path.into())
        .with_context("platform", std::env::consts::OS.to_string())
}

pub fn new_validation_error(
    message: impl Into<String>,
    field: impl Into<String>,
    value: impl std::any::Any + Send + Sync + 'static,
) -> WowPatcherError {
    WowPatcherError::new(ErrorCategory::ValidationError, message)
        .with_context("field", field.into())
        .with_context("value", value)
}

pub fn new_patching_error(
    message: impl Into<String>,
    cause: impl Error + Send + Sync + 'static,
    pattern: impl Into<String>,
) -> WowPatcherError {
    WowPatcherError::wrap(ErrorCategory::PatchingError, message, cause)
        .with_context("pattern", pattern.into())
        .with_context(
            "suggestion",
            "This may be an unsupported WoW version or a pre-patched executable".to_string(),
        )
}

pub fn new_platform_error(
    message: impl Into<String>,
    cause: impl Error + Send + Sync + 'static,
    operation: impl Into<String>,
) -> WowPatcherError {
    WowPatcherError::wrap(ErrorCategory::PlatformError, message, cause)
        .with_context("operation", operation.into())
        .with_context("platform", std::env::consts::OS.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_category_string() {
        assert_eq!(
            ErrorCategory::FileOperationError.to_string(),
            "File Operation"
        );
        assert_eq!(ErrorCategory::ValidationError.to_string(), "Validation");
        assert_eq!(ErrorCategory::PatchingError.to_string(), "Patching");
        assert_eq!(ErrorCategory::PlatformError.to_string(), "Platform");
    }

    #[test]
    fn test_new() {
        let err = WowPatcherError::new(ErrorCategory::ValidationError, "test error message");

        assert_eq!(err.category, ErrorCategory::ValidationError);
        assert_eq!(err.message, "test error message");
        assert!(err.cause.is_none());
        assert!(err.context.is_empty());
    }

    #[test]
    fn test_wrap() {
        let base_err = std::io::Error::new(std::io::ErrorKind::NotFound, "base error");
        let wrapped = WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "wrapped message",
            base_err,
        );

        assert_eq!(wrapped.category, ErrorCategory::FileOperationError);
        assert_eq!(wrapped.message, "wrapped message");
        assert!(wrapped.cause.is_some());
    }

    #[test]
    fn test_error_display() {
        let err = WowPatcherError::new(ErrorCategory::ValidationError, "validation failed");
        assert_eq!(err.to_string(), "[Validation] validation failed");

        let base_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err_with_cause = WowPatcherError::wrap(
            ErrorCategory::FileOperationError,
            "file operation failed",
            base_err,
        );
        assert_eq!(
            err_with_cause.to_string(),
            "[File Operation] file operation failed: permission denied"
        );
    }

    #[test]
    fn test_with_context() {
        let err = WowPatcherError::new(ErrorCategory::ValidationError, "test error")
            .with_context("field", "username".to_string())
            .with_context("value", "test123".to_string())
            .with_context("maxLength", 10usize);

        let field = err
            .get_context("field")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(field, Some(&"username".to_string()));

        let value = err
            .get_context("value")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(value, Some(&"test123".to_string()));

        let max_length = err
            .get_context("maxLength")
            .and_then(|v| v.downcast_ref::<usize>());
        assert_eq!(max_length, Some(&10));

        assert!(err.get_context("missing").is_none());
    }

    #[test]
    fn test_new_file_error() {
        let base_err =
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let file_err = new_file_error("failed to read file", base_err, "/path/to/file");

        assert_eq!(file_err.category, ErrorCategory::FileOperationError);
        assert_eq!(file_err.message, "failed to read file");

        let file_path = file_err
            .get_context("file_path")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(file_path, Some(&"/path/to/file".to_string()));

        let platform = file_err
            .get_context("platform")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(platform, Some(&std::env::consts::OS.to_string()));
    }

    #[test]
    fn test_new_validation_error() {
        let val_err = new_validation_error("invalid input", "age", -5i32);

        assert_eq!(val_err.category, ErrorCategory::ValidationError);

        let field = val_err
            .get_context("field")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(field, Some(&"age".to_string()));

        let value = val_err
            .get_context("value")
            .and_then(|v| v.downcast_ref::<i32>());
        assert_eq!(value, Some(&-5));
    }

    #[test]
    fn test_new_patching_error() {
        let base_err = std::io::Error::new(std::io::ErrorKind::NotFound, "pattern not found");
        let patch_err = new_patching_error("failed to patch", base_err, "portal_pattern");

        assert_eq!(patch_err.category, ErrorCategory::PatchingError);

        let pattern = patch_err
            .get_context("pattern")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(pattern, Some(&"portal_pattern".to_string()));

        let suggestion = patch_err
            .get_context("suggestion")
            .and_then(|v| v.downcast_ref::<String>());
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().contains("unsupported WoW version"));
    }

    #[test]
    fn test_new_platform_error() {
        let base_err = std::io::Error::new(std::io::ErrorKind::Other, "command failed");
        let plat_err = new_platform_error("codesign failed", base_err, "remove_signature");

        assert_eq!(plat_err.category, ErrorCategory::PlatformError);

        let operation = plat_err
            .get_context("operation")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(operation, Some(&"remove_signature".to_string()));

        let platform = plat_err
            .get_context("platform")
            .and_then(|v| v.downcast_ref::<String>());
        assert_eq!(platform, Some(&std::env::consts::OS.to_string()));
    }

    #[test]
    fn test_error_chaining() {
        let root_err = std::io::Error::new(std::io::ErrorKind::NotFound, "root cause");
        let level1 =
            WowPatcherError::wrap(ErrorCategory::FileOperationError, "file error", root_err);
        let level2 = WowPatcherError::wrap(
            ErrorCategory::ValidationError,
            "validation error",
            std::io::Error::new(std::io::ErrorKind::Other, level1.to_string()),
        );

        let err_msg = level2.to_string();
        assert!(err_msg.contains("Validation"));
        assert!(err_msg.contains("validation error"));
    }
}
