use thiserror::Error;

/// Errors that can occur while opening or reading a CASC storage.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CascError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed {what}: {reason}")]
    Malformed { what: &'static str, reason: String },
    #[error("file not found: {0}")]
    NotFound(String),
    /// The path exists in the storage's catalog, but its content was never
    /// downloaded locally (e.g. assets for locales that aren't installed).
    /// This is a normal state for a partial install, not corruption.
    #[error("file known but not installed locally: {0}")]
    NotInstalled(String),
    #[error("unsupported {what}: {reason}")]
    Unsupported { what: &'static str, reason: String },
    #[error("checksum mismatch in {0}")]
    ChecksumMismatch(&'static str),
}

impl CascError {
    pub(crate) fn malformed(what: &'static str, reason: impl Into<String>) -> Self {
        CascError::Malformed {
            what,
            reason: reason.into(),
        }
    }
}

pub type Result<T, E = CascError> = std::result::Result<T, E>;
