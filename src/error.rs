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
