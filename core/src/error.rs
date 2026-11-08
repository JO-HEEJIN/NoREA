//! Error type and ErrorCode.
//!
//! Spec: Fable_5_1/docs/CORE-API.md (common section). Messages are English
//! technical text; the UI translates them. Messages never contain secrets,
//! input data values or paths.

use std::fmt;

/// Error category. The UI maps each code to a localized message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadInput,
    NoMarker,
    CanaryExhausted,
    BadEvidence,
    BadSignature,
    BadBlob,
    BadDisclosure,
    BadAnchor,
}

/// noreacore error: a code plus an English technical message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Error { code, message: message.into() }
    }

    pub(crate) fn bad_input(message: impl Into<String>) -> Self {
        Error::new(ErrorCode::BadInput, message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}
