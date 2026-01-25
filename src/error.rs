//! Error types for the SignedShot validator.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Failed to read sidecar file: {0}")]
    SidecarReadError(#[from] std::io::Error),

    #[error("Failed to parse sidecar JSON: {0}")]
    SidecarParseError(#[from] serde_json::Error),

    #[error("Invalid sidecar: {0}")]
    InvalidSidecar(String),

    #[error("Unsupported sidecar version: {0}")]
    UnsupportedVersion(String),
}

pub type Result<T> = std::result::Result<T, ValidationError>;
