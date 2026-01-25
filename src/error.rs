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

    #[error("Invalid JWT: {0}")]
    InvalidJwt(String),

    #[error("Failed to decode JWT: {0}")]
    JwtDecodeError(String),

    #[error("Failed to fetch JWKS: {0}")]
    JwksFetchError(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Signature verification failed: {0}")]
    SignatureError(String),
}

pub type Result<T> = std::result::Result<T, ValidationError>;
