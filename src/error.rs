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

    #[error("Media integrity missing")]
    MediaIntegrityMissing,

    #[error("Content hash mismatch: expected {expected}, got {actual}")]
    ContentHashMismatch { expected: String, actual: String },

    #[error("Media integrity signature verification failed: {0}")]
    MediaIntegritySignatureError(String),

    #[error(
        "Capture ID mismatch: JWT has {jwt_capture_id}, media_integrity has {integrity_capture_id}"
    )]
    CaptureIdMismatch {
        jwt_capture_id: String,
        integrity_capture_id: String,
    },

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
}

pub type Result<T> = std::result::Result<T, ValidationError>;
