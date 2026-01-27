//! SignedShot Validator Library
//!
//! Validates SignedShot media authenticity proofs.
//!
//! # Quick Start
//!
//! Use the high-level `validate` function for complete validation:
//!
//! ```no_run
//! use signedshot_validator::{validate, ValidationResult};
//! use std::path::Path;
//!
//! let result = validate(
//!     Path::new("photo.sidecar.json"),
//!     Path::new("photo.jpg"),
//! ).unwrap();
//!
//! if result.valid {
//!     println!("Valid! Publisher: {}", result.capture_trust.publisher_id);
//! } else {
//!     println!("Invalid: {}", result.error.unwrap_or_default());
//! }
//! ```

pub mod error;
pub mod integrity;
pub mod jwt;
pub mod sidecar;
pub mod validate;

pub use error::{Result, ValidationError};
pub use integrity::{
    compute_file_hash, compute_hash, verify_capture_id_match, verify_content_hash,
    verify_media_integrity, verify_signature as verify_media_signature,
};
pub use jwt::{
    fetch_jwks, parse_jwt, verify_signature, CaptureTrustClaims, Jwk, Jwks, JwtHeader, ParsedJwt,
};
pub use sidecar::{CaptureTrust, MediaIntegrity, Sidecar};
pub use validate::{
    validate, validate_from_bytes, CaptureTrustResult, MediaIntegrityResult, ValidationResult,
};
