//! SignedShot Validator Library
//!
//! Validates SignedShot media authenticity proofs.

pub mod error;
pub mod integrity;
pub mod jwt;
pub mod sidecar;

pub use error::{Result, ValidationError};
pub use integrity::{
    compute_file_hash, compute_hash, verify_capture_id_match, verify_content_hash,
    verify_media_integrity, verify_signature as verify_media_signature,
};
pub use jwt::{
    fetch_jwks, parse_jwt, verify_signature, CaptureTrustClaims, Jwk, Jwks, JwtHeader, ParsedJwt,
};
pub use sidecar::{CaptureTrust, MediaIntegrity, Sidecar};
