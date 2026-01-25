//! SignedShot Validator Library
//!
//! Validates SignedShot media authenticity proofs.

pub mod error;
pub mod jwt;
pub mod sidecar;

pub use error::{Result, ValidationError};
pub use jwt::{
    fetch_jwks, parse_jwt, verify_signature, CaptureTrustClaims, Jwk, Jwks, JwtHeader, ParsedJwt,
};
pub use sidecar::{CaptureTrust, Sidecar};
