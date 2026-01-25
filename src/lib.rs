//! SignedShot Validator Library
//!
//! Validates SignedShot media authenticity proofs.

pub mod error;
pub mod jwt;
pub mod sidecar;

pub use error::{Result, ValidationError};
pub use jwt::{parse_jwt, CaptureTrustClaims, JwtHeader, ParsedJwt};
pub use sidecar::{CaptureTrust, Sidecar};
