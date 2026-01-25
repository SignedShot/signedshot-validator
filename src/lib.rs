//! SignedShot Validator Library
//!
//! Validates SignedShot media authenticity proofs.

pub mod error;
pub mod sidecar;

pub use error::{Result, ValidationError};
pub use sidecar::{CaptureTrust, Sidecar};
