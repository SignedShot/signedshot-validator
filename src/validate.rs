//! High-level validation API for SignedShot.
//!
//! This module provides a unified validation function that returns
//! structured results suitable for API responses.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Result, ValidationError};
use crate::integrity::{verify_capture_id_match, verify_signature as verify_media_signature};
use crate::jwt::{
    fetch_jwks, parse_jwt, parse_jwks_json, verify_signature as verify_jwt_signature,
    CaptureTrustClaims, Jwks,
};
use crate::sidecar::Sidecar;

/// Result of capture trust (JWT) validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTrustResult {
    /// Whether the JWT signature was verified successfully
    pub signature_valid: bool,
    /// Issuer URL from the JWT
    pub issuer: String,
    /// Publisher ID from the JWT claims
    pub publisher_id: String,
    /// Device ID from the JWT claims
    pub device_id: String,
    /// Capture ID from the JWT claims
    pub capture_id: String,
    /// Attestation method (sandbox, app_check, app_attest)
    pub method: String,
    /// Unix timestamp when the JWT was issued
    pub issued_at: i64,
    /// Key ID used to sign the JWT
    pub key_id: Option<String>,
}

impl CaptureTrustResult {
    fn from_claims(
        claims: &CaptureTrustClaims,
        key_id: Option<String>,
        signature_valid: bool,
    ) -> Self {
        Self {
            signature_valid,
            issuer: claims.iss.clone(),
            publisher_id: claims.publisher_id.clone(),
            device_id: claims.device_id.clone(),
            capture_id: claims.capture_id.clone(),
            method: claims.method.clone(),
            issued_at: claims.iat,
            key_id,
        }
    }
}

/// Result of media integrity validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaIntegrityResult {
    /// Whether the content hash matches the media file
    pub content_hash_valid: bool,
    /// Whether the ECDSA signature is valid
    pub signature_valid: bool,
    /// Whether the capture_id matches between JWT and media_integrity
    pub capture_id_match: bool,
    /// The content hash from the sidecar
    pub content_hash: String,
    /// The capture ID from media_integrity
    pub capture_id: String,
    /// The captured_at timestamp from media_integrity
    pub captured_at: String,
}

/// Complete validation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Overall validation status (true only if all checks pass)
    pub valid: bool,
    /// Sidecar version
    pub version: String,
    /// Capture trust (JWT) validation results
    pub capture_trust: CaptureTrustResult,
    /// Media integrity validation results
    pub media_integrity: MediaIntegrityResult,
    /// Error message if validation failed (None if valid)
    pub error: Option<String>,
}

/// Validate a sidecar file against a media file.
///
/// This performs complete validation:
/// 1. Parse the sidecar JSON
/// 2. Parse and decode the JWT
/// 3. Fetch JWKS from the issuer
/// 4. Verify the JWT signature
/// 5. Verify the content hash matches the media file
/// 6. Verify the media integrity signature
/// 7. Verify the capture_id matches between JWT and media_integrity
///
/// Returns a `ValidationResult` with detailed information about each check.
pub fn validate(sidecar_path: &Path, media_path: &Path) -> Result<ValidationResult> {
    validate_impl(sidecar_path, media_path)
}

/// Validate from sidecar JSON string and media bytes.
///
/// Useful when you have the content in memory rather than files.
pub fn validate_from_bytes(sidecar_json: &str, media_bytes: &[u8]) -> Result<ValidationResult> {
    validate_bytes_impl(sidecar_json, media_bytes, None)
}

/// Validate from sidecar JSON string and media bytes with pre-loaded JWKS.
///
/// Use this when you already have the JWKS available locally, avoiding HTTP fetch.
/// This is useful for the API service that wants to validate using its own keys.
pub fn validate_from_bytes_with_jwks(
    sidecar_json: &str,
    media_bytes: &[u8],
    jwks_json: &str,
) -> Result<ValidationResult> {
    let jwks = parse_jwks_json(jwks_json)?;
    validate_bytes_impl(sidecar_json, media_bytes, Some(jwks))
}

fn validate_impl(sidecar_path: &Path, media_path: &Path) -> Result<ValidationResult> {
    // Parse sidecar
    let sidecar = Sidecar::from_file(sidecar_path)?;

    // Read media file for hash verification
    let media_bytes = std::fs::read(media_path)?;

    validate_sidecar_and_media(&sidecar, &media_bytes, None)
}

fn validate_bytes_impl(
    sidecar_json: &str,
    media_bytes: &[u8],
    jwks: Option<Jwks>,
) -> Result<ValidationResult> {
    // Parse sidecar
    let sidecar = Sidecar::from_json(sidecar_json)?;

    validate_sidecar_and_media(&sidecar, media_bytes, jwks)
}

fn validate_sidecar_and_media(
    sidecar: &Sidecar,
    media_bytes: &[u8],
    jwks: Option<Jwks>,
) -> Result<ValidationResult> {
    let integrity = sidecar.media_integrity();

    // Parse JWT (without signature verification yet)
    let parsed = parse_jwt(sidecar.jwt())?;
    let kid = parsed.header.kid.clone();

    // Track individual check results
    let mut jwt_signature_valid = false;
    let mut content_hash_valid = false;
    let mut media_signature_valid = false;
    let mut capture_id_match = false;
    let mut error_message: Option<String> = None;

    // Verify JWT signature (using provided JWKS or fetching from issuer)
    match verify_jwt_with_jwks(sidecar.jwt(), &parsed.claims.iss, kid.as_deref(), jwks) {
        Ok(()) => jwt_signature_valid = true,
        Err(e) => {
            error_message = Some(format!("JWT verification failed: {}", e));
        }
    }

    // Verify content hash
    let actual_hash = crate::integrity::compute_hash(media_bytes);
    if actual_hash == integrity.content_hash {
        content_hash_valid = true;
    } else if error_message.is_none() {
        error_message = Some(format!(
            "Content hash mismatch: expected {}, got {}",
            integrity.content_hash, actual_hash
        ));
    }

    // Verify media integrity signature
    match verify_media_signature(integrity) {
        Ok(()) => media_signature_valid = true,
        Err(e) => {
            if error_message.is_none() {
                error_message = Some(format!("Media signature verification failed: {}", e));
            }
        }
    }

    // Verify capture_id match
    match verify_capture_id_match(&parsed.claims.capture_id, integrity) {
        Ok(()) => capture_id_match = true,
        Err(e) => {
            if error_message.is_none() {
                error_message = Some(format!("Capture ID mismatch: {}", e));
            }
        }
    }

    // Overall validation passes only if all checks pass
    let valid =
        jwt_signature_valid && content_hash_valid && media_signature_valid && capture_id_match;

    Ok(ValidationResult {
        valid,
        version: sidecar.version.clone(),
        capture_trust: CaptureTrustResult::from_claims(&parsed.claims, kid, jwt_signature_valid),
        media_integrity: MediaIntegrityResult {
            content_hash_valid,
            signature_valid: media_signature_valid,
            capture_id_match,
            content_hash: integrity.content_hash.clone(),
            capture_id: integrity.capture_id.clone(),
            captured_at: integrity.captured_at.clone(),
        },
        error: if valid { None } else { error_message },
    })
}

/// Verify JWT signature using provided JWKS or by fetching from issuer.
fn verify_jwt_with_jwks(
    token: &str,
    issuer: &str,
    kid: Option<&str>,
    jwks: Option<Jwks>,
) -> Result<()> {
    let kid =
        kid.ok_or_else(|| ValidationError::InvalidJwt("JWT missing kid in header".to_string()))?;

    // Use provided JWKS or fetch from issuer
    let jwks = match jwks {
        Some(jwks) => jwks,
        None => fetch_jwks(issuer)?,
    };

    verify_jwt_signature(token, &jwks, kid)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_serialization() {
        let result = ValidationResult {
            valid: true,
            version: "1.0".to_string(),
            capture_trust: CaptureTrustResult {
                signature_valid: true,
                issuer: "https://dev-api.signedshot.io".to_string(),
                publisher_id: "pub-123".to_string(),
                device_id: "dev-456".to_string(),
                capture_id: "cap-789".to_string(),
                method: "sandbox".to_string(),
                issued_at: 1705312200,
                key_id: Some("key-1".to_string()),
            },
            media_integrity: MediaIntegrityResult {
                content_hash_valid: true,
                signature_valid: true,
                capture_id_match: true,
                content_hash: "abc123".to_string(),
                capture_id: "cap-789".to_string(),
                captured_at: "2026-01-26T15:30:00Z".to_string(),
            },
            error: None,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"publisher_id\":\"pub-123\""));
        assert!(json.contains("\"method\":\"sandbox\""));
    }

    #[test]
    fn test_validation_result_with_error() {
        let result = ValidationResult {
            valid: false,
            version: "1.0".to_string(),
            capture_trust: CaptureTrustResult {
                signature_valid: false,
                issuer: "https://dev-api.signedshot.io".to_string(),
                publisher_id: "pub-123".to_string(),
                device_id: "dev-456".to_string(),
                capture_id: "cap-789".to_string(),
                method: "sandbox".to_string(),
                issued_at: 1705312200,
                key_id: None,
            },
            media_integrity: MediaIntegrityResult {
                content_hash_valid: true,
                signature_valid: true,
                capture_id_match: true,
                content_hash: "abc123".to_string(),
                capture_id: "cap-789".to_string(),
                captured_at: "2026-01-26T15:30:00Z".to_string(),
            },
            error: Some("JWT verification failed".to_string()),
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":false"));
        assert!(json.contains("\"error\":\"JWT verification failed\""));
    }
}
