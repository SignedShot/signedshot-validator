//! Media integrity verification for SignedShot.

use base64::{engine::general_purpose::STANDARD, Engine};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::error::{Result, ValidationError};
use crate::sidecar::MediaIntegrity;

/// Compute SHA-256 hash of a file and return as lowercase hex string
pub fn compute_file_hash(path: &Path) -> Result<String> {
    let data = std::fs::read(path)?;
    Ok(compute_hash(&data))
}

/// Compute SHA-256 hash of data and return as lowercase hex string
pub fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    hex::encode(result)
}

/// Build the signed message from media integrity components
///
/// Format: `{content_hash}:{capture_id}:{captured_at}`
pub fn build_signed_message(integrity: &MediaIntegrity) -> String {
    format!(
        "{}:{}:{}",
        integrity.content_hash, integrity.capture_id, integrity.captured_at
    )
}

/// Verify the content hash matches the actual media file
pub fn verify_content_hash(integrity: &MediaIntegrity, media_path: &Path) -> Result<()> {
    let actual_hash = compute_file_hash(media_path)?;

    if actual_hash != integrity.content_hash {
        return Err(ValidationError::ContentHashMismatch {
            expected: integrity.content_hash.clone(),
            actual: actual_hash,
        });
    }

    Ok(())
}

/// Verify the ECDSA signature using the embedded public key
pub fn verify_signature(integrity: &MediaIntegrity) -> Result<()> {
    // Decode the public key from base64
    let public_key_bytes = STANDARD
        .decode(&integrity.public_key)
        .map_err(|e| ValidationError::InvalidPublicKey(format!("Base64 decode failed: {}", e)))?;

    // The public key should be in uncompressed format (65 bytes: 0x04 || x || y)
    if public_key_bytes.len() != 65 {
        return Err(ValidationError::InvalidPublicKey(format!(
            "Expected 65 bytes (uncompressed), got {} bytes",
            public_key_bytes.len()
        )));
    }

    if public_key_bytes[0] != 0x04 {
        return Err(ValidationError::InvalidPublicKey(
            "Expected uncompressed point format (0x04 prefix)".to_string(),
        ));
    }

    // Parse the public key
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key_bytes)
        .map_err(|e| ValidationError::InvalidPublicKey(format!("Invalid EC point: {}", e)))?;

    // Decode the signature from base64
    let signature_bytes = STANDARD.decode(&integrity.signature).map_err(|e| {
        ValidationError::MediaIntegritySignatureError(format!(
            "Signature base64 decode failed: {}",
            e
        ))
    })?;

    // Parse the DER-encoded signature
    let signature = Signature::from_der(&signature_bytes).map_err(|e| {
        ValidationError::MediaIntegritySignatureError(format!("Invalid DER signature: {}", e))
    })?;

    // Build the message that was signed
    let message = build_signed_message(integrity);

    // Verify the signature
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|e| {
            ValidationError::MediaIntegritySignatureError(format!(
                "Signature verification failed: {}",
                e
            ))
        })?;

    Ok(())
}

/// Verify that capture_id matches between JWT claims and media_integrity
pub fn verify_capture_id_match(jwt_capture_id: &str, integrity: &MediaIntegrity) -> Result<()> {
    if jwt_capture_id != integrity.capture_id {
        return Err(ValidationError::CaptureIdMismatch {
            jwt_capture_id: jwt_capture_id.to_string(),
            integrity_capture_id: integrity.capture_id.clone(),
        });
    }

    Ok(())
}

/// Full media integrity verification
///
/// This verifies:
/// 1. Content hash matches the media file
/// 2. Signature is valid for the signed message
/// 3. Capture ID matches the JWT (if provided)
pub fn verify_media_integrity(
    integrity: &MediaIntegrity,
    media_path: &Path,
    jwt_capture_id: Option<&str>,
) -> Result<()> {
    // 1. Verify content hash
    verify_content_hash(integrity, media_path)?;

    // 2. Verify signature
    verify_signature(integrity)?;

    // 3. Verify capture_id match (if JWT capture_id provided)
    if let Some(jwt_id) = jwt_capture_id {
        verify_capture_id_match(jwt_id, integrity)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash() {
        // SHA-256 of "hello" is well-known
        let hash = compute_hash(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_compute_hash_empty() {
        // SHA-256 of empty data
        let hash = compute_hash(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_build_signed_message() {
        let integrity = MediaIntegrity {
            content_hash: "abc123".to_string(),
            signature: "sig".to_string(),
            public_key: "key".to_string(),
            capture_id: "uuid-456".to_string(),
            captured_at: "2026-01-26T15:30:00Z".to_string(),
        };

        let message = build_signed_message(&integrity);
        assert_eq!(message, "abc123:uuid-456:2026-01-26T15:30:00Z");
    }

    #[test]
    fn test_verify_capture_id_match_success() {
        let integrity = MediaIntegrity {
            content_hash: "abc".to_string(),
            signature: "sig".to_string(),
            public_key: "key".to_string(),
            capture_id: "same-id".to_string(),
            captured_at: "2026-01-26T15:30:00Z".to_string(),
        };

        let result = verify_capture_id_match("same-id", &integrity);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_capture_id_match_failure() {
        let integrity = MediaIntegrity {
            content_hash: "abc".to_string(),
            signature: "sig".to_string(),
            public_key: "key".to_string(),
            capture_id: "integrity-id".to_string(),
            captured_at: "2026-01-26T15:30:00Z".to_string(),
        };

        let result = verify_capture_id_match("jwt-id", &integrity);
        assert!(matches!(
            result,
            Err(ValidationError::CaptureIdMismatch { .. })
        ));
    }
}
