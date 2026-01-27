//! Sidecar parsing for SignedShot media authenticity proofs.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Result, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTrust {
    pub jwt: String,
}

/// Media integrity proof from the device's Secure Enclave
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaIntegrity {
    /// SHA-256 hash of the media content (hex string, 64 characters)
    pub content_hash: String,
    /// Base64-encoded ECDSA signature of the signed message
    pub signature: String,
    /// Base64-encoded public key (uncompressed EC point, 65 bytes)
    pub public_key: String,
    /// UUID of the capture session (must match JWT capture_id)
    pub capture_id: String,
    /// ISO8601 UTC timestamp of when the media was captured
    pub captured_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub version: String,
    pub capture_trust: CaptureTrust,
    /// Media integrity proof from the device's Secure Enclave
    pub media_integrity: MediaIntegrity,
}

impl Sidecar {
    pub fn from_json(json: &str) -> Result<Self> {
        let sidecar: Sidecar = serde_json::from_str(json)?;
        sidecar.validate()?;
        Ok(sidecar)
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_json(&contents)
    }

    fn validate(&self) -> Result<()> {
        if self.version != "1.0" {
            return Err(ValidationError::UnsupportedVersion(self.version.clone()));
        }

        if self.capture_trust.jwt.is_empty() {
            return Err(ValidationError::InvalidSidecar(
                "capture_trust.jwt is empty".to_string(),
            ));
        }

        let parts: Vec<&str> = self.capture_trust.jwt.split('.').collect();
        if parts.len() != 3 {
            return Err(ValidationError::InvalidSidecar(
                "capture_trust.jwt is not a valid JWT format".to_string(),
            ));
        }

        Ok(())
    }

    pub fn jwt(&self) -> &str {
        &self.capture_trust.jwt
    }

    pub fn media_integrity(&self) -> &MediaIntegrity {
        &self.media_integrity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JWT: &str =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    const VALID_SIDECAR_JSON: &str = r#"{
        "version": "1.0",
        "capture_trust": {
            "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        },
        "media_integrity": {
            "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "signature": "MEUCIQC...",
            "public_key": "BF8lB7BJ5vOldMb...",
            "capture_id": "550e8400-e29b-41d4-a716-446655440000",
            "captured_at": "2026-01-26T15:30:00Z"
        }
    }"#;

    #[test]
    fn parse_valid_sidecar() {
        let sidecar = Sidecar::from_json(VALID_SIDECAR_JSON).unwrap();
        assert_eq!(sidecar.version, "1.0");
        assert!(sidecar.jwt().starts_with("eyJ"));

        let integrity = sidecar.media_integrity();
        assert_eq!(integrity.content_hash.len(), 64);
        assert_eq!(integrity.capture_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(integrity.captured_at, "2026-01-26T15:30:00Z");
    }

    #[test]
    fn reject_unsupported_version() {
        let json = format!(
            r#"{{
                "version": "2.0",
                "capture_trust": {{"jwt": "{}"}},
                "media_integrity": {{
                    "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "signature": "sig",
                    "public_key": "key",
                    "capture_id": "uuid",
                    "captured_at": "2026-01-26T15:30:00Z"
                }}
            }}"#,
            VALID_JWT
        );

        let result = Sidecar::from_json(&json);
        assert!(matches!(
            result,
            Err(ValidationError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn reject_empty_jwt() {
        let json = r#"{
            "version": "1.0",
            "capture_trust": {"jwt": ""},
            "media_integrity": {
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signature": "sig",
                "public_key": "key",
                "capture_id": "uuid",
                "captured_at": "2026-01-26T15:30:00Z"
            }
        }"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::InvalidSidecar(_))));
    }

    #[test]
    fn reject_invalid_jwt_format() {
        let json = r#"{
            "version": "1.0",
            "capture_trust": {"jwt": "not-a-jwt"},
            "media_integrity": {
                "content_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "signature": "sig",
                "public_key": "key",
                "capture_id": "uuid",
                "captured_at": "2026-01-26T15:30:00Z"
            }
        }"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::InvalidSidecar(_))));
    }

    #[test]
    fn reject_missing_capture_trust() {
        let json = r#"{"version": "1.0", "media_integrity": {}}"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::SidecarParseError(_))));
    }

    #[test]
    fn reject_missing_media_integrity() {
        let json = r#"{
            "version": "1.0",
            "capture_trust": {
                "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
            }
        }"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::SidecarParseError(_))));
    }

    #[test]
    fn reject_invalid_json() {
        let json = "not valid json";

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::SidecarParseError(_))));
    }

    #[test]
    fn from_file_nonexistent() {
        let result = Sidecar::from_file(Path::new("/nonexistent/file.json"));
        assert!(matches!(result, Err(ValidationError::SidecarReadError(_))));
    }
}
