//! Sidecar parsing for SignedShot media authenticity proofs.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Result, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTrust {
    pub jwt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecar {
    pub version: String,
    pub capture_trust: CaptureTrust,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_JWT: &str =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature";

    #[test]
    fn parse_valid_sidecar() {
        let json = r#"{
            "version": "1.0",
            "capture_trust": {
                "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
            }
        }"#;

        let sidecar = Sidecar::from_json(json).unwrap();
        assert_eq!(sidecar.version, "1.0");
        assert!(sidecar.jwt().starts_with("eyJ"));
    }

    #[test]
    fn reject_unsupported_version() {
        let json = format!(
            r#"{{"version": "2.0", "capture_trust": {{"jwt": "{}"}}}}"#,
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
        let json = r#"{"version": "1.0", "capture_trust": {"jwt": ""}}"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::InvalidSidecar(_))));
    }

    #[test]
    fn reject_invalid_jwt_format() {
        let json = r#"{"version": "1.0", "capture_trust": {"jwt": "not-a-jwt"}}"#;

        let result = Sidecar::from_json(json);
        assert!(matches!(result, Err(ValidationError::InvalidSidecar(_))));
    }

    #[test]
    fn reject_missing_capture_trust() {
        let json = r#"{"version": "1.0"}"#;

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
