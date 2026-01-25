//! JWT parsing for SignedShot capture trust tokens.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::error::{Result, ValidationError};

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    pub kid: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtHeader {
    pub alg: String,
    pub typ: Option<String>,
    pub kid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureTrustClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub iat: i64,
    pub capture_id: String,
    pub publisher_id: String,
    pub device_id: String,
    pub method: String,
}

#[derive(Debug, Clone)]
pub struct ParsedJwt {
    pub header: JwtHeader,
    pub claims: CaptureTrustClaims,
    pub signature: String,
}

pub fn parse_jwt(token: &str) -> Result<ParsedJwt> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ValidationError::InvalidJwt(
            "JWT must have 3 parts separated by dots".to_string(),
        ));
    }

    let header = decode_part::<JwtHeader>(parts[0], "header")?;
    let claims = decode_part::<CaptureTrustClaims>(parts[1], "claims")?;
    let signature = parts[2].to_string();

    validate_header(&header)?;
    validate_claims(&claims)?;

    Ok(ParsedJwt {
        header,
        claims,
        signature,
    })
}

fn decode_part<T: for<'de> Deserialize<'de>>(encoded: &str, part_name: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|e| {
        ValidationError::JwtDecodeError(format!("Failed to decode {}: {}", part_name, e))
    })?;

    serde_json::from_slice(&bytes).map_err(|e| {
        ValidationError::JwtDecodeError(format!("Failed to parse {}: {}", part_name, e))
    })
}

fn validate_header(header: &JwtHeader) -> Result<()> {
    if header.alg != "ES256" {
        return Err(ValidationError::InvalidJwt(format!(
            "Expected algorithm ES256, got {}",
            header.alg
        )));
    }
    Ok(())
}

fn validate_claims(claims: &CaptureTrustClaims) -> Result<()> {
    if claims.aud != "signedshot" {
        return Err(ValidationError::InvalidJwt(format!(
            "Expected audience 'signedshot', got '{}'",
            claims.aud
        )));
    }

    let valid_methods = ["sandbox", "app_check", "app_attest"];
    if !valid_methods.contains(&claims.method.as_str()) {
        return Err(ValidationError::InvalidJwt(format!(
            "Invalid method '{}', expected one of: {:?}",
            claims.method, valid_methods
        )));
    }

    Ok(())
}

pub fn fetch_jwks(issuer: &str) -> Result<Jwks> {
    let url = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));

    let response = reqwest::blocking::get(&url)
        .map_err(|e| ValidationError::JwksFetchError(format!("HTTP request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(ValidationError::JwksFetchError(format!(
            "HTTP {} from {}",
            response.status(),
            url
        )));
    }

    response
        .json::<Jwks>()
        .map_err(|e| ValidationError::JwksFetchError(format!("Failed to parse JWKS: {}", e)))
}

pub fn verify_signature(token: &str, jwks: &Jwks, kid: &str) -> Result<()> {
    let jwk = jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ValidationError::KeyNotFound(kid.to_string()))?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.x)
        .map_err(|e| ValidationError::SignatureError(format!("Invalid x coordinate: {}", e)))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&jwk.y)
        .map_err(|e| ValidationError::SignatureError(format!("Invalid y coordinate: {}", e)))?;

    let mut public_key = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    public_key.push(0x04);
    public_key.extend_from_slice(&x_bytes);
    public_key.extend_from_slice(&y_bytes);

    let decoding_key = DecodingKey::from_ec_der(&public_key);

    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&["signedshot"]);
    validation.validate_exp = false;
    validation.set_required_spec_claims::<&str>(&[]);

    decode::<CaptureTrustClaims>(token, &decoding_key, &validation)
        .map_err(|e| ValidationError::SignatureError(format!("{}", e)))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(header: &str, payload: &str) -> String {
        let h = URL_SAFE_NO_PAD.encode(header);
        let p = URL_SAFE_NO_PAD.encode(payload);
        format!("{}.{}.fake-signature", h, p)
    }

    #[test]
    fn parse_valid_jwt() {
        let header = r#"{"alg":"ES256","typ":"JWT","kid":"test-key"}"#;
        let payload = r#"{"iss":"https://dev-api.signedshot.io","aud":"signedshot","sub":"capture-service","iat":1705312200,"capture_id":"123","publisher_id":"456","device_id":"789","method":"sandbox"}"#;
        let token = make_jwt(header, payload);

        let parsed = parse_jwt(&token).unwrap();
        assert_eq!(parsed.header.alg, "ES256");
        assert_eq!(parsed.claims.capture_id, "123");
        assert_eq!(parsed.claims.method, "sandbox");
    }

    #[test]
    fn reject_invalid_algorithm() {
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload = r#"{"iss":"https://dev-api.signedshot.io","aud":"signedshot","sub":"capture-service","iat":1705312200,"capture_id":"123","publisher_id":"456","device_id":"789","method":"sandbox"}"#;
        let token = make_jwt(header, payload);

        let result = parse_jwt(&token);
        assert!(matches!(result, Err(ValidationError::InvalidJwt(_))));
    }

    #[test]
    fn reject_invalid_audience() {
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = r#"{"iss":"https://example.com","aud":"wrong","sub":"capture-service","iat":1705312200,"capture_id":"123","publisher_id":"456","device_id":"789","method":"sandbox"}"#;
        let token = make_jwt(header, payload);

        let result = parse_jwt(&token);
        assert!(matches!(result, Err(ValidationError::InvalidJwt(_))));
    }

    #[test]
    fn reject_invalid_method() {
        let header = r#"{"alg":"ES256","typ":"JWT"}"#;
        let payload = r#"{"iss":"https://dev-api.signedshot.io","aud":"signedshot","sub":"capture-service","iat":1705312200,"capture_id":"123","publisher_id":"456","device_id":"789","method":"invalid"}"#;
        let token = make_jwt(header, payload);

        let result = parse_jwt(&token);
        assert!(matches!(result, Err(ValidationError::InvalidJwt(_))));
    }

    #[test]
    fn reject_malformed_jwt() {
        let result = parse_jwt("not.a.valid.jwt");
        assert!(matches!(result, Err(ValidationError::InvalidJwt(_))));
    }

    #[test]
    fn reject_invalid_base64() {
        let result = parse_jwt("!!!.@@@.###");
        assert!(matches!(result, Err(ValidationError::JwtDecodeError(_))));
    }
}
