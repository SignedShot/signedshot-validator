//! Python bindings for the SignedShot validator.
//!
//! This module provides Python-accessible functions and classes
//! for validating SignedShot media authenticity proofs.

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::validate::{
    validate_from_bytes, validate_from_bytes_with_jwks, ValidationResult as RustValidationResult,
};

/// Python-accessible validation result
#[pyclass(name = "ValidationResult")]
#[derive(Clone)]
pub struct PyValidationResult {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub version: String,
    #[pyo3(get)]
    pub error: Option<String>,
    inner: RustValidationResult,
}

#[pymethods]
impl PyValidationResult {
    /// Get the capture trust information as a dictionary
    #[getter]
    fn capture_trust<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        dict.set_item("signature_valid", self.inner.capture_trust.signature_valid)?;
        dict.set_item("issuer", &self.inner.capture_trust.issuer)?;
        dict.set_item("publisher_id", &self.inner.capture_trust.publisher_id)?;
        dict.set_item("device_id", &self.inner.capture_trust.device_id)?;
        dict.set_item("capture_id", &self.inner.capture_trust.capture_id)?;
        dict.set_item("method", &self.inner.capture_trust.method)?;
        dict.set_item("issued_at", self.inner.capture_trust.issued_at)?;
        dict.set_item("key_id", &self.inner.capture_trust.key_id)?;
        Ok(dict)
    }

    /// Get the media integrity information as a dictionary
    #[getter]
    fn media_integrity<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        dict.set_item(
            "content_hash_valid",
            self.inner.media_integrity.content_hash_valid,
        )?;
        dict.set_item(
            "signature_valid",
            self.inner.media_integrity.signature_valid,
        )?;
        dict.set_item(
            "capture_id_match",
            self.inner.media_integrity.capture_id_match,
        )?;
        dict.set_item("content_hash", &self.inner.media_integrity.content_hash)?;
        dict.set_item("capture_id", &self.inner.media_integrity.capture_id)?;
        dict.set_item("captured_at", &self.inner.media_integrity.captured_at)?;
        Ok(dict)
    }

    /// Convert to a dictionary
    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new_bound(py);
        dict.set_item("valid", self.valid)?;
        dict.set_item("version", &self.version)?;
        dict.set_item("capture_trust", self.capture_trust(py)?)?;
        dict.set_item("media_integrity", self.media_integrity(py)?)?;
        dict.set_item("error", &self.error)?;
        Ok(dict)
    }

    /// Convert to JSON string
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    /// Convert to pretty-printed JSON string
    fn to_json_pretty(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.inner)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
    }

    fn __repr__(&self) -> String {
        format!(
            "ValidationResult(valid={}, version='{}', method='{}')",
            self.valid, self.version, self.inner.capture_trust.method
        )
    }

    fn __str__(&self) -> String {
        if self.valid {
            format!(
                "Valid SignedShot proof (publisher={}, method={})",
                self.inner.capture_trust.publisher_id, self.inner.capture_trust.method
            )
        } else {
            format!(
                "Invalid SignedShot proof: {}",
                self.error.as_deref().unwrap_or("unknown error")
            )
        }
    }
}

impl From<RustValidationResult> for PyValidationResult {
    fn from(result: RustValidationResult) -> Self {
        PyValidationResult {
            valid: result.valid,
            version: result.version.clone(),
            error: result.error.clone(),
            inner: result,
        }
    }
}

/// Validate a SignedShot sidecar against media content.
///
/// Args:
///     sidecar_json: The sidecar JSON as a string
///     media_bytes: The media file content as bytes
///
/// Returns:
///     ValidationResult: The validation result with detailed information
///
/// Raises:
///     ValueError: If the sidecar cannot be parsed
///
/// Example:
///     ```python
///     import signedshot
///
///     with open("photo.sidecar.json") as f:
///         sidecar_json = f.read()
///     with open("photo.jpg", "rb") as f:
///         media_bytes = f.read()
///
///     result = signedshot.validate(sidecar_json, media_bytes)
///     if result.valid:
///         print(f"Valid! Publisher: {result.capture_trust['publisher_id']}")
///     else:
///         print(f"Invalid: {result.error}")
///     ```
#[pyfunction]
fn validate(sidecar_json: &str, media_bytes: &[u8]) -> PyResult<PyValidationResult> {
    validate_from_bytes(sidecar_json, media_bytes)
        .map(PyValidationResult::from)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

/// Validate a SignedShot sidecar against media content using pre-loaded JWKS.
///
/// Use this when you already have the JWKS available locally, avoiding HTTP fetch.
/// This is useful for API services that want to validate using their own keys.
///
/// Args:
///     sidecar_json: The sidecar JSON as a string
///     media_bytes: The media file content as bytes
///     jwks_json: The JWKS JSON as a string (from /.well-known/jwks.json)
///
/// Returns:
///     ValidationResult: The validation result with detailed information
///
/// Raises:
///     ValueError: If the sidecar or JWKS cannot be parsed
///
/// Example:
///     ```python
///     import signedshot
///
///     # Get JWKS from your service's keys
///     jwks_json = '{"keys": [...]}'
///
///     with open("photo.sidecar.json") as f:
///         sidecar_json = f.read()
///     with open("photo.jpg", "rb") as f:
///         media_bytes = f.read()
///
///     result = signedshot.validate_with_jwks(sidecar_json, media_bytes, jwks_json)
///     if result.valid:
///         print(f"Valid! Publisher: {result.capture_trust['publisher_id']}")
///     else:
///         print(f"Invalid: {result.error}")
///     ```
#[pyfunction]
fn validate_with_jwks(
    sidecar_json: &str,
    media_bytes: &[u8],
    jwks_json: &str,
) -> PyResult<PyValidationResult> {
    validate_from_bytes_with_jwks(sidecar_json, media_bytes, jwks_json)
        .map(PyValidationResult::from)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

/// Validate a SignedShot sidecar from file paths.
///
/// Args:
///     sidecar_path: Path to the sidecar JSON file
///     media_path: Path to the media file
///
/// Returns:
///     ValidationResult: The validation result with detailed information
///
/// Raises:
///     ValueError: If the files cannot be read or parsed
///     FileNotFoundError: If the files do not exist
///
/// Example:
///     ```python
///     import signedshot
///
///     result = signedshot.validate_files("photo.sidecar.json", "photo.jpg")
///     print(result)
///     ```
#[pyfunction]
fn validate_files(sidecar_path: &str, media_path: &str) -> PyResult<PyValidationResult> {
    use std::path::Path;

    let sidecar_path = Path::new(sidecar_path);
    let media_path = Path::new(media_path);

    if !sidecar_path.exists() {
        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            format!("Sidecar file not found: {}", sidecar_path.display()),
        ));
    }

    if !media_path.exists() {
        return Err(PyErr::new::<pyo3::exceptions::PyFileNotFoundError, _>(
            format!("Media file not found: {}", media_path.display()),
        ));
    }

    crate::validate::validate(sidecar_path, media_path)
        .map(PyValidationResult::from)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))
}

/// SignedShot Validator Python Module
///
/// Validate SignedShot media authenticity proofs.
///
/// Functions:
///     validate(sidecar_json, media_bytes) -> ValidationResult
///     validate_files(sidecar_path, media_path) -> ValidationResult
///
/// Example:
///     ```python
///     import signedshot
///
///     # From file paths
///     result = signedshot.validate_files("photo.sidecar.json", "photo.jpg")
///
///     # From content
///     result = signedshot.validate(sidecar_json, media_bytes)
///
///     if result.valid:
///         print(f"Publisher: {result.capture_trust['publisher_id']}")
///         print(f"Method: {result.capture_trust['method']}")
///     ```
#[pymodule]
fn signedshot(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyValidationResult>()?;
    m.add_function(wrap_pyfunction!(validate, m)?)?;
    m.add_function(wrap_pyfunction!(validate_with_jwks, m)?)?;
    m.add_function(wrap_pyfunction!(validate_files, m)?)?;
    Ok(())
}
