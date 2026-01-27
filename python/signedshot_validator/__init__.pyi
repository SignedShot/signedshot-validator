"""Type stubs for signedshot_validator."""

from typing import Optional, Dict, Any

class ValidationResult:
    """Result of validating a SignedShot sidecar."""

    valid: bool
    """Whether the validation passed all checks."""

    version: str
    """The sidecar version."""

    error: Optional[str]
    """Error message if validation failed, None if valid."""

    @property
    def capture_trust(self) -> Dict[str, Any]:
        """Get capture trust (JWT) information.

        Returns:
            Dict with keys:
                - signature_valid: bool
                - issuer: str
                - publisher_id: str
                - device_id: str
                - capture_id: str
                - method: str (sandbox, app_check, or app_attest)
                - issued_at: int (Unix timestamp)
                - key_id: Optional[str]
        """
        ...

    @property
    def media_integrity(self) -> Dict[str, Any]:
        """Get media integrity information.

        Returns:
            Dict with keys:
                - content_hash_valid: bool
                - signature_valid: bool
                - capture_id_match: bool
                - content_hash: str
                - capture_id: str
                - captured_at: str (ISO8601)
        """
        ...

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        ...

    def to_json(self) -> str:
        """Convert to JSON string."""
        ...

    def to_json_pretty(self) -> str:
        """Convert to pretty-printed JSON string."""
        ...

def validate(sidecar_json: str, media_bytes: bytes) -> ValidationResult:
    """Validate a SignedShot sidecar against media content.

    Args:
        sidecar_json: The sidecar JSON as a string
        media_bytes: The media file content as bytes

    Returns:
        ValidationResult with detailed information about the validation

    Raises:
        ValueError: If the sidecar cannot be parsed

    Example:
        >>> with open("photo.sidecar.json") as f:
        ...     sidecar_json = f.read()
        >>> with open("photo.jpg", "rb") as f:
        ...     media_bytes = f.read()
        >>> result = validate(sidecar_json, media_bytes)
        >>> if result.valid:
        ...     print(f"Publisher: {result.capture_trust['publisher_id']}")
    """
    ...

def validate_files(sidecar_path: str, media_path: str) -> ValidationResult:
    """Validate a SignedShot sidecar from file paths.

    Args:
        sidecar_path: Path to the sidecar JSON file
        media_path: Path to the media file

    Returns:
        ValidationResult with detailed information about the validation

    Raises:
        ValueError: If the files cannot be read or parsed
        FileNotFoundError: If the files do not exist

    Example:
        >>> result = validate_files("photo.sidecar.json", "photo.jpg")
        >>> print(result)
    """
    ...
