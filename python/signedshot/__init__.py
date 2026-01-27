# Re-export from the native module
from signedshot.signedshot import (
    ValidationResult,
    validate,
    validate_files,
)

__all__ = ["ValidationResult", "validate", "validate_files"]
__version__ = "0.1.0"
