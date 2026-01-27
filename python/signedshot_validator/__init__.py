# Re-export from the native module
from signedshot_validator.signedshot_validator import (
    ValidationResult,
    validate,
    validate_files,
)

__all__ = ["ValidationResult", "validate", "validate_files"]
__version__ = "0.1.0"
