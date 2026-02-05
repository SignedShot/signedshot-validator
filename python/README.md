# SignedShot

Verify SignedShot media authenticity proofs in Python.

[![PyPI](https://img.shields.io/pypi/v/signedshot)](https://pypi.org/project/signedshot/)

## Installation

```bash
pip install signedshot
```

## Quick Start

```python
import signedshot

# Validate from files
result = signedshot.validate_files("photo.sidecar.json", "photo.jpg")

print(result.valid)   # True if all checks pass
print(result.error)   # Error message if validation failed
```

## Usage

### Validate from Files

```python
result = signedshot.validate_files("photo.sidecar.json", "photo.jpg")
```

### Validate from Bytes

```python
with open("photo.sidecar.json") as f:
    sidecar_json = f.read()
with open("photo.jpg", "rb") as f:
    media_bytes = f.read()

result = signedshot.validate(sidecar_json, media_bytes)
```

### Validate with Pre-loaded JWKS

Avoid HTTP calls by providing JWKS directly:

```python
import requests

jwks = requests.get("https://api.signedshot.io/.well-known/jwks.json").text
result = signedshot.validate_with_jwks(sidecar_json, media_bytes, jwks)
```

## Validation Result

```python
result = signedshot.validate_files("photo.sidecar.json", "photo.jpg")

# Overall result
result.valid      # True/False
result.version    # Sidecar format version
result.error      # Error message (if any)

# Capture trust (JWT verification)
trust = result.capture_trust
trust["signature_valid"]   # JWT signature verified
trust["issuer"]            # API that issued the token
trust["publisher_id"]      # Publisher ID
trust["device_id"]         # Device ID
trust["capture_id"]        # Capture session ID
trust["method"]            # "sandbox", "app_check", or "app_attest"
trust["app_id"]            # App bundle ID (if attested)
trust["issued_at"]         # Unix timestamp

# Media integrity (content verification)
integrity = result.media_integrity
integrity["content_hash_valid"]   # SHA-256 hash matches
integrity["signature_valid"]      # ECDSA signature verified
integrity["capture_id_match"]     # Capture IDs match
integrity["content_hash"]         # SHA-256 of media
integrity["captured_at"]          # ISO8601 timestamp

# Export
result.to_dict()   # Convert to dictionary
result.to_json()   # Convert to JSON string
```

## What It Validates

1. **Capture Trust (JWT)**
   - Fetches JWKS from issuer
   - Verifies ES256 signature
   - Extracts attestation claims

2. **Media Integrity**
   - Computes SHA-256 of media
   - Verifies ECDSA signature
   - Confirms capture_id matches

## Links

- [Documentation](https://signedshot.io/docs)
- [GitHub](https://github.com/SignedShot/signedshot-validator)
- [Website](https://signedshot.io)

## License

MIT
