# SignedShot Validator

Validator for SignedShot media authenticity proofs.

## Overview

SignedShot is a media authenticity verification system. This validator checks cryptographic proofs (sidecars) that verify media was captured on a legitimate device.

## Installation

```bash
cargo install signedshot-validator
```

## Usage

```bash
signedshot validate photo.sidecar.json
```

## Development

Run these checks locally before pushing (same as CI):

```bash
cargo fmt --check   # Check formatting
cargo clippy -- -D warnings   # Lint
cargo test   # Run tests
cargo build --release   # Build
```

To fix formatting automatically:

```bash
cargo fmt
```

## License

MIT
