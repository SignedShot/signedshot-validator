use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use signedshot_validator::{fetch_jwks, parse_jwt, verify_signature, Sidecar};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "signedshot")]
#[command(about = "Validate SignedShot media authenticity proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse a sidecar file without validating the JWT
    Parse {
        /// Path to the sidecar JSON file
        sidecar: PathBuf,
    },
    /// Validate a sidecar file (parse + decode + verify signature)
    Validate {
        /// Path to the sidecar JSON file
        sidecar: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { sidecar } => parse_command(&sidecar),
        Commands::Validate { sidecar } => validate_command(&sidecar),
    }
}

fn parse_command(path: &Path) -> Result<()> {
    println!("Parsing sidecar: {}", path.display());

    match Sidecar::from_file(path) {
        Ok(sidecar) => {
            println!("[OK] Sidecar parsed successfully");
            println!("  Version: {}", sidecar.version);
            println!("  JWT length: {} chars", sidecar.jwt().len());
            Ok(())
        }
        Err(e) => {
            println!("[FAILED] {}", e);
            Err(e).context("Failed to parse sidecar")
        }
    }
}

fn validate_command(path: &Path) -> Result<()> {
    println!("Validating sidecar: {}", path.display());

    let sidecar = match Sidecar::from_file(path) {
        Ok(s) => {
            println!("[OK] Sidecar parsed");
            s
        }
        Err(e) => {
            println!("[FAILED] Sidecar parsing: {}", e);
            return Err(e).context("Failed to parse sidecar");
        }
    };

    let parsed = match parse_jwt(sidecar.jwt()) {
        Ok(p) => {
            println!("[OK] JWT decoded");
            p
        }
        Err(e) => {
            println!("[FAILED] JWT decoding: {}", e);
            return Err(e).context("Failed to decode JWT");
        }
    };

    let kid = match &parsed.header.kid {
        Some(k) => k.clone(),
        None => {
            println!("[FAILED] JWT missing kid in header");
            return Err(anyhow::anyhow!("JWT missing kid in header"));
        }
    };

    println!("[..] Fetching JWKS from {}", parsed.claims.iss);
    let jwks = match fetch_jwks(&parsed.claims.iss) {
        Ok(j) => {
            println!("[OK] JWKS fetched ({} keys)", j.keys.len());
            j
        }
        Err(e) => {
            println!("[FAILED] JWKS fetch: {}", e);
            return Err(e).context("Failed to fetch JWKS");
        }
    };

    match verify_signature(sidecar.jwt(), &jwks, &kid) {
        Ok(()) => {
            println!("[OK] Signature verified");
        }
        Err(e) => {
            println!("[FAILED] Signature verification: {}", e);
            return Err(e).context("Signature verification failed");
        }
    }

    println!();
    println!("Claims:");
    println!("  Issuer:       {}", parsed.claims.iss);
    println!("  Capture ID:   {}", parsed.claims.capture_id);
    println!("  Publisher ID: {}", parsed.claims.publisher_id);
    println!("  Device ID:    {}", parsed.claims.device_id);
    println!("  Method:       {}", parsed.claims.method);
    println!("  Issued At:    {}", parsed.claims.iat);
    println!("  Key ID:       {}", kid);
    println!();
    println!("[OK] Validation complete");

    Ok(())
}
