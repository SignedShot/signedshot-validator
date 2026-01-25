use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use signedshot_validator::{parse_jwt, Sidecar};
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
    /// Validate a sidecar file (parse sidecar + decode JWT)
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

    match parse_jwt(sidecar.jwt()) {
        Ok(parsed) => {
            println!("[OK] JWT decoded");
            println!();
            println!("Claims:");
            println!("  Issuer:       {}", parsed.claims.iss);
            println!("  Capture ID:   {}", parsed.claims.capture_id);
            println!("  Publisher ID: {}", parsed.claims.publisher_id);
            println!("  Device ID:    {}", parsed.claims.device_id);
            println!("  Method:       {}", parsed.claims.method);
            println!("  Issued At:    {}", parsed.claims.iat);
            if let Some(kid) = &parsed.header.kid {
                println!("  Key ID:       {}", kid);
            }
            println!();
            println!("[OK] Validation complete (signature not verified)");
            Ok(())
        }
        Err(e) => {
            println!("[FAILED] JWT decoding: {}", e);
            Err(e).context("Failed to decode JWT")
        }
    }
}
