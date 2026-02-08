use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use signedshot_validator::{parse_jwt, validate, Sidecar};
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
    /// Validate a sidecar file (parse + decode + verify signature + verify media integrity)
    Validate {
        /// Path to the sidecar JSON file
        sidecar: PathBuf,

        /// Path to the media file for content hash verification
        media: PathBuf,

        /// Output result as JSON
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { sidecar } => parse_command(&sidecar),
        Commands::Validate {
            sidecar,
            media,
            json,
        } => validate_command(&sidecar, &media, json),
    }
}

fn parse_command(path: &Path) -> Result<()> {
    println!("Parsing sidecar: {}", path.display());

    match Sidecar::from_file(path) {
        Ok(sidecar) => {
            println!("[OK] Sidecar parsed successfully");
            println!("  Version: {}", sidecar.version);
            println!("  JWT length: {} chars", sidecar.jwt().len());

            let integrity = sidecar.media_integrity();
            println!("  Media Integrity:");
            println!("    Content Hash: {}...", &integrity.content_hash[..16]);
            println!("    Capture ID: {}", integrity.capture_id);
            println!("    Captured At: {}", integrity.captured_at);

            Ok(())
        }
        Err(e) => {
            println!("[FAILED] {}", e);
            Err(e).context("Failed to parse sidecar")
        }
    }
}

fn validate_command(sidecar_path: &Path, media_path: &Path, json_output: bool) -> Result<()> {
    if json_output {
        return validate_json(sidecar_path, media_path);
    }

    println!("Validating sidecar: {}", sidecar_path.display());
    println!("Media file: {}", media_path.display());

    // Parse sidecar first to show progress
    let sidecar = match Sidecar::from_file(sidecar_path) {
        Ok(s) => {
            println!("[OK] Sidecar parsed");
            s
        }
        Err(e) => {
            let err_msg = format!("{}", e);
            if err_msg.contains("valid UTF-8") || err_msg.contains("expected value") {
                let ext = sidecar_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if matches!(ext, "jpg" | "jpeg" | "png" | "heic" | "heif" | "mp4" | "mov") {
                    eprintln!("[FAILED] The sidecar path appears to be a media file, not a JSON sidecar.");
                    eprintln!("         Did you swap the arguments?");
                    eprintln!("         Usage: signedshot validate <sidecar.json> <media>");
                    return Err(anyhow::anyhow!("Arguments appear to be swapped: sidecar path '{}' looks like a media file", sidecar_path.display()));
                }
            }
            println!("[FAILED] Sidecar parsing: {}", e);
            return Err(e).context("Failed to parse sidecar");
        }
    };

    // Parse JWT to get claims for display
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

    let kid = parsed
        .header
        .kid
        .clone()
        .unwrap_or_else(|| "N/A".to_string());
    println!("[..] Fetching JWKS from {}", parsed.claims.iss);

    // Run full validation
    let result = match validate(sidecar_path, media_path) {
        Ok(r) => r,
        Err(e) => {
            println!("[FAILED] Validation error: {}", e);
            return Err(e).context("Validation failed");
        }
    };

    // Display results
    if result.capture_trust.signature_valid {
        println!("[OK] JWT signature verified");
    } else {
        println!("[FAILED] JWT signature verification");
    }

    if result.media_integrity.content_hash_valid {
        println!("[OK] Content hash verified");
    } else {
        println!("[FAILED] Content hash mismatch");
    }

    if result.media_integrity.signature_valid {
        println!("[OK] Media signature verified");
    } else {
        println!("[FAILED] Media signature verification");
    }

    if result.media_integrity.capture_id_match {
        println!("[OK] Capture ID match verified");
    } else {
        println!("[FAILED] Capture ID mismatch");
    }

    let integrity = sidecar.media_integrity();

    println!();
    println!("Claims:");
    println!("  Issuer:       {}", result.capture_trust.issuer);
    println!("  Capture ID:   {}", result.capture_trust.capture_id);
    println!("  Publisher ID: {}", result.capture_trust.publisher_id);
    println!("  Device ID:    {}", result.capture_trust.device_id);
    println!("  Method:       {}", result.capture_trust.method);
    if let Some(ref app_id) = result.capture_trust.app_id {
        println!("  App ID:       {}", app_id);
    }
    println!("  Issued At:    {}", result.capture_trust.issued_at);
    println!("  Key ID:       {}", kid);

    println!();
    println!("Media Integrity:");
    println!("  Content Hash: {}", integrity.content_hash);
    println!("  Capture ID:   {}", integrity.capture_id);
    println!("  Captured At:  {}", integrity.captured_at);
    println!(
        "  Public Key:   {}...",
        &integrity.public_key[..40.min(integrity.public_key.len())]
    );

    println!();
    if result.valid {
        println!("[OK] Validation complete");
        Ok(())
    } else {
        println!(
            "[FAILED] Validation failed: {}",
            result.error.unwrap_or_default()
        );
        Err(anyhow::anyhow!("Validation failed"))
    }
}

fn validate_json(sidecar_path: &Path, media_path: &Path) -> Result<()> {
    let result = validate(sidecar_path, media_path).context("Validation failed")?;

    let json = serde_json::to_string_pretty(&result).context("Failed to serialize result")?;

    println!("{}", json);

    if result.valid {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Validation failed"))
    }
}
