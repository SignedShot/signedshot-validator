use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use signedshot_validator::Sidecar;
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
    /// Parse a sidecar file without validating the JWT signature
    Parse {
        /// Path to the sidecar JSON file
        sidecar: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Parse { sidecar } => parse_command(&sidecar),
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
