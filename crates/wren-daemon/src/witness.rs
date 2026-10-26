//! Durable authenticated lease arbiter; deliberately independent of either HA member.
use anyhow::{Context, Result};
use clap::Parser;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: std::path::PathBuf,
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = wren_ha::read_private(&args.config).context("reading witness configuration")?;
    wren_ha::serve(config).await
}
