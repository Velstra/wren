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
    let config: wren_ha::WitnessConfig =
        wren_ha::read_private(&args.config).context("reading witness configuration")?;
    if config.members.is_empty() {
        // Kept so an upgraded witness does not black out a working pair, but
        // any host that can reach the port can hold the sessions both members
        // need to renew. Said on every start until it is configured.
        eprintln!(
            "warning: no witness members configured; any source may open sessions. \
             Configure the two member addresses to restrict the witness to them."
        );
    }
    wren_ha::serve(config).await
}
