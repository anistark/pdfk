mod cli;
mod commands;
mod core;
mod pdf;
mod utils;

use anyhow::Result;

fn main() -> Result<()> {
    let cli = cli::parse();
    commands::dispatch(cli)
}
