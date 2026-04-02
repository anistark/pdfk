mod cli;
mod commands;
mod core;
mod pdf;
mod utils;

use anyhow::Result;
use utils::output::{init_output, Verbosity};

fn main() -> Result<()> {
    let cli = cli::parse();

    let verbosity = if cli.quiet {
        Verbosity::Quiet
    } else if cli.debug {
        Verbosity::Debug
    } else if cli.verbose {
        Verbosity::Verbose
    } else {
        Verbosity::Normal
    };

    init_output(verbosity);

    commands::dispatch(cli)
}
