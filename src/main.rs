mod cli;
mod commands;
mod core;
mod pdf;
mod utils;

use anyhow::Result;
use utils::output::{set_verbosity, Verbosity};

fn main() -> Result<()> {
    let cli = cli::parse();

    if cli.quiet {
        set_verbosity(Verbosity::Quiet);
    } else if cli.verbose {
        set_verbosity(Verbosity::Verbose);
    } else {
        set_verbosity(Verbosity::Normal);
    }

    commands::dispatch(cli)
}
