use anyhow::Result;
use clap::CommandFactory;
use clap_mangen::Man;
use std::path::{Path, PathBuf};

use crate::cli::Cli;

pub fn execute(out_dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&out_dir)?;
    let cmd = Cli::command();
    generate_pages(&cmd, "", &out_dir)?;
    Ok(())
}

fn generate_pages(cmd: &clap::Command, parent: &str, out_dir: &Path) -> Result<()> {
    let name = if parent.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{}-{}", parent, cmd.get_name())
    };

    let static_name: &'static str = Box::leak(name.into_boxed_str());
    let renamed = cmd.clone().name(static_name);
    let mut buf = Vec::new();
    Man::new(renamed.clone()).render(&mut buf)?;
    std::fs::write(out_dir.join(format!("{static_name}.1")), &buf)?;

    for sub in renamed.get_subcommands() {
        if !sub.is_hide_set() {
            generate_pages(sub, static_name, out_dir)?;
        }
    }

    Ok(())
}
