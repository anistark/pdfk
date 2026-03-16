use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "pdfk",
    version,
    about = "Modern PDF password CLI",
    long_about = "A modern, developer-friendly CLI for managing PDF passwords and encryption.\nFully offline. Never sends data outside your machine."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Encrypt a PDF with a password
    Lock {
        /// Input PDF file
        file: PathBuf,

        /// Password (sets both user & owner password; prompts if omitted)
        #[arg(short, long, group = "password_source", num_args = 0..=1, default_missing_value = "")]
        password: Option<String>,

        /// Read password from stdin
        #[arg(long, group = "password_source")]
        password_stdin: bool,

        /// User password (required to open/view)
        #[arg(short = 'u', long)]
        user_password: Option<String>,

        /// Owner password (controls permissions)
        #[arg(short = 'O', long)]
        owner_password: Option<String>,

        /// Disable printing
        #[arg(long, default_value_t = false)]
        no_print: bool,

        /// Disable copying
        #[arg(long, default_value_t = false)]
        no_copy: bool,

        /// Disable editing
        #[arg(long, default_value_t = false)]
        no_edit: bool,

        /// Output file path
        #[arg(short, long, group = "output_mode")]
        output: Option<PathBuf>,

        /// Modify the file in place
        #[arg(long, group = "output_mode")]
        in_place: bool,
    },

    /// Decrypt a PDF by removing password protection
    Unlock {
        /// Input PDF file
        file: PathBuf,

        /// Password (prompts interactively if value is omitted)
        #[arg(short, long, group = "password_source", num_args = 0..=1, default_missing_value = "")]
        password: Option<String>,

        /// Read password from stdin
        #[arg(long, group = "password_source")]
        password_stdin: bool,

        /// Output file path
        #[arg(short, long, group = "output_mode")]
        output: Option<PathBuf>,

        /// Modify the file in place
        #[arg(long, group = "output_mode")]
        in_place: bool,
    },

    /// Change the password on an encrypted PDF
    ChangePassword {
        /// Input PDF file
        file: PathBuf,

        /// Current password (prompts interactively if value is omitted)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        old: Option<String>,

        /// New password (prompts interactively if value is omitted)
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        new: Option<String>,

        /// Read passwords from stdin (old then new, one per line)
        #[arg(long)]
        password_stdin: bool,

        /// Output file path
        #[arg(short, long, group = "output_mode")]
        output: Option<PathBuf>,

        /// Modify the file in place
        #[arg(long, group = "output_mode")]
        in_place: bool,
    },

    /// Verify a password works without modifying the file
    Check {
        /// Input PDF file
        file: PathBuf,

        /// Password to verify (prompts interactively if value is omitted)
        #[arg(short, long, group = "password_source", num_args = 0..=1, default_missing_value = "")]
        password: Option<String>,

        /// Read password from stdin
        #[arg(long, group = "password_source")]
        password_stdin: bool,
    },
}

pub fn parse() -> Cli {
    Cli::parse()
}
