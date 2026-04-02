use colored::Colorize;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

static VERBOSITY: OnceLock<Verbosity> = OnceLock::new();

pub fn set_verbosity(v: Verbosity) {
    VERBOSITY.set(v).ok();
}

pub fn verbosity() -> Verbosity {
    *VERBOSITY.get().unwrap_or(&Verbosity::Normal)
}

pub fn is_quiet() -> bool {
    verbosity() == Verbosity::Quiet
}

pub fn is_verbose() -> bool {
    verbosity() == Verbosity::Verbose
}

pub fn print_success(msg: &str) {
    if !is_quiet() {
        eprintln!("{} {}", "✓".green(), msg);
    }
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red(), msg);
}

pub fn print_warning(msg: &str) {
    if !is_quiet() {
        eprintln!("{} {}", "⚠".yellow(), msg);
    }
}

pub fn print_verbose(msg: &str) {
    if is_verbose() {
        eprintln!("{} {}", "·".dimmed(), msg);
    }
}

pub fn write_stdout(msg: &str) {
    println!("{msg}");
}

pub fn print_status(msg: &str) {
    if !is_quiet() {
        eprintln!("{msg}");
    }
}

pub fn display_path(path: &Path) -> String {
    path.display().to_string()
}
