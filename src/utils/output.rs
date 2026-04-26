use colored::Colorize;
use std::io::Write;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
    Debug,
}

static VERBOSITY: OnceLock<Verbosity> = OnceLock::new();

pub fn init_output(v: Verbosity) {
    VERBOSITY.set(v).ok();

    let log_level = match v {
        Verbosity::Debug => log::LevelFilter::Debug,
        Verbosity::Verbose => log::LevelFilter::Info,
        Verbosity::Normal => log::LevelFilter::Warn,
        Verbosity::Quiet => log::LevelFilter::Off,
    };

    env_logger::Builder::new()
        .filter_level(log_level)
        .format(|buf, record| {
            let prefix = match record.level() {
                log::Level::Debug => "dbg".dimmed().to_string(),
                log::Level::Info => "·".dimmed().to_string(),
                log::Level::Warn => "⚠".yellow().to_string(),
                log::Level::Error => "✗".red().to_string(),
                log::Level::Trace => "trc".dimmed().to_string(),
            };
            writeln!(buf, "{} {}", prefix, record.args())
        })
        .init();
}

pub fn is_quiet() -> bool {
    *VERBOSITY.get().unwrap_or(&Verbosity::Normal) <= Verbosity::Quiet
}

pub fn print_success(msg: &str) {
    if !is_quiet() {
        eprintln!("{} {}", "✓".green(), msg);
    }
}

pub fn print_error(msg: &str) {
    eprintln!("{} {}", "✗".red(), msg);
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
