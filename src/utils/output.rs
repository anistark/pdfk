use std::path::Path;

pub fn print_success(msg: &str) {
    eprintln!("✓ {msg}");
}

pub fn print_error(msg: &str) {
    eprintln!("✗ {msg}");
}

pub fn display_path(path: &Path) -> String {
    path.display().to_string()
}
