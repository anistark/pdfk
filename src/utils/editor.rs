use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use log::{debug, info};

/// Programs offered by the interactive menu, best first.
const MENU_CANDIDATES: &[&str] = &[
    "nvim", "vim", "hx", "micro", "nano", "bat", "glow", "less", "more",
];

/// How a program accepts a document on stdin, when it can at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StdinMode {
    /// Reads stdin with no extra argument (`less`, `bat`, …).
    Native,
    /// Needs an explicit `-` argument (`vim -`, `nvim -`).
    Dash,
}

/// Piping avoids writing a decrypted document to disk, so prefer it whenever
/// the target program supports it.
fn stdin_mode(program: &str) -> Option<StdinMode> {
    match program {
        "less" | "more" | "most" | "cat" | "bat" | "batcat" | "glow" => Some(StdinMode::Native),
        "vim" | "nvim" | "vi" | "view" => Some(StdinMode::Dash),
        _ => None,
    }
}

/// Resolve which program to open with.
///
/// Order: explicit flag, `$PDFK_EDITOR`, `$VISUAL`, `$EDITOR`, `$PAGER`, then an
/// interactive menu. The menu is only reachable on a TTY, so scripts and CI get
/// a clear error instead of a hang.
pub fn resolve_editor(explicit: Option<String>) -> Result<String> {
    if let Some(cmd) = explicit {
        let cmd = cmd.trim().to_string();
        if cmd.is_empty() {
            bail!("--editor was given an empty command");
        }
        debug!("editor from --editor: {cmd}");
        return Ok(cmd);
    }

    for var in ["PDFK_EDITOR", "VISUAL", "EDITOR", "PAGER"] {
        if let Ok(val) = std::env::var(var) {
            let val = val.trim().to_string();
            if !val.is_empty() {
                debug!("editor from ${var}: {val}");
                return Ok(val);
            }
        }
    }

    if std::io::stdin().is_terminal() && std::io::stderr().is_terminal() {
        return prompt_for_editor();
    }

    bail!(
        "No editor configured. Set $EDITOR (or $PDFK_EDITOR/$VISUAL/$PAGER), \
         or pass --editor <CMD>"
    )
}

fn prompt_for_editor() -> Result<String> {
    let found: Vec<&str> = MENU_CANDIDATES
        .iter()
        .copied()
        .filter(|p| find_in_path(p).is_some())
        .collect();

    if found.is_empty() {
        bail!(
            "No editor configured and none of the usual ones were found on PATH. \
             Set $EDITOR or pass --editor <CMD>"
        );
    }

    eprintln!("No editor configured. Choose one:");
    for (i, prog) in found.iter().enumerate() {
        eprintln!("  {}) {}", i + 1, prog);
    }
    eprint!("Selection [1-{}]: ", found.len());
    std::io::stderr().flush().ok();

    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("Failed to read selection")?;

    let choice: usize = line
        .trim()
        .parse()
        .with_context(|| format!("Not a valid selection: {}", line.trim()))?;

    found
        .get(choice.wrapping_sub(1))
        .map(|s| s.to_string())
        .with_context(|| format!("Selection out of range: {choice}"))
}

/// Hand `content` to `cmd_line`, preferring the child's stdin over a temp file.
///
/// `encrypted` says whether the content came from an encrypted PDF; spilling
/// that to disk needs `--allow-temp`.
pub fn open_with(
    cmd_line: &str,
    content: &str,
    extension: &str,
    allow_temp: bool,
    encrypted: bool,
) -> Result<()> {
    let mut parts = cmd_line.split_whitespace();
    let program = parts
        .next()
        .with_context(|| format!("Empty editor command: {cmd_line:?}"))?;
    let args: Vec<&str> = parts.collect();

    // stdout gets a trailing newline from `println!`; keep the editor path
    // byte-identical so files don't end up missing their final newline.
    let mut content = content.to_string();
    if !content.ends_with('\n') {
        content.push('\n');
    }
    let content = content.as_str();

    let base = Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(program);

    match stdin_mode(base) {
        Some(mode) => {
            info!("opening with {program} (via stdin)");
            pipe_to_child(program, &args, mode, content)
        }
        None => {
            if encrypted && !allow_temp {
                bail!(
                    "{program} cannot read from stdin, so opening it would write the \
                     decrypted document to a temporary file. Re-run with --allow-temp \
                     to permit that, or use an editor that reads stdin (e.g. less, vim)"
                );
            }
            info!("opening with {program} (via temp file)");
            open_via_temp_file(program, &args, content, extension)
        }
    }
}

fn pipe_to_child(program: &str, args: &[&str], mode: StdinMode, content: &str) -> Result<()> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if mode == StdinMode::Dash {
        cmd.arg("-");
    }

    let mut child = cmd
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("Failed to run {program}"))?;

    // Drop our handle so the child sees EOF; otherwise pagers wait forever.
    {
        let mut stdin = child
            .stdin
            .take()
            .context("Failed to open the editor's stdin")?;
        stdin
            .write_all(content.as_bytes())
            .with_context(|| format!("Failed to write to {program}"))?;
    }

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait for {program}"))?;
    check_status(program, status)
}

fn open_via_temp_file(program: &str, args: &[&str], content: &str, extension: &str) -> Result<()> {
    let file = tempfile::Builder::new()
        .prefix("pdfk-")
        .suffix(extension)
        .tempfile()
        .context("Failed to create a temporary file")?;

    restrict_permissions(file.path())?;

    std::fs::write(file.path(), content)
        .with_context(|| format!("Failed to write {}", file.path().display()))?;

    let status = Command::new(program)
        .args(args)
        .arg(file.path())
        .status()
        .with_context(|| format!("Failed to run {program}"))?;

    // `file` unlinks on drop, including on the error path below.
    check_status(program, status)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to restrict permissions on {}", path.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

fn check_status(program: &str, status: std::process::ExitStatus) -> Result<()> {
    if status.success() {
        return Ok(());
    }
    match status.code() {
        Some(code) => bail!("{program} exited with status {code}"),
        None => bail!("{program} was terminated by a signal"),
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_capable_programs_are_recognized() {
        assert_eq!(stdin_mode("less"), Some(StdinMode::Native));
        assert_eq!(stdin_mode("bat"), Some(StdinMode::Native));
        assert_eq!(stdin_mode("vim"), Some(StdinMode::Dash));
        assert_eq!(stdin_mode("nvim"), Some(StdinMode::Dash));
    }

    #[test]
    fn editors_needing_a_path_are_not_stdin_capable() {
        assert_eq!(stdin_mode("nano"), None);
        assert_eq!(stdin_mode("micro"), None);
        assert_eq!(stdin_mode("hx"), None);
        assert_eq!(stdin_mode("true"), None);
    }

    #[test]
    fn explicit_editor_wins_and_is_trimmed() {
        let got = resolve_editor(Some("  bat -l md  ".to_string())).unwrap();
        assert_eq!(got, "bat -l md");
    }

    #[test]
    fn explicit_empty_editor_is_rejected() {
        assert!(resolve_editor(Some("   ".to_string())).is_err());
    }

    #[test]
    fn find_in_path_locates_a_real_binary() {
        assert!(find_in_path("sh").is_some());
        assert!(find_in_path("pdfk-definitely-not-a-real-binary").is_none());
    }
}
