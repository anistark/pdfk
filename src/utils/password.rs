use anyhow::{bail, Result};
use std::io::{self, BufRead};

/// Read a single password from stdin
pub fn read_password_stdin() -> Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let password = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
    if password.is_empty() {
        bail!("Empty password received from stdin");
    }
    Ok(password)
}

/// Read two passwords from stdin (one per line)
pub fn read_two_passwords_stdin() -> Result<(String, String)> {
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();

    let old = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Expected old password on first line of stdin"))??;
    let old = old.trim().to_string();

    let new = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Expected new password on second line of stdin"))??;
    let new = new.trim().to_string();

    if old.is_empty() || new.is_empty() {
        bail!("Passwords must not be empty");
    }

    Ok((old, new))
}

/// Resolve password from --password or --password-stdin
pub fn resolve_password(password: Option<String>, password_stdin: bool) -> Result<String> {
    if let Some(p) = password {
        return Ok(p);
    }
    if password_stdin {
        return read_password_stdin();
    }
    bail!("No password provided. Use --password or --password-stdin")
}
