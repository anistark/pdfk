use anyhow::{bail, Result};
use std::io::{self, BufRead, IsTerminal};

/// Read a single password from stdin
pub fn read_password_stdin() -> Result<String> {
    let stdin = io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let password = line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
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

/// Prompt the user for a password interactively (hidden input, no echo).
pub fn prompt_password_interactive(prompt: &str) -> Result<String> {
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("Failed to read password: {e}"))?;
    if password.is_empty() {
        bail!("Password must not be empty");
    }
    Ok(password)
}

/// Resolve password from --password, --password-stdin, or interactive prompt.
pub fn resolve_password(password: Option<String>, password_stdin: bool) -> Result<String> {
    if let Some(ref p) = password {
        if !p.is_empty() {
            return Ok(p.clone());
        }
    }
    if password_stdin {
        return read_password_stdin();
    }
    if password.is_some() || io::stdin().is_terminal() {
        // Bare --password (no value) or no flag at all with a TTY
        return prompt_password_interactive("Enter password: ");
    }
    bail!("No password provided. Use --password or --password-stdin")
}

/// Resolve old and new passwords from flags, stdin, or interactive prompts.
pub fn resolve_old_new_passwords(
    old: Option<String>,
    new: Option<String>,
    password_stdin: bool,
) -> Result<(String, String)> {
    if password_stdin {
        return read_two_passwords_stdin();
    }

    let old_pass = match old {
        Some(ref p) if !p.is_empty() => p.clone(),
        Some(_) | None if io::stdin().is_terminal() => {
            prompt_password_interactive("Enter current password: ")?
        }
        _ => bail!("--old password is required"),
    };

    let new_pass = match new {
        Some(ref p) if !p.is_empty() => p.clone(),
        Some(_) | None if io::stdin().is_terminal() => {
            prompt_password_interactive("Enter new password: ")?
        }
        _ => bail!("--new password is required"),
    };

    Ok((old_pass, new_pass))
}
