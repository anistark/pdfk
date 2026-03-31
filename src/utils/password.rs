use anyhow::{bail, Result};
use std::io::{self, BufRead, IsTerminal};
use std::process;

fn read_password_stdin() -> Result<String> {
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

fn read_two_passwords_stdin() -> Result<(String, String)> {
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

fn prompt_password_interactive(prompt: &str) -> Result<String> {
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| anyhow::anyhow!("Failed to read password: {e}"))?;
    if password.is_empty() {
        bail!("Password must not be empty");
    }
    Ok(password)
}

pub fn read_password_env(var_name: &str) -> Result<String> {
    let value = std::env::var(var_name)
        .map_err(|_| anyhow::anyhow!("Environment variable '{var_name}' is not set"))?;
    if value.is_empty() {
        bail!("Environment variable '{var_name}' is empty");
    }
    Ok(value)
}

pub fn read_password_cmd(cmd: &str) -> Result<String> {
    let output = if cfg!(target_os = "windows") {
        process::Command::new("cmd").args(["/C", cmd]).output()
    } else {
        process::Command::new("sh").args(["-c", cmd]).output()
    }
    .map_err(|e| anyhow::anyhow!("Failed to run command: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Command exited with {}: {}",
            output.status,
            stderr.trim()
        );
    }

    let password = String::from_utf8(output.stdout)
        .map_err(|_| anyhow::anyhow!("Command output is not valid UTF-8"))?
        .trim()
        .to_string();

    if password.is_empty() {
        bail!("Command produced empty output");
    }
    Ok(password)
}

pub fn resolve_password(
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
) -> Result<String> {
    if let Some(ref p) = password {
        if !p.is_empty() {
            return Ok(p.clone());
        }
    }
    if password_stdin {
        return read_password_stdin();
    }
    if let Some(var) = password_env {
        return read_password_env(&var);
    }
    if let Some(cmd) = password_cmd {
        return read_password_cmd(&cmd);
    }
    if password.is_some() || io::stdin().is_terminal() {
        return prompt_password_interactive("Enter password: ");
    }
    bail!("No password provided. Use --password, --password-stdin, --password-env, or --password-cmd")
}

pub fn resolve_old_new_passwords(
    old: Option<String>,
    new: Option<String>,
    password_stdin: bool,
    old_env: Option<String>,
    new_env: Option<String>,
    old_cmd: Option<String>,
    new_cmd: Option<String>,
) -> Result<(String, String)> {
    if password_stdin {
        return read_two_passwords_stdin();
    }

    let old_pass = if let Some(ref p) = old {
        if !p.is_empty() {
            p.clone()
        } else if io::stdin().is_terminal() {
            prompt_password_interactive("Enter current password: ")?
        } else {
            bail!("--old password is required")
        }
    } else if let Some(var) = old_env {
        read_password_env(&var)?
    } else if let Some(cmd) = old_cmd {
        read_password_cmd(&cmd)?
    } else if io::stdin().is_terminal() {
        prompt_password_interactive("Enter current password: ")?
    } else {
        bail!("--old password is required")
    };

    let new_pass = if let Some(ref p) = new {
        if !p.is_empty() {
            p.clone()
        } else if io::stdin().is_terminal() {
            prompt_password_interactive("Enter new password: ")?
        } else {
            bail!("--new password is required")
        }
    } else if let Some(var) = new_env {
        read_password_env(&var)?
    } else if let Some(cmd) = new_cmd {
        read_password_cmd(&cmd)?
    } else if io::stdin().is_terminal() {
        prompt_password_interactive("Enter new password: ")?
    } else {
        bail!("--new password is required")
    };

    Ok((old_pass, new_pass))
}
