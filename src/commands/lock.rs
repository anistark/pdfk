use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, EncryptParams};
use crate::utils::batch::{self, BatchSummary};
use log::{debug, info};

use crate::utils::{display_path, print_error, print_status, print_success, resolve_password};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    files: Vec<PathBuf>,
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
    user_password: Option<String>,
    owner_password: Option<String>,
    no_print: bool,
    no_copy: bool,
    no_edit: bool,
    output: Option<PathBuf>,
    in_place: bool,
    recursive: bool,
    dry_run: bool,
) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;

    if output.is_some() && resolved.len() > 1 {
        bail!("--output cannot be used with multiple files. Use --in-place instead.");
    }

    let (user_pass, owner_pass) = if user_password.is_some() || owner_password.is_some() {
        let up = user_password.unwrap_or_default();
        let op = owner_password.unwrap_or_else(|| up.clone());
        (up, op)
    } else {
        let p = resolve_password(password, password_stdin, password_env, password_cmd)?;
        (p.clone(), p)
    };

    if user_pass.is_empty() && owner_pass.is_empty() {
        bail!("At least one password must be non-empty");
    }

    let permissions = PdfPermissions {
        allow_print: !no_print,
        allow_copy: !no_copy,
        allow_edit: !no_edit,
    };

    let is_batch = resolved.len() > 1;
    let pb = batch::create_progress_bar(resolved.len());
    let mut summary = BatchSummary::default();

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        if dry_run {
            let output_path = resolve_output_path(file, output.clone(), in_place, "_locked")
                .unwrap_or_else(|_| file.clone());
            print_status(&format!(
                "[dry-run] Would encrypt {} → {}",
                display_path(file),
                display_path(&output_path)
            ));
            summary.succeeded += 1;
        } else {
            match lock_single(
                file,
                &user_pass,
                &owner_pass,
                &permissions,
                output.clone(),
                in_place,
            ) {
                Ok(()) => summary.succeeded += 1,
                Err(e) => {
                    print_error(&format!("{}: {}", display_path(file), e));
                    summary.failed += 1;
                }
            }
        }

        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if is_batch {
        summary.print();
    }

    if summary.has_failures() {
        bail!("{} file(s) failed", summary.failed);
    }

    Ok(())
}

fn lock_single(
    file: &Path,
    user_pass: &str,
    owner_pass: &str,
    permissions: &PdfPermissions,
    output: Option<PathBuf>,
    in_place: bool,
) -> Result<()> {
    info!("Loading {}", display_path(file));
    let mut doc = reader::load_pdf(file)?;

    if reader::is_encrypted(&doc) {
        bail!("File is already encrypted. Use `pdfk change-password` to change the password.");
    }

    let params = EncryptParams {
        user_password: user_pass.as_bytes().to_vec(),
        owner_password: owner_pass.as_bytes().to_vec(),
        permissions: *permissions,
    };

    debug!("Permissions: print={}, copy={}, edit={}", permissions.allow_print, permissions.allow_copy, permissions.allow_edit);
    info!("Encrypting with AES-256 R6");
    writer::encrypt_pdf(&mut doc, &params)?;

    let output_path = resolve_output_path(file, output, in_place, "_locked")?;
    info!("Writing to {}", display_path(&output_path));
    writer::save_pdf(&mut doc, &output_path)?;

    print_success(&format!(
        "Encrypted {} → {}",
        display_path(file),
        display_path(&output_path)
    ));

    Ok(())
}

fn resolve_output_path(
    input: &Path,
    output: Option<PathBuf>,
    in_place: bool,
    suffix: &str,
) -> Result<PathBuf> {
    if let Some(out) = output {
        return Ok(out);
    }
    if in_place {
        return Ok(input.to_path_buf());
    }

    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());
    let ext = input
        .extension()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "pdf".to_string());
    Ok(input
        .parent()
        .unwrap_or(input)
        .join(format!("{stem}{suffix}.{ext}")))
}
