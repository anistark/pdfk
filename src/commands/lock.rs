use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, EncryptParams};
use crate::utils::batch::{self, BatchSummary};
use crate::utils::{
    copy_to_clipboard, display_path, generate_password, print_error, print_success,
    resolve_password,
};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    files: Vec<PathBuf>,
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
    generate: bool,
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

    if generate && (user_password.is_some() || owner_password.is_some()) {
        bail!("--generate-password cannot be combined with --user-password or --owner-password");
    }

    let (user_pass, owner_pass, generated) = if generate {
        let pw = generate_password();
        (pw.clone(), pw.clone(), Some(pw))
    } else if user_password.is_some() || owner_password.is_some() {
        let up = user_password.unwrap_or_default();
        let op = owner_password.unwrap_or_else(|| up.clone());
        (up, op, None)
    } else {
        let p = resolve_password(password, password_stdin, password_env, password_cmd)?;
        (p.clone(), p, None)
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
            eprintln!(
                "[dry-run] Would encrypt {} → {}",
                display_path(file),
                display_path(&output_path)
            );
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

    if let Some(pw) = generated {
        announce_generated_password(&pw, dry_run);
    }

    Ok(())
}

fn announce_generated_password(password: &str, dry_run: bool) {
    eprintln!();
    eprintln!("Generated password: {password}");
    if dry_run {
        eprintln!("(dry-run: clipboard not updated)");
        return;
    }
    match copy_to_clipboard(password) {
        Ok(()) => eprintln!("✓ Copied to clipboard. Save it now — it will not be shown again."),
        Err(e) => {
            eprintln!("! Could not copy to clipboard: {e}\n  Save the password above manually.")
        }
    }
}

fn lock_single(
    file: &Path,
    user_pass: &str,
    owner_pass: &str,
    permissions: &PdfPermissions,
    output: Option<PathBuf>,
    in_place: bool,
) -> Result<()> {
    let mut doc = reader::load_pdf(file)?;

    if reader::is_encrypted(&doc) {
        bail!("File is already encrypted. Use `pdfk change-password` to change the password.");
    }

    let params = EncryptParams {
        user_password: user_pass.as_bytes().to_vec(),
        owner_password: owner_pass.as_bytes().to_vec(),
        permissions: *permissions,
    };

    writer::encrypt_pdf(&mut doc, &params)?;

    let output_path = resolve_output_path(file, output, in_place, "_locked")?;
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
