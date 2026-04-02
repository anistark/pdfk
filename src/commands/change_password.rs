use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, EncryptParams};
use crate::utils::batch::{self, BatchSummary};
use crate::utils::{display_path, password, print_error, print_status, print_success, print_verbose};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    files: Vec<PathBuf>,
    old: Option<String>,
    new: Option<String>,
    password_stdin: bool,
    old_env: Option<String>,
    new_env: Option<String>,
    old_cmd: Option<String>,
    new_cmd: Option<String>,
    output: Option<PathBuf>,
    in_place: bool,
    recursive: bool,
    dry_run: bool,
) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;

    if output.is_some() && resolved.len() > 1 {
        bail!("--output cannot be used with multiple files. Use --in-place instead.");
    }

    let (old_pass, new_pass) =
        password::resolve_old_new_passwords(old, new, password_stdin, old_env, new_env, old_cmd, new_cmd)?;

    let is_batch = resolved.len() > 1;
    let pb = batch::create_progress_bar(resolved.len());
    let mut summary = BatchSummary::default();

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        if dry_run {
            let output_path = resolve_output_path(file, output.clone(), in_place)
                .unwrap_or_else(|_| file.clone());
            print_status(&format!(
                "[dry-run] Would change password: {} → {}",
                display_path(file),
                display_path(&output_path)
            ));
            summary.succeeded += 1;
        } else {
            match change_password_single(file, &old_pass, &new_pass, output.clone(), in_place) {
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

fn change_password_single(
    file: &Path,
    old_pass: &str,
    new_pass: &str,
    output: Option<PathBuf>,
    in_place: bool,
) -> Result<()> {
    print_verbose(&format!("Loading {}", display_path(file)));
    let doc = reader::load_pdf(file)?;
    if !reader::is_encrypted(&doc) {
        bail!("File is not encrypted. Use `pdfk lock` to encrypt it first.");
    }

    let enc_info = reader::parse_encryption_dict(&doc)?;
    let permissions = PdfPermissions::from_p_value(enc_info.p_value);
    drop(doc);

    print_verbose("Decrypting with old password");
    let mut decrypted_doc = reader::load_pdf_decrypted(file, old_pass)?;

    let params = EncryptParams {
        user_password: new_pass.as_bytes().to_vec(),
        owner_password: new_pass.as_bytes().to_vec(),
        permissions,
    };
    print_verbose("Re-encrypting with new password");
    writer::encrypt_pdf(&mut decrypted_doc, &params)?;

    let output_path = resolve_output_path(file, output, in_place)?;
    print_verbose(&format!("Writing to {}", display_path(&output_path)));
    writer::save_pdf(&mut decrypted_doc, &output_path)?;

    print_success(&format!(
        "Password changed: {} → {}",
        display_path(file),
        display_path(&output_path)
    ));

    Ok(())
}

fn resolve_output_path(input: &Path, output: Option<PathBuf>, in_place: bool) -> Result<PathBuf> {
    if let Some(out) = output {
        return Ok(out);
    }
    if in_place {
        return Ok(input.to_path_buf());
    }
    Ok(input.to_path_buf())
}
