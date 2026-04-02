use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::pdf::reader;
use crate::pdf::writer;
use crate::utils::batch::{self, BatchSummary};
use crate::utils::{display_path, print_error, print_status, print_success, print_verbose, resolve_password};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    files: Vec<PathBuf>,
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
    output: Option<PathBuf>,
    in_place: bool,
    recursive: bool,
    dry_run: bool,
) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;

    if output.is_some() && resolved.len() > 1 {
        bail!("--output cannot be used with multiple files. Use --in-place instead.");
    }

    let pass = resolve_password(password, password_stdin, password_env, password_cmd)?;

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
                "[dry-run] Would decrypt {} → {}",
                display_path(file),
                display_path(&output_path)
            ));
            summary.succeeded += 1;
        } else {
            match unlock_single(file, &pass, output.clone(), in_place) {
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

fn unlock_single(file: &Path, pass: &str, output: Option<PathBuf>, in_place: bool) -> Result<()> {
    print_verbose(&format!("Loading {}", display_path(file)));
    let doc = reader::load_pdf(file)?;
    if !reader::is_encrypted(&doc) {
        bail!("File is not encrypted: {}", display_path(file));
    }
    drop(doc);

    print_verbose("Decrypting PDF");
    let mut decrypted_doc = reader::load_pdf_decrypted(file, pass)?;

    let output_path = resolve_output_path(file, output, in_place)?;
    print_verbose(&format!("Writing to {}", display_path(&output_path)));
    writer::save_pdf(&mut decrypted_doc, &output_path)?;

    print_success(&format!(
        "Decrypted {} → {}",
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
        .join(format!("{stem}_unlocked.{ext}")))
}
