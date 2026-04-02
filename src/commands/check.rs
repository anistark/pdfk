use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use std::process;

use crate::core::encryption;
use crate::pdf::reader;
use crate::utils::batch::{self, BatchSummary};
use crate::utils::{display_path, print_error, print_success, print_verbose, resolve_password};

pub fn execute(
    files: Vec<PathBuf>,
    password: Option<String>,
    password_stdin: bool,
    password_env: Option<String>,
    password_cmd: Option<String>,
    recursive: bool,
) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;

    let pass = resolve_password(password, password_stdin, password_env, password_cmd)?;

    let is_batch = resolved.len() > 1;
    let pb = batch::create_progress_bar(resolved.len());
    let mut summary = BatchSummary::default();

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        match check_single(file, &pass) {
            Ok(true) => summary.succeeded += 1,
            Ok(false) => summary.failed += 1,
            Err(e) => {
                print_error(&format!("{}: {}", display_path(file), e));
                summary.failed += 1;
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
        if is_batch {
            bail!("{} file(s) failed", summary.failed);
        } else {
            // For single file, exit with code 1 without extra error message
            process::exit(1);
        }
    }

    Ok(())
}

/// Check a single file. Returns Ok(true) if password is correct, Ok(false) if wrong.
fn check_single(file: &Path, pass: &str) -> Result<bool> {
    if !file.exists() {
        bail!("File not found: {}", display_path(file));
    }

    print_verbose(&format!("Loading {}", display_path(file)));
    let doc = reader::load_pdf(file)?;

    if !reader::is_encrypted(&doc) {
        bail!("File is not encrypted: {}", display_path(file));
    }

    let enc_info = reader::parse_encryption_dict(&doc)?;

    print_verbose(&format!("Verifying against R{} encryption", enc_info.revision));
    let valid = match enc_info.revision {
        6 => {
            encryption::verify_user_password_r6(
                pass.as_bytes(),
                &enc_info.u_value,
                &enc_info.ue_value,
            )
            .is_some()
                || encryption::verify_owner_password_r6(
                    pass.as_bytes(),
                    &enc_info.o_value,
                    &enc_info.oe_value,
                    &enc_info.u_value,
                )
                .is_some()
        }
        5 => {
            encryption::verify_user_password_r5(
                pass.as_bytes(),
                &enc_info.u_value,
                &enc_info.ue_value,
            )
            .is_some()
                || encryption::verify_owner_password_r5(
                    pass.as_bytes(),
                    &enc_info.o_value,
                    &enc_info.oe_value,
                    &enc_info.u_value,
                )
                .is_some()
        }
        3 | 4 => {
            let key_length_bytes = (enc_info.key_length / 8) as usize;
            encryption::verify_user_password_legacy(
                pass.as_bytes(),
                &enc_info.u_value,
                &enc_info.o_value,
                enc_info.p_value,
                &enc_info.file_id,
                key_length_bytes,
                enc_info.revision,
                enc_info.encrypt_metadata,
            )
            .is_some()
                || encryption::verify_owner_password_legacy(
                    pass.as_bytes(),
                    &enc_info.u_value,
                    &enc_info.o_value,
                    enc_info.p_value,
                    &enc_info.file_id,
                    key_length_bytes,
                    enc_info.revision,
                    enc_info.encrypt_metadata,
                )
                .is_some()
        }
        r => bail!("Unsupported encryption revision: R{r}"),
    };

    if valid {
        print_success(&format!("Password is correct for {}", display_path(file)));
        Ok(true)
    } else {
        print_error(&format!("Wrong password for {}", display_path(file)));
        Ok(false)
    }
}
