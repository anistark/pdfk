use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, EncryptParams};
use crate::utils::{display_path, password, print_success};

pub fn execute(
    file: PathBuf,
    old: Option<String>,
    new: Option<String>,
    password_stdin: bool,
    output: Option<PathBuf>,
    in_place: bool,
) -> Result<()> {
    if !file.exists() {
        bail!("File not found: {}", display_path(&file));
    }

    // Load without password first to check encryption and read permissions.
    let doc = reader::load_pdf(&file)?;
    if !reader::is_encrypted(&doc) {
        bail!(
            "File is not encrypted: {}\nUse `pdfk lock` to encrypt it first.",
            display_path(&file)
        );
    }

    let enc_info = reader::parse_encryption_dict(&doc)?;
    let permissions = PdfPermissions::from_p_value(enc_info.p_value);
    drop(doc);

    let (old_pass, new_pass) = password::resolve_old_new_passwords(old, new, password_stdin)?;

    // Load and decrypt using lopdf's built-in decryption.
    let mut decrypted_doc = reader::load_pdf_decrypted(&file, &old_pass)?;

    // Re-encrypt with the new password.
    let params = EncryptParams {
        user_password: new_pass.clone().into_bytes(),
        owner_password: new_pass.into_bytes(),
        permissions,
    };
    writer::encrypt_pdf(&mut decrypted_doc, &params)?;

    let output_path = resolve_output_path(&file, output, in_place)?;
    writer::save_pdf(&mut decrypted_doc, &output_path)?;

    print_success(&format!(
        "Password changed: {} → {}",
        display_path(&file),
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
