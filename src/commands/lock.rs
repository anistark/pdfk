use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, EncryptParams};
use crate::utils::{display_path, print_success, resolve_password};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    file: PathBuf,
    password: Option<String>,
    password_stdin: bool,
    user_password: Option<String>,
    owner_password: Option<String>,
    no_print: bool,
    no_copy: bool,
    no_edit: bool,
    output: Option<PathBuf>,
    in_place: bool,
) -> Result<()> {
    if !file.exists() {
        bail!("File not found: {}", display_path(&file));
    }

    let mut doc = reader::load_pdf(&file)?;

    if reader::is_encrypted(&doc) {
        bail!(
            "File is already encrypted: {}\nUse `pdfk change-password` to change the password.",
            display_path(&file)
        );
    }

    let (user_pass, owner_pass) = if user_password.is_some() || owner_password.is_some() {
        let up = user_password.unwrap_or_default();
        let op = owner_password.unwrap_or_else(|| up.clone());
        (up, op)
    } else {
        let p = resolve_password(password, password_stdin)?;
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

    let params = EncryptParams {
        user_password: user_pass.into_bytes(),
        owner_password: owner_pass.into_bytes(),
        permissions,
    };

    writer::encrypt_pdf(&mut doc, &params)?;

    let output_path = resolve_output_path(&file, output, in_place, "_locked")?;
    writer::save_pdf(&mut doc, &output_path)?;

    print_success(&format!(
        "Encrypted {} → {}",
        display_path(&file),
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

    let stem = input.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "output".to_string());
    let ext = input.extension()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "pdf".to_string());
    Ok(input.parent().unwrap_or(input).join(format!("{stem}{suffix}.{ext}")))
}
