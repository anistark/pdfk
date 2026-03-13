use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::encryption;
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

    let mut doc = reader::load_pdf(&file)?;

    if !reader::is_encrypted(&doc) {
        bail!(
            "File is not encrypted: {}\nUse `pdfk lock` to encrypt it first.",
            display_path(&file)
        );
    }

    let (old_pass, new_pass) = if password_stdin {
        password::read_two_passwords_stdin()?
    } else {
        let old_p = old.ok_or_else(|| anyhow::anyhow!("--old password is required"))?;
        let new_p = new.ok_or_else(|| anyhow::anyhow!("--new password is required"))?;
        (old_p, new_p)
    };

    let enc_info = reader::parse_encryption_dict(&doc)?;
    let file_key = try_recover_key(&enc_info, old_pass.as_bytes())?;

    writer::decrypt_pdf(&mut doc, &file_key)?;

    let permissions = PdfPermissions::from_p_value(enc_info.p_value);
    let params = EncryptParams {
        user_password: new_pass.clone().into_bytes(),
        owner_password: new_pass.into_bytes(),
        permissions,
    };

    writer::encrypt_pdf(&mut doc, &params)?;

    let output_path = resolve_output_path(&file, output, in_place)?;
    writer::save_pdf(&mut doc, &output_path)?;

    print_success(&format!(
        "Password changed: {} → {}",
        display_path(&file),
        display_path(&output_path)
    ));

    Ok(())
}

fn try_recover_key(
    enc_info: &reader::EncryptionInfo,
    password: &[u8],
) -> Result<[u8; encryption::KEY_LEN]> {
    match enc_info.revision {
        6 => {
            if let Some(key) = encryption::verify_user_password_r6(password, &enc_info.u_value, &enc_info.ue_value) {
                return Ok(key);
            }
            if let Some(key) = encryption::verify_owner_password_r6(password, &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value) {
                return Ok(key);
            }
            bail!("Wrong password")
        }
        5 => {
            if let Some(key) = encryption::verify_user_password_r5(password, &enc_info.u_value, &enc_info.ue_value) {
                return Ok(key);
            }
            if let Some(key) = encryption::verify_owner_password_r5(password, &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value) {
                return Ok(key);
            }
            bail!("Wrong password")
        }
        r => bail!("Unsupported encryption revision: R{r}. pdfk v0.1 supports AES-256 (R5/R6) only."),
    }
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
