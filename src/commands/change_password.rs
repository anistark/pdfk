use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

use crate::core::encryption;
use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::pdf::writer::{self, CipherMode, DecryptionKey, EncryptParams};
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

    let (old_pass, new_pass) = password::resolve_old_new_passwords(old, new, password_stdin)?;

    let enc_info = reader::parse_encryption_dict(&doc)?;
    let dec_key = try_recover_key(&enc_info, old_pass.as_bytes())?;

    writer::decrypt_pdf(&mut doc, &dec_key)?;

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
) -> Result<DecryptionKey> {
    match enc_info.revision {
        6 => {
            if let Some(key) = encryption::verify_user_password_r6(password, &enc_info.u_value, &enc_info.ue_value) {
                return Ok(DecryptionKey { file_key: key.to_vec(), cipher_mode: CipherMode::Aes256 });
            }
            if let Some(key) = encryption::verify_owner_password_r6(password, &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value) {
                return Ok(DecryptionKey { file_key: key.to_vec(), cipher_mode: CipherMode::Aes256 });
            }
            bail!("Wrong password")
        }
        5 => {
            if let Some(key) = encryption::verify_user_password_r5(password, &enc_info.u_value, &enc_info.ue_value) {
                return Ok(DecryptionKey { file_key: key.to_vec(), cipher_mode: CipherMode::Aes256 });
            }
            if let Some(key) = encryption::verify_owner_password_r5(password, &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value) {
                return Ok(DecryptionKey { file_key: key.to_vec(), cipher_mode: CipherMode::Aes256 });
            }
            bail!("Wrong password")
        }
        3 | 4 => {
            let key_length_bytes = (enc_info.key_length / 8) as usize;
            let cipher_mode = cipher_mode_for_legacy(enc_info);

            if let Some(key) = encryption::verify_user_password_legacy(
                password, &enc_info.u_value, &enc_info.o_value,
                enc_info.p_value, &enc_info.file_id, key_length_bytes,
                enc_info.revision, enc_info.encrypt_metadata,
            ) {
                return Ok(DecryptionKey { file_key: key, cipher_mode });
            }
            if let Some(key) = encryption::verify_owner_password_legacy(
                password, &enc_info.u_value, &enc_info.o_value,
                enc_info.p_value, &enc_info.file_id, key_length_bytes,
                enc_info.revision, enc_info.encrypt_metadata,
            ) {
                return Ok(DecryptionKey { file_key: key, cipher_mode });
            }
            bail!("Wrong password")
        }
        r => bail!("Unsupported encryption revision: R{r}"),
    }
}

/// Determine the cipher mode for R3/R4 from the encryption info.
fn cipher_mode_for_legacy(enc_info: &reader::EncryptionInfo) -> CipherMode {
    if enc_info.revision == 4 {
        match enc_info.stm_cfm.as_deref() {
            Some("AESV2") => CipherMode::Aes128,
            _ => CipherMode::Rc4,
        }
    } else {
        // R3 is always RC4
        CipherMode::Rc4
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
