use anyhow::{bail, Result};
use std::path::PathBuf;
use std::process;

use crate::core::encryption;
use crate::pdf::reader;
use crate::utils::{display_path, print_error, print_success, resolve_password};

pub fn execute(
    file: PathBuf,
    password: Option<String>,
    password_stdin: bool,
) -> Result<()> {
    if !file.exists() {
        bail!("File not found: {}", display_path(&file));
    }

    let doc = reader::load_pdf(&file)?;

    if !reader::is_encrypted(&doc) {
        bail!("File is not encrypted: {}", display_path(&file));
    }

    let pass = resolve_password(password, password_stdin)?;
    let enc_info = reader::parse_encryption_dict(&doc)?;

    let valid = match enc_info.revision {
        6 => {
            encryption::verify_user_password_r6(pass.as_bytes(), &enc_info.u_value, &enc_info.ue_value).is_some()
                || encryption::verify_owner_password_r6(pass.as_bytes(), &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value).is_some()
        }
        5 => {
            encryption::verify_user_password_r5(pass.as_bytes(), &enc_info.u_value, &enc_info.ue_value).is_some()
                || encryption::verify_owner_password_r5(pass.as_bytes(), &enc_info.o_value, &enc_info.oe_value, &enc_info.u_value).is_some()
        }
        3 | 4 => {
            let key_length_bytes = (enc_info.key_length / 8) as usize;
            encryption::verify_user_password_legacy(
                pass.as_bytes(), &enc_info.u_value, &enc_info.o_value,
                enc_info.p_value, &enc_info.file_id, key_length_bytes,
                enc_info.revision, enc_info.encrypt_metadata,
            ).is_some()
                || encryption::verify_owner_password_legacy(
                pass.as_bytes(), &enc_info.u_value, &enc_info.o_value,
                enc_info.p_value, &enc_info.file_id, key_length_bytes,
                enc_info.revision, enc_info.encrypt_metadata,
            ).is_some()
        }
        r => bail!("Unsupported encryption revision: R{r}"),
    };

    if valid {
        print_success(&format!("Password is correct for {}", display_path(&file)));
    } else {
        print_error(&format!("Wrong password for {}", display_path(&file)));
        process::exit(1);
    }

    Ok(())
}
