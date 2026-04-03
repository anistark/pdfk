use anyhow::{bail, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::utils::batch::{self, BatchSummary};
use colored::Colorize;

use log::info;

use crate::utils::{display_path, print_error, write_stdout};

#[derive(Serialize)]
struct InfoOutput {
    file: String,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_length: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypt_filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<PermissionsOutput>,
}

#[derive(Serialize)]
struct PermissionsOutput {
    print: bool,
    copy: bool,
    edit: bool,
}

pub fn execute(files: Vec<PathBuf>, json: bool, recursive: bool) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;

    let is_batch = resolved.len() > 1;
    let pb = batch::create_progress_bar(resolved.len());
    let mut summary = BatchSummary::default();
    let mut json_outputs: Vec<InfoOutput> = Vec::new();

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        info!("Inspecting {}", display_path(file));
        match info_single(file, json, is_batch, &mut json_outputs) {
            Ok(()) => summary.succeeded += 1,
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

    // For JSON batch output, print as array
    if json && is_batch {
        write_stdout(&serde_json::to_string_pretty(&json_outputs)?);
    }

    if is_batch {
        summary.print();
    }

    if summary.has_failures() {
        bail!("{} file(s) failed", summary.failed);
    }

    Ok(())
}

fn info_single(
    file: &Path,
    json: bool,
    is_batch: bool,
    json_outputs: &mut Vec<InfoOutput>,
) -> Result<()> {
    if !file.exists() {
        bail!("File not found: {}", display_path(file));
    }

    let doc = reader::load_pdf(file)?;
    let encrypted = reader::is_encrypted(&doc);

    if !encrypted {
        let output = InfoOutput {
            file: display_path(file),
            encrypted: false,
            algorithm: None,
            key_length: None,
            revision: None,
            crypt_filter: None,
            permissions: None,
        };

        if json {
            if is_batch {
                json_outputs.push(output);
            } else {
                write_stdout(&serde_json::to_string_pretty(&output)?);
            }
        } else {
            if is_batch {
                write_stdout("");
            }
            write_stdout(&format!("File:      {}", display_path(file)));
            write_stdout(&format!("Encrypted: {}", "no".dimmed()));
        }
        return Ok(());
    }

    let enc = reader::parse_encryption_dict(&doc)?;
    let perms = PdfPermissions::from_p_value(enc.p_value);
    let algorithm = resolve_algorithm(enc.revision, &enc.stm_cfm);

    let output = InfoOutput {
        file: display_path(file),
        encrypted: true,
        algorithm: Some(algorithm.clone()),
        key_length: Some(enc.key_length),
        revision: Some(format!("R{}", enc.revision)),
        crypt_filter: enc.stm_cfm.clone(),
        permissions: Some(PermissionsOutput {
            print: perms.allow_print,
            copy: perms.allow_copy,
            edit: perms.allow_edit,
        }),
    };

    if json {
        if is_batch {
            json_outputs.push(output);
        } else {
            write_stdout(&serde_json::to_string_pretty(&output)?);
        }
    } else {
        if is_batch {
            write_stdout("");
        }
        write_stdout(&format!("File:         {}", display_path(file)));
        write_stdout(&format!("Encrypted:    {}", "yes".green()));
        write_stdout(&format!("Algorithm:    {algorithm}"));
        write_stdout(&format!("Key length:   {} bits", enc.key_length));
        write_stdout(&format!("Revision:     R{}", enc.revision));
        if let Some(ref cfm) = enc.stm_cfm {
            write_stdout(&format!("Crypt filter: {cfm}"));
        }
        write_stdout("Permissions:");
        write_stdout(&format!(
            "  Print: {}",
            if perms.allow_print {
                "allowed".green()
            } else {
                "denied".red()
            }
        ));
        write_stdout(&format!(
            "  Copy:  {}",
            if perms.allow_copy {
                "allowed".green()
            } else {
                "denied".red()
            }
        ));
        write_stdout(&format!(
            "  Edit:  {}",
            if perms.allow_edit {
                "allowed".green()
            } else {
                "denied".red()
            }
        ));
    }

    Ok(())
}

fn resolve_algorithm(revision: i64, stm_cfm: &Option<String>) -> String {
    match revision {
        5 | 6 => "AES-256".to_string(),
        4 => match stm_cfm.as_deref() {
            Some("AESV2") => "AES-128".to_string(),
            Some("V2") => "RC4-128".to_string(),
            Some(other) => other.to_string(),
            None => "AES-128/RC4-128".to_string(),
        },
        3 => "RC4-128".to_string(),
        2 => "RC4-40".to_string(),
        _ => format!("Unknown (R{revision})"),
    }
}
