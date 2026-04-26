use anyhow::{bail, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::core::permissions::PdfPermissions;
use crate::pdf::reader;
use crate::utils::batch;
use crate::utils::display_path;

#[derive(Serialize)]
struct AuditEntry {
    file: String,
    encrypted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    permissions: Option<AuditPermissions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
struct AuditPermissions {
    print: bool,
    copy: bool,
    edit: bool,
}

struct AuditStats {
    encrypted: usize,
    unencrypted: usize,
    errors: usize,
}

pub fn execute(files: Vec<PathBuf>, json: bool, recursive: bool) -> Result<()> {
    let resolved = batch::resolve_files(&files, recursive)?;
    let pb = batch::create_progress_bar(resolved.len());

    let mut entries: Vec<AuditEntry> = Vec::new();
    let mut stats = AuditStats {
        encrypted: 0,
        unencrypted: 0,
        errors: 0,
    };

    for file in &resolved {
        if let Some(ref pb) = pb {
            pb.set_message(display_path(file));
        }

        let entry = audit_single(file);
        match &entry {
            e if e.error.is_some() => stats.errors += 1,
            e if e.encrypted => stats.encrypted += 1,
            _ => stats.unencrypted += 1,
        }
        entries.push(entry);

        if let Some(ref pb) = pb {
            pb.inc(1);
        }
    }

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        print_table(&entries);
        eprintln!();
        eprintln!(
            "Audit: {} encrypted, {} unencrypted, {} errors (out of {} files)",
            stats.encrypted,
            stats.unencrypted,
            stats.errors,
            entries.len()
        );
    }

    if stats.unencrypted > 0 || stats.errors > 0 {
        bail!("{} unencrypted, {} errors", stats.unencrypted, stats.errors);
    }

    Ok(())
}

fn audit_single(file: &Path) -> AuditEntry {
    let path_str = display_path(file);

    if !file.exists() {
        return AuditEntry {
            file: path_str,
            encrypted: false,
            algorithm: None,
            revision: None,
            permissions: None,
            error: Some("File not found".to_string()),
        };
    }

    let doc = match reader::load_pdf(file) {
        Ok(d) => d,
        Err(e) => {
            return AuditEntry {
                file: path_str,
                encrypted: false,
                algorithm: None,
                revision: None,
                permissions: None,
                error: Some(format!("{e}")),
            };
        }
    };

    if !reader::is_encrypted(&doc) {
        return AuditEntry {
            file: path_str,
            encrypted: false,
            algorithm: None,
            revision: None,
            permissions: None,
            error: None,
        };
    }

    match reader::parse_encryption_dict(&doc) {
        Ok(enc) => {
            let perms = PdfPermissions::from_p_value(enc.p_value);
            let algorithm = resolve_algorithm(enc.revision, &enc.stm_cfm);

            AuditEntry {
                file: path_str,
                encrypted: true,
                algorithm: Some(algorithm),
                revision: Some(format!("R{}", enc.revision)),
                permissions: Some(AuditPermissions {
                    print: perms.allow_print,
                    copy: perms.allow_copy,
                    edit: perms.allow_edit,
                }),
                error: None,
            }
        }
        Err(e) => AuditEntry {
            file: path_str,
            encrypted: true,
            algorithm: None,
            revision: None,
            permissions: None,
            error: Some(format!("{e}")),
        },
    }
}

fn print_table(entries: &[AuditEntry]) {
    let max_file = entries
        .iter()
        .map(|e| e.file.len())
        .max()
        .unwrap_or(4)
        .max(4);

    eprintln!(
        "{:<width$}  {:^9}  {:^9}  {:^8}  {:^5}  {:^5}  {:^5}",
        "FILE",
        "ENCRYPTED",
        "ALGORITHM",
        "REVISION",
        "PRINT",
        "COPY",
        "EDIT",
        width = max_file
    );
    eprintln!(
        "{:<width$}  {:─^9}  {:─^9}  {:─^8}  {:─^5}  {:─^5}  {:─^5}",
        "─".repeat(max_file),
        "",
        "",
        "",
        "",
        "",
        "",
        width = max_file
    );

    for entry in entries {
        if let Some(ref err) = entry.error {
            eprintln!(
                "{:<width$}  {:^9}  {}",
                entry.file,
                "ERROR",
                err,
                width = max_file
            );
            continue;
        }

        let encrypted = if entry.encrypted { "yes" } else { "no" };
        let algorithm = entry.algorithm.as_deref().unwrap_or("—");
        let revision = entry.revision.as_deref().unwrap_or("—");

        let (print, copy, edit) = match &entry.permissions {
            Some(p) => (
                if p.print { "✓" } else { "✗" },
                if p.copy { "✓" } else { "✗" },
                if p.edit { "✓" } else { "✗" },
            ),
            None => ("—", "—", "—"),
        };

        eprintln!(
            "{:<width$}  {:^9}  {:^9}  {:^8}  {:^5}  {:^5}  {:^5}",
            entry.file,
            encrypted,
            algorithm,
            revision,
            print,
            copy,
            edit,
            width = max_file
        );
    }
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
