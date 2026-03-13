use anyhow::{Context, Result};
use lopdf::{Document, Object, ObjectId};
use std::path::Path;

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields used in v0.2 info command
pub struct EncryptionInfo {
    pub filter: String,
    pub sub_filter: Option<String>,
    pub version: i64,
    pub revision: i64,
    pub key_length: i64,
    pub p_value: i32,
    pub u_value: Vec<u8>,
    pub o_value: Vec<u8>,
    pub ue_value: Vec<u8>,
    pub oe_value: Vec<u8>,
    pub perms_value: Vec<u8>,
    pub encrypt_metadata: bool,
}

pub fn load_pdf(path: &Path) -> Result<Document> {
    Document::load(path)
        .with_context(|| format!("Failed to load PDF: {}", path.display()))
}

pub fn is_encrypted(doc: &Document) -> bool {
    doc.trailer.get(b"Encrypt").is_ok()
}

pub fn parse_encryption_dict(doc: &Document) -> Result<EncryptionInfo> {
    let encrypt_ref = doc.trailer.get(b"Encrypt")
        .context("PDF does not have an Encrypt dictionary")?;

    let encrypt_dict = match encrypt_ref {
        Object::Reference(id) => {
            doc.get_object(*id)
                .context("Could not resolve Encrypt reference")?
        }
        obj => obj,
    };

    let dict = encrypt_dict.as_dict()
        .context("Encrypt entry is not a dictionary")?;

    let filter = dict.get(b"Filter")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).to_string())
        .unwrap_or_else(|| "Standard".to_string());

    let sub_filter = dict.get(b"SubFilter")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).to_string());

    let version = dict.get(b"V").ok().and_then(|o| o.as_i64().ok()).unwrap_or(0);
    let revision = dict.get(b"R").ok().and_then(|o| o.as_i64().ok()).unwrap_or(0);
    let key_length = dict.get(b"Length").ok().and_then(|o| o.as_i64().ok())
        .unwrap_or(if version >= 5 { 256 } else { 40 });
    let p_value = dict.get(b"P").ok().and_then(|o| o.as_i64().ok()).unwrap_or(0) as i32;

    let u_value = extract_bytes(dict, b"U").unwrap_or_default();
    let o_value = extract_bytes(dict, b"O").unwrap_or_default();
    let ue_value = extract_bytes(dict, b"UE").unwrap_or_default();
    let oe_value = extract_bytes(dict, b"OE").unwrap_or_default();
    let perms_value = extract_bytes(dict, b"Perms").unwrap_or_default();

    let encrypt_metadata = dict.get(b"EncryptMetadata").ok()
        .and_then(|o| match o {
            Object::Boolean(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(true);

    Ok(EncryptionInfo {
        filter, sub_filter, version, revision, key_length, p_value,
        u_value, o_value, ue_value, oe_value, perms_value, encrypt_metadata,
    })
}

pub fn get_encrypt_object_id(doc: &Document) -> Option<ObjectId> {
    match doc.trailer.get(b"Encrypt") {
        Ok(Object::Reference(id)) => Some(*id),
        _ => None,
    }
}

fn extract_bytes(dict: &lopdf::Dictionary, key: &[u8]) -> Option<Vec<u8>> {
    dict.get(key).ok().and_then(|o| match o {
        Object::String(bytes, _) => Some(bytes.clone()),
        _ => None,
    })
}
