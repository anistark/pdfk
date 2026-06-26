use anyhow::{Context, Result};
use log::debug;
use lopdf::{Dictionary, Document, Object, ObjectId};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
    /// First element of the trailer /ID array (needed for R2/R3/R4 key derivation).
    pub file_id: Vec<u8>,
    /// The CFM value from the stream crypt filter (e.g. "V2", "AESV2", "AESV3").
    pub stm_cfm: Option<String>,
}

pub fn load_pdf(path: &Path) -> Result<Document> {
    Document::load(path).with_context(|| format!("Failed to load PDF: {}", path.display()))
}

/// Load an encrypted PDF, decrypting it with the given password.
/// Returns the fully decrypted document with all objects populated.
pub fn load_pdf_decrypted(path: &Path, password: &str) -> Result<Document> {
    Document::load_with_password(path, password).map_err(|e| {
        let msg = format!("{e}");
        if msg.to_lowercase().contains("password") {
            anyhow::anyhow!("Wrong password")
        } else {
            anyhow::anyhow!("Failed to load/decrypt PDF: {}: {e}", path.display())
        }
    })
}

pub fn is_encrypted(doc: &Document) -> bool {
    doc.trailer.get(b"Encrypt").is_ok()
}

pub fn parse_encryption_dict(doc: &Document) -> Result<EncryptionInfo> {
    let encrypt_ref = doc
        .trailer
        .get(b"Encrypt")
        .context("PDF does not have an Encrypt dictionary")?;

    let encrypt_dict = match encrypt_ref {
        Object::Reference(id) => doc
            .get_object(*id)
            .context("Could not resolve Encrypt reference")?,
        obj => obj,
    };

    let dict = encrypt_dict
        .as_dict()
        .context("Encrypt entry is not a dictionary")?;

    let filter = dict
        .get(b"Filter")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).to_string())
        .unwrap_or_else(|| "Standard".to_string());

    let sub_filter = dict
        .get(b"SubFilter")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).to_string());

    let version = dict
        .get(b"V")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0);
    let revision = dict
        .get(b"R")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0);
    let key_length = dict
        .get(b"Length")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(match version {
            5 => 256,
            4 => 128,
            _ => 40,
        });
    let p_value = dict
        .get(b"P")
        .ok()
        .and_then(|o| o.as_i64().ok())
        .unwrap_or(0) as i32;

    let u_value = extract_bytes(dict, b"U").unwrap_or_default();
    let o_value = extract_bytes(dict, b"O").unwrap_or_default();
    let ue_value = extract_bytes(dict, b"UE").unwrap_or_default();
    let oe_value = extract_bytes(dict, b"OE").unwrap_or_default();
    let perms_value = extract_bytes(dict, b"Perms").unwrap_or_default();

    let encrypt_metadata = dict
        .get(b"EncryptMetadata")
        .ok()
        .and_then(|o| match o {
            Object::Boolean(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(true);

    // Parse file ID from trailer /ID array (first element)
    let file_id = parse_file_id(doc);

    // Parse crypt filter method (CFM) from CF/StmF
    let stm_cfm = parse_stm_cfm(dict);

    debug!("Encryption dict: filter={filter}, V={version}, R={revision}, key_length={key_length}, P={p_value}");
    debug!("Crypt filter: {stm_cfm:?}, encrypt_metadata: {encrypt_metadata}");
    debug!(
        "U: {} bytes, O: {} bytes, UE: {} bytes, OE: {} bytes",
        u_value.len(),
        o_value.len(),
        ue_value.len(),
        oe_value.len()
    );

    Ok(EncryptionInfo {
        filter,
        sub_filter,
        version,
        revision,
        key_length,
        p_value,
        u_value,
        o_value,
        ue_value,
        oe_value,
        perms_value,
        encrypt_metadata,
        file_id,
        stm_cfm,
    })
}

fn extract_bytes(dict: &lopdf::Dictionary, key: &[u8]) -> Option<Vec<u8>> {
    dict.get(key).ok().and_then(|o| match o {
        Object::String(bytes, _) => Some(bytes.clone()),
        _ => None,
    })
}

/// Extract the first element of the trailer /ID array.
fn parse_file_id(doc: &Document) -> Vec<u8> {
    let id_obj = match doc.trailer.get(b"ID") {
        Ok(obj) => obj,
        Err(_) => return Vec::new(),
    };
    let arr = match id_obj {
        Object::Array(arr) => arr,
        _ => return Vec::new(),
    };
    if let Some(Object::String(bytes, _)) = arr.first() {
        return bytes.clone();
    }
    Vec::new()
}

/// An image XObject referenced by a page.
#[derive(Debug, Clone, Serialize)]
pub struct PageImage {
    pub name: String,
    pub width: Option<i64>,
    pub height: Option<i64>,
    pub caption: Option<String>,
}

/// List the image XObjects referenced by a page (best-effort, never panics).
/// Captions are left empty here; see `collect_figure_captions`.
pub fn list_page_images(doc: &Document, page_id: ObjectId) -> Vec<PageImage> {
    let mut images = Vec::new();
    let Ok((resource_dict, resource_ids)) = doc.get_page_resources(page_id) else {
        return images;
    };
    if let Some(dict) = resource_dict {
        collect_images(doc, dict, &mut images);
    }
    for id in resource_ids {
        if let Ok(dict) = doc.get_dictionary(id) {
            collect_images(doc, dict, &mut images);
        }
    }
    images
}

fn collect_images(doc: &Document, resources: &Dictionary, out: &mut Vec<PageImage>) {
    let Some(xobjects) = resources
        .get(b"XObject")
        .ok()
        .and_then(|o| resolve_dict(doc, o))
    else {
        return;
    };
    for (name, value) in xobjects.iter() {
        let Some(dict) = resolve_dict(doc, value) else {
            continue;
        };
        if dict.get(b"Subtype").ok().and_then(|o| o.as_name().ok()) != Some(b"Image".as_slice()) {
            continue;
        }
        out.push(PageImage {
            name: String::from_utf8_lossy(name).to_string(),
            width: dict.get(b"Width").ok().and_then(|o| o.as_i64().ok()),
            height: dict.get(b"Height").ok().and_then(|o| o.as_i64().ok()),
            caption: None,
        });
    }
}

/// Resolve an object (following a single reference) to a dictionary, treating a
/// stream as its dictionary.
fn resolve_dict<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Dictionary> {
    let resolved = match obj {
        Object::Reference(id) => doc.get_object(*id).ok()?,
        other => other,
    };
    match resolved {
        Object::Dictionary(d) => Some(d),
        Object::Stream(s) => Some(&s.dict),
        _ => None,
    }
}

/// Best-effort caption extraction: map each page object id to the alternate text
/// of any `/Figure` structure elements on it (Tagged PDF only). Returns an empty
/// map when the document has no structure tree.
pub fn collect_figure_captions(doc: &Document) -> HashMap<ObjectId, Vec<String>> {
    let mut map: HashMap<ObjectId, Vec<String>> = HashMap::new();
    let Some(root) = doc
        .catalog()
        .ok()
        .and_then(|c| c.get(b"StructTreeRoot").ok())
        .and_then(|o| resolve_dict(doc, o))
    else {
        return map;
    };
    let mut seen = HashSet::new();
    if let Ok(kids) = root.get(b"K") {
        walk_struct_kids(doc, kids, &mut map, &mut seen, 0);
    }
    map
}

fn walk_struct_kids(
    doc: &Document,
    obj: &Object,
    map: &mut HashMap<ObjectId, Vec<String>>,
    seen: &mut HashSet<ObjectId>,
    depth: usize,
) {
    if depth > 64 {
        return;
    }
    match obj {
        Object::Reference(id) => {
            if seen.insert(*id) {
                if let Ok(dict) = doc.get_dictionary(*id) {
                    walk_struct_elem(doc, dict, map, seen, depth);
                }
            }
        }
        Object::Dictionary(dict) => walk_struct_elem(doc, dict, map, seen, depth),
        Object::Array(items) => {
            for item in items {
                walk_struct_kids(doc, item, map, seen, depth + 1);
            }
        }
        _ => {}
    }
}

fn walk_struct_elem(
    doc: &Document,
    elem: &Dictionary,
    map: &mut HashMap<ObjectId, Vec<String>>,
    seen: &mut HashSet<ObjectId>,
    depth: usize,
) {
    let is_figure =
        elem.get(b"S").ok().and_then(|o| o.as_name().ok()) == Some(b"Figure".as_slice());
    if is_figure {
        if let (Some(caption), Some(page)) = (figure_caption(elem), figure_page(elem)) {
            map.entry(page).or_default().push(caption);
        }
    }
    if let Ok(kids) = elem.get(b"K") {
        walk_struct_kids(doc, kids, map, seen, depth + 1);
    }
}

fn figure_caption(elem: &Dictionary) -> Option<String> {
    for key in [b"Alt".as_slice(), b"ActualText".as_slice()] {
        if let Ok(Object::String(bytes, _)) = elem.get(key) {
            let text = decode_pdf_text(bytes);
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
    }
    None
}

fn figure_page(elem: &Dictionary) -> Option<ObjectId> {
    elem.get(b"Pg").ok().and_then(|o| o.as_reference().ok())
}

/// Decode a PDF text string: UTF-16BE when it carries a BOM, otherwise lossy UTF-8.
fn decode_pdf_text(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF {
        let units: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

/// Parse the stream crypt filter method (CFM) from the encrypt dictionary.
/// Looks up /StmF in /CF to find the /CFM value.
fn parse_stm_cfm(dict: &lopdf::Dictionary) -> Option<String> {
    let stm_f = dict
        .get(b"StmF")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| n.to_vec())?;

    let cf = dict.get(b"CF").ok().and_then(|o| o.as_dict().ok())?;

    let filter_dict = cf.get(&stm_f).ok().and_then(|o| o.as_dict().ok())?;

    filter_dict
        .get(b"CFM")
        .ok()
        .and_then(|o| o.as_name().ok())
        .map(|n| String::from_utf8_lossy(n).to_string())
}
