use anyhow::{Context, Result};
use lopdf::{Document, Object, ObjectId, StringFormat};
use std::path::Path;

use crate::core::encryption::{
    self, compute_o_oe_r6, compute_perms_r6, compute_u_ue_r6, generate_file_encryption_key,
    KEY_LEN,
};
use crate::core::permissions::PdfPermissions;

pub struct EncryptParams {
    pub user_password: Vec<u8>,
    pub owner_password: Vec<u8>,
    pub permissions: PdfPermissions,
}

/// Encrypt a PDF document with AES-256 (R6).
pub fn encrypt_pdf(doc: &mut Document, params: &EncryptParams) -> Result<()> {
    let file_key = generate_file_encryption_key();
    let p_value = params.permissions.to_p_value();

    let (u_value, ue_value) = compute_u_ue_r6(&params.user_password, &file_key);
    let (o_value, oe_value) = compute_o_oe_r6(&params.owner_password, &file_key, &u_value);
    let perms_value = compute_perms_r6(&file_key, p_value, true);

    encrypt_objects(doc, &file_key)?;

    let encrypt_dict = lopdf::Dictionary::from_iter(vec![
        ("Type", Object::Name(b"CryptFilter".to_vec())),
        ("Filter", Object::Name(b"Standard".to_vec())),
        ("V", Object::Integer(5)),
        ("R", Object::Integer(6)),
        ("Length", Object::Integer(256)),
        ("P", Object::Integer(p_value as i64)),
        ("U", Object::String(u_value.to_vec(), StringFormat::Literal)),
        ("O", Object::String(o_value.to_vec(), StringFormat::Literal)),
        ("UE", Object::String(ue_value.to_vec(), StringFormat::Literal)),
        ("OE", Object::String(oe_value.to_vec(), StringFormat::Literal)),
        ("Perms", Object::String(perms_value.to_vec(), StringFormat::Literal)),
        ("EncryptMetadata", Object::Boolean(true)),
        ("StmF", Object::Name(b"StdCF".to_vec())),
        ("StrF", Object::Name(b"StdCF".to_vec())),
        ("CF", Object::Dictionary(lopdf::Dictionary::from_iter(vec![
            ("StdCF", Object::Dictionary(lopdf::Dictionary::from_iter(vec![
                ("Type", Object::Name(b"CryptFilter".to_vec())),
                ("CFM", Object::Name(b"AESV3".to_vec())),
                ("AuthEvent", Object::Name(b"DocOpen".to_vec())),
                ("Length", Object::Integer(32)),
            ]))),
        ]))),
    ]);

    let encrypt_id = doc.add_object(Object::Dictionary(encrypt_dict));
    doc.trailer.set("Encrypt", Object::Reference(encrypt_id));

    Ok(())
}

pub fn save_pdf(doc: &mut Document, path: &Path) -> Result<()> {
    doc.save(path)
        .with_context(|| format!("Failed to save PDF to {}", path.display()))?;
    Ok(())
}

fn encrypt_objects(doc: &mut Document, file_key: &[u8; KEY_LEN]) -> Result<()> {
    let ids: Vec<ObjectId> = doc.objects.keys().cloned().collect();
    for id in ids {
        if let Some(obj) = doc.objects.get(&id).cloned() {
            doc.objects.insert(id, encrypt_object(obj, file_key)?);
        }
    }
    Ok(())
}

fn encrypt_object(obj: Object, file_key: &[u8; KEY_LEN]) -> Result<Object> {
    match obj {
        Object::String(data, _) => {
            let encrypted = encryption::encrypt_stream_aes256(file_key, &data);
            Ok(Object::String(encrypted, StringFormat::Literal))
        }
        Object::Stream(mut stream) => {
            if is_skip_type(&stream.dict) {
                return Ok(Object::Stream(stream));
            }
            let _ = stream.decompress();
            let encrypted = encryption::encrypt_stream_aes256(file_key, &stream.content);
            stream.content = encrypted;
            stream.dict.set("Length", Object::Integer(stream.content.len() as i64));
            stream.dict.remove(b"Filter");
            Ok(Object::Stream(stream))
        }
        Object::Array(arr) => {
            let new: Result<Vec<_>> = arr.into_iter().map(|o| encrypt_object(o, file_key)).collect();
            Ok(Object::Array(new?))
        }
        Object::Dictionary(dict) => {
            let mut new = lopdf::Dictionary::new();
            for (key, val) in dict.into_iter() {
                new.set(key, encrypt_object(val, file_key)?);
            }
            Ok(Object::Dictionary(new))
        }
        other => Ok(other),
    }
}

/// Skip XRef and CryptFilter type objects during encryption.
fn is_skip_type(dict: &lopdf::Dictionary) -> bool {
    if let Ok(type_name) = dict.get(b"Type") {
        if let Ok(name) = type_name.as_name() {
            return name == b"XRef" || name == b"CryptFilter";
        }
    }
    false
}
