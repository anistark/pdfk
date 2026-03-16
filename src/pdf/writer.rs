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

/// Which cipher is used for stream/string decryption.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CipherMode {
    /// RC4 — used by R2, R3, and R4 with CFM=V2
    Rc4,
    /// AES-128-CBC — used by R4 with CFM=AESV2
    Aes128,
    /// AES-256-CBC — used by R5/R6 with CFM=AESV3
    Aes256,
}

/// Everything needed to decrypt a PDF, regardless of revision.
pub struct DecryptionKey {
    pub file_key: Vec<u8>,
    pub cipher_mode: CipherMode,
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

/// Remove encryption from a PDF. Requires the decryption key.
pub fn decrypt_pdf(doc: &mut Document, key: &DecryptionKey) -> Result<()> {
    match key.cipher_mode {
        CipherMode::Aes256 => {
            let mut file_key_arr = [0u8; KEY_LEN];
            file_key_arr.copy_from_slice(&key.file_key);
            decrypt_objects(doc, &file_key_arr)?;
        }
        CipherMode::Aes128 | CipherMode::Rc4 => {
            decrypt_objects_legacy(doc, &key.file_key, key.cipher_mode)?;
        }
    }

    let encrypt_id = crate::pdf::reader::get_encrypt_object_id(doc);
    doc.trailer.remove(b"Encrypt");
    if let Some(id) = encrypt_id {
        doc.delete_object(id);
    }

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

fn decrypt_objects(doc: &mut Document, file_key: &[u8; KEY_LEN]) -> Result<()> {
    let ids: Vec<ObjectId> = doc.objects.keys().cloned().collect();
    for id in ids {
        if let Some(obj) = doc.objects.get(&id).cloned() {
            doc.objects.insert(id, decrypt_object(obj, file_key)?);
        }
    }
    Ok(())
}

/// Decrypt all objects using per-object keys (R3/R4).
fn decrypt_objects_legacy(doc: &mut Document, file_key: &[u8], cipher_mode: CipherMode) -> Result<()> {
    let ids: Vec<ObjectId> = doc.objects.keys().cloned().collect();
    for id in ids {
        if let Some(obj) = doc.objects.get(&id).cloned() {
            let object_key = match cipher_mode {
                CipherMode::Aes128 => encryption::compute_object_key_aes128(file_key, id.0, id.1),
                CipherMode::Rc4 => encryption::compute_object_key_rc4(file_key, id.0, id.1),
                CipherMode::Aes256 => unreachable!(),
            };
            doc.objects.insert(id, decrypt_object_legacy(obj, &object_key, cipher_mode)?);
        }
    }
    Ok(())
}

/// Decrypt a single PDF object using a per-object key (R3/R4).
fn decrypt_object_legacy(obj: Object, object_key: &[u8], cipher_mode: CipherMode) -> Result<Object> {
    match obj {
        Object::String(data, _) => {
            if data.is_empty() {
                return Ok(Object::String(data, StringFormat::Literal));
            }
            let decrypted = match cipher_mode {
                CipherMode::Rc4 => encryption::rc4_transform(object_key, &data),
                CipherMode::Aes128 => {
                    if data.len() < 32 {
                        // Too short for AES-128-CBC (need at least IV + 1 block)
                        return Ok(Object::String(data, StringFormat::Literal));
                    }
                    match encryption::decrypt_stream_aes128(object_key, &data) {
                        Ok(d) => d,
                        Err(_) => data,
                    }
                }
                CipherMode::Aes256 => unreachable!(),
            };
            Ok(Object::String(decrypted, StringFormat::Literal))
        }
        Object::Stream(mut stream) => {
            if is_skip_type(&stream.dict) {
                return Ok(Object::Stream(stream));
            }
            if stream.content.is_empty() {
                return Ok(Object::Stream(stream));
            }
            match cipher_mode {
                CipherMode::Rc4 => {
                    stream.content = encryption::rc4_transform(object_key, &stream.content);
                }
                CipherMode::Aes128 => {
                    if stream.content.len() >= 32 {
                        if let Ok(decrypted) = encryption::decrypt_stream_aes128(object_key, &stream.content) {
                            stream.content = decrypted;
                        }
                    }
                }
                CipherMode::Aes256 => unreachable!(),
            }
            stream.dict.set("Length", Object::Integer(stream.content.len() as i64));
            Ok(Object::Stream(stream))
        }
        Object::Array(arr) => {
            let new: Result<Vec<_>> = arr.into_iter()
                .map(|o| decrypt_object_legacy(o, object_key, cipher_mode))
                .collect();
            Ok(Object::Array(new?))
        }
        Object::Dictionary(dict) => {
            let mut new = lopdf::Dictionary::new();
            for (key, val) in dict.into_iter() {
                new.set(key, decrypt_object_legacy(val, object_key, cipher_mode)?);
            }
            Ok(Object::Dictionary(new))
        }
        other => Ok(other),
    }
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

fn decrypt_object(obj: Object, file_key: &[u8; KEY_LEN]) -> Result<Object> {
    match obj {
        Object::String(data, _) => {
            if data.len() < 16 {
                return Ok(Object::String(data, StringFormat::Literal));
            }
            match encryption::decrypt_stream_aes256(file_key, &data) {
                Ok(decrypted) => Ok(Object::String(decrypted, StringFormat::Literal)),
                Err(_) => Ok(Object::String(data, StringFormat::Literal)),
            }
        }
        Object::Stream(mut stream) => {
            if is_skip_type(&stream.dict) {
                return Ok(Object::Stream(stream));
            }
            if stream.content.len() >= 16 {
                if let Ok(decrypted) = encryption::decrypt_stream_aes256(file_key, &stream.content) {
                    stream.content = decrypted;
                    stream.dict.set("Length", Object::Integer(stream.content.len() as i64));
                }
            }
            Ok(Object::Stream(stream))
        }
        Object::Array(arr) => {
            let new: Result<Vec<_>> = arr.into_iter().map(|o| decrypt_object(o, file_key)).collect();
            Ok(Object::Array(new?))
        }
        Object::Dictionary(dict) => {
            let mut new = lopdf::Dictionary::new();
            for (key, val) in dict.into_iter() {
                new.set(key, decrypt_object(val, file_key)?);
            }
            Ok(Object::Dictionary(new))
        }
        other => Ok(other),
    }
}

/// Skip XRef and CryptFilter type objects during encryption/decryption.
fn is_skip_type(dict: &lopdf::Dictionary) -> bool {
    if let Ok(type_name) = dict.get(b"Type") {
        if let Ok(name) = type_name.as_name() {
            return name == b"XRef" || name == b"CryptFilter";
        }
    }
    false
}
