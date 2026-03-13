//! PDF AES-256 encryption/decryption (Revision 5 and 6).
//!
//! R5: Adobe Supplement to ISO 32000-1 (Extension Level 3)
//! R6: ISO 32000-2:2020 (PDF 2.0)

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use anyhow::{bail, Result};
use rand::RngExt;
use sha2::{Digest, Sha256, Sha384, Sha512};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub const KEY_LEN: usize = 32;

pub fn generate_file_encryption_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    rand::rng().fill(&mut key);
    key
}

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill(buf.as_mut_slice());
    buf
}

// --- R6 key derivation (ISO 32000-2, Algorithm 2.B) ---

/// Iterative hash used in R6 for password validation and key derivation.
/// Selects SHA-256/384/512 based on intermediate hash bytes.
fn compute_hash_r6(password: &[u8], salt: &[u8], user_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.update(user_key);
    let mut k = hasher.finalize().to_vec();

    let mut round = 0u32;
    loop {
        let mut k1_single = Vec::with_capacity(password.len() + k.len() + user_key.len());
        k1_single.extend_from_slice(password);
        k1_single.extend_from_slice(&k);
        k1_single.extend_from_slice(user_key);

        let mut k1 = Vec::with_capacity(k1_single.len() * 64);
        for _ in 0..64 {
            k1.extend_from_slice(&k1_single);
        }

        let aes_key = &k[..16];
        let aes_iv = &k[16..32];
        let encrypted = aes128_cbc_encrypt(aes_key, aes_iv, &k1);

        let remainder = {
            let mut sum: u64 = 0;
            for &b in &encrypted[..16] {
                sum = sum.wrapping_add(b as u64);
            }
            (sum % 3) as u8
        };

        k = match remainder {
            0 => Sha256::digest(&encrypted).to_vec(),
            1 => Sha384::digest(&encrypted).to_vec(),
            _ => Sha512::digest(&encrypted).to_vec(),
        };

        let last_byte = *encrypted.last().unwrap();
        if round >= 63 && (last_byte as u32) <= round - 32 {
            break;
        }
        round += 1;
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&k[..32]);
    result
}

fn aes128_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

    let mut buf = data.to_vec();
    let pad_len = (16 - (buf.len() % 16)) % 16;
    buf.extend(vec![0u8; pad_len]);

    let data_len = buf.len();
    buf.resize(data_len + 16, 0);
    let ct = Aes128CbcEnc::new_from_slices(key, iv)
        .expect("AES-128-CBC key/iv init")
        .encrypt_padded_mut::<NoPadding>(&mut buf, data_len)
        .expect("AES-128-CBC encrypt");
    ct.to_vec()
}

// --- R5 key derivation ---

fn compute_hash_r5(password: &[u8], salt: &[u8], user_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.update(user_key);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

// --- Compute encryption dictionary values ---

pub fn compute_u_ue_r6(
    password: &[u8],
    file_key: &[u8; KEY_LEN],
) -> ([u8; 48], [u8; 32]) {
    let validation_salt = random_bytes(8);
    let key_salt = random_bytes(8);

    let hash = compute_hash_r6(password, &validation_salt, &[]);
    let mut u = [0u8; 48];
    u[..32].copy_from_slice(&hash);
    u[32..40].copy_from_slice(&validation_salt);
    u[40..48].copy_from_slice(&key_salt);

    let ke_hash = compute_hash_r6(password, &key_salt, &[]);
    let iv = [0u8; 16];
    let ue = aes256_cbc_encrypt(&ke_hash, &iv, file_key);
    let mut ue_arr = [0u8; 32];
    ue_arr.copy_from_slice(&ue[..32]);

    (u, ue_arr)
}

pub fn compute_o_oe_r6(
    password: &[u8],
    file_key: &[u8; KEY_LEN],
    u_value: &[u8; 48],
) -> ([u8; 48], [u8; 32]) {
    let validation_salt = random_bytes(8);
    let key_salt = random_bytes(8);

    let hash = compute_hash_r6(password, &validation_salt, u_value);
    let mut o = [0u8; 48];
    o[..32].copy_from_slice(&hash);
    o[32..40].copy_from_slice(&validation_salt);
    o[40..48].copy_from_slice(&key_salt);

    let ke_hash = compute_hash_r6(password, &key_salt, u_value);
    let iv = [0u8; 16];
    let oe = aes256_cbc_encrypt(&ke_hash, &iv, file_key);
    let mut oe_arr = [0u8; 32];
    oe_arr.copy_from_slice(&oe[..32]);

    (o, oe_arr)
}

pub fn compute_perms_r6(file_key: &[u8; KEY_LEN], p_value: i32, encrypt_metadata: bool) -> [u8; 16] {
    let p_bytes = (p_value as u32).to_le_bytes();
    let mut block = [0u8; 16];
    block[..4].copy_from_slice(&p_bytes);
    block[4..8].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
    block[8] = if encrypt_metadata { b'T' } else { b'F' };
    block[9] = b'a';
    block[10] = b'd';
    block[11] = b'b';
    let rnd = random_bytes(4);
    block[12..16].copy_from_slice(&rnd);

    aes256_ecb_encrypt(file_key, &block)
}

// --- Password verification ---

pub fn verify_user_password_r6(
    password: &[u8],
    u_value: &[u8],
    ue_value: &[u8],
) -> Option<[u8; KEY_LEN]> {
    if u_value.len() < 48 || ue_value.len() < 32 {
        return None;
    }

    let computed_hash = compute_hash_r6(password, &u_value[32..40], &[]);
    if computed_hash != u_value[..32] {
        return None;
    }

    let ke_hash = compute_hash_r6(password, &u_value[40..48], &[]);
    let decrypted = aes256_cbc_decrypt(&ke_hash, &[0u8; 16], &ue_value[..32])?;
    let mut file_key = [0u8; KEY_LEN];
    file_key.copy_from_slice(&decrypted[..KEY_LEN]);
    Some(file_key)
}

pub fn verify_owner_password_r6(
    password: &[u8],
    o_value: &[u8],
    oe_value: &[u8],
    u_value: &[u8],
) -> Option<[u8; KEY_LEN]> {
    if o_value.len() < 48 || oe_value.len() < 32 {
        return None;
    }

    let computed_hash = compute_hash_r6(password, &o_value[32..40], u_value);
    if computed_hash != o_value[..32] {
        return None;
    }

    let ke_hash = compute_hash_r6(password, &o_value[40..48], u_value);
    let decrypted = aes256_cbc_decrypt(&ke_hash, &[0u8; 16], &oe_value[..32])?;
    let mut file_key = [0u8; KEY_LEN];
    file_key.copy_from_slice(&decrypted[..KEY_LEN]);
    Some(file_key)
}

pub fn verify_user_password_r5(
    password: &[u8],
    u_value: &[u8],
    ue_value: &[u8],
) -> Option<[u8; KEY_LEN]> {
    if u_value.len() < 48 || ue_value.len() < 32 {
        return None;
    }

    let computed_hash = compute_hash_r5(password, &u_value[32..40], &[]);
    if computed_hash != u_value[..32] {
        return None;
    }

    let ke_hash = compute_hash_r5(password, &u_value[40..48], &[]);
    let decrypted = aes256_cbc_decrypt(&ke_hash, &[0u8; 16], &ue_value[..32])?;
    let mut file_key = [0u8; KEY_LEN];
    file_key.copy_from_slice(&decrypted[..KEY_LEN]);
    Some(file_key)
}

pub fn verify_owner_password_r5(
    password: &[u8],
    o_value: &[u8],
    oe_value: &[u8],
    u_value: &[u8],
) -> Option<[u8; KEY_LEN]> {
    if o_value.len() < 48 || oe_value.len() < 32 {
        return None;
    }

    let computed_hash = compute_hash_r5(password, &o_value[32..40], u_value);
    if computed_hash != o_value[..32] {
        return None;
    }

    let ke_hash = compute_hash_r5(password, &o_value[40..48], u_value);
    let decrypted = aes256_cbc_decrypt(&ke_hash, &[0u8; 16], &oe_value[..32])?;
    let mut file_key = [0u8; KEY_LEN];
    file_key.copy_from_slice(&decrypted[..KEY_LEN]);
    Some(file_key)
}

// --- AES helpers ---

pub fn aes256_cbc_encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let pad_len = (16 - (buf.len() % 16)) % 16;
    buf.extend(vec![0u8; pad_len]);

    let data_len = buf.len();
    buf.resize(data_len + 16, 0);
    let ct = Aes256CbcEnc::new_from_slices(key, iv)
        .expect("AES-256-CBC key/iv init")
        .encrypt_padded_mut::<NoPadding>(&mut buf, data_len)
        .expect("AES-256-CBC encrypt");
    ct.to_vec()
}

pub fn aes256_cbc_decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() % 16 != 0 {
        return None;
    }
    let mut buf = data.to_vec();
    let result = Aes256CbcDec::new_from_slices(key, iv)
        .ok()?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .ok()?;
    Some(result.to_vec())
}

fn aes256_ecb_encrypt(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    use ecb::Encryptor;
    type Aes256EcbEnc = Encryptor<aes::Aes256>;

    let mut buf = [0u8; 32];
    buf[..16].copy_from_slice(block);
    let ct = Aes256EcbEnc::new_from_slice(key)
        .expect("AES-256-ECB key init")
        .encrypt_padded_mut::<NoPadding>(&mut buf, 16)
        .expect("AES-256-ECB encrypt");
    let mut out = [0u8; 16];
    out.copy_from_slice(&ct[..16]);
    out
}

// --- Stream encryption/decryption for PDF objects ---

/// Encrypt PDF stream data with AES-256-CBC. Prepends random 16-byte IV, uses PKCS#7 padding.
pub fn encrypt_stream_aes256(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let iv = random_bytes(16);
    let pad_len = 16 - (plaintext.len() % 16);
    let mut padded = plaintext.to_vec();
    padded.extend(vec![pad_len as u8; pad_len]);

    let ct = aes256_cbc_encrypt(key, &iv, &padded);
    let mut result = iv;
    result.extend(ct);
    result
}

/// Decrypt PDF stream data with AES-256-CBC. First 16 bytes are IV, strips PKCS#7 padding.
pub fn decrypt_stream_aes256(key: &[u8; KEY_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 16 {
        bail!("Ciphertext too short for AES-256-CBC");
    }
    let iv = &ciphertext[..16];
    let ct = &ciphertext[16..];
    if ct.is_empty() || ct.len() % 16 != 0 {
        bail!("Invalid ciphertext length for AES-256-CBC");
    }
    let decrypted = aes256_cbc_decrypt(key, iv, ct)
        .ok_or_else(|| anyhow::anyhow!("AES-256-CBC decryption failed"))?;

    let pad_byte = *decrypted.last().unwrap_or(&0);
    let pad_len = pad_byte as usize;
    if pad_len == 0 || pad_len > 16 || pad_len > decrypted.len() {
        bail!("Invalid PKCS#7 padding");
    }
    for &b in &decrypted[decrypted.len() - pad_len..] {
        if b != pad_byte {
            bail!("Invalid PKCS#7 padding");
        }
    }
    Ok(decrypted[..decrypted.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_encrypt_decrypt_roundtrip() {
        let key = generate_file_encryption_key();
        let plaintext = b"Hello, PDF encryption!";
        let ciphertext = encrypt_stream_aes256(&key, plaintext);
        let decrypted = decrypt_stream_aes256(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stream_encrypt_decrypt_empty() {
        let key = generate_file_encryption_key();
        let ciphertext = encrypt_stream_aes256(&key, b"");
        let decrypted = decrypt_stream_aes256(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, b"".to_vec());
    }

    #[test]
    fn test_stream_encrypt_decrypt_block_aligned() {
        let key = generate_file_encryption_key();
        let plaintext = [0x42u8; 32];
        let ciphertext = encrypt_stream_aes256(&key, &plaintext);
        let decrypted = decrypt_stream_aes256(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_u_ue_verify_roundtrip_r6() {
        let password = b"testpass123";
        let file_key = generate_file_encryption_key();
        let (u, ue) = compute_u_ue_r6(password, &file_key);
        let recovered = verify_user_password_r6(password, &u, &ue);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), file_key);
    }

    #[test]
    fn test_u_ue_wrong_password_r6() {
        let file_key = generate_file_encryption_key();
        let (u, ue) = compute_u_ue_r6(b"correctpass", &file_key);
        assert!(verify_user_password_r6(b"wrongpass", &u, &ue).is_none());
    }

    #[test]
    fn test_o_oe_verify_roundtrip_r6() {
        let file_key = generate_file_encryption_key();
        let (u, _ue) = compute_u_ue_r6(b"userpass", &file_key);
        let (o, oe) = compute_o_oe_r6(b"ownerpass", &file_key, &u);
        let recovered = verify_owner_password_r6(b"ownerpass", &o, &oe, &u);
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), file_key);
    }

    #[test]
    fn test_permissions_roundtrip() {
        use crate::core::permissions::PdfPermissions;
        let perms = PdfPermissions {
            allow_print: true,
            allow_copy: false,
            allow_edit: true,
        };
        let p = perms.to_p_value();
        let decoded = PdfPermissions::from_p_value(p);
        assert!(decoded.allow_print);
        assert!(!decoded.allow_copy);
        assert!(decoded.allow_edit);
    }
}
