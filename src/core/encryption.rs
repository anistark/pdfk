//! PDF encryption/decryption support.
//!
//! R3: PDF 1.4 — RC4, up to 128-bit keys
//! R4: PDF 1.5–1.7 — AES-128 or RC4, 128-bit keys
//! R5: Adobe Supplement to ISO 32000-1 (Extension Level 3) — AES-256
//! R6: ISO 32000-2:2020 (PDF 2.0) — AES-256

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
#[cfg(test)]
use anyhow::{bail, Result};
use md5::Md5;
use rand::RngExt;
use sha2::{Digest, Sha256, Sha384, Sha512};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
#[cfg(test)]
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub const KEY_LEN: usize = 32;

// ======================================================================
// R3/R4 support: MD5-based key derivation, RC4, AES-128
// ======================================================================

/// Standard PDF password padding string (Table 2 / Appendix A in PDF spec).
pub const PASSWORD_PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

/// Pad or truncate a password to exactly 32 bytes using the PDF padding string.
fn pad_password(password: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];
    let len = password.len().min(32);
    padded[..len].copy_from_slice(&password[..len]);
    padded[len..].copy_from_slice(&PASSWORD_PADDING[..32 - len]);
    padded
}

/// Algorithm 2: Compute the file encryption key from a user password (R2/R3/R4).
pub fn compute_encryption_key(
    password: &[u8],
    o_value: &[u8],
    p_value: i32,
    file_id: &[u8],
    key_length_bytes: usize,
    revision: i64,
    encrypt_metadata: bool,
) -> Vec<u8> {
    let padded = pad_password(password);
    let mut hasher = Md5::new();
    hasher.update(padded);
    hasher.update(o_value);
    hasher.update((p_value as u32).to_le_bytes());
    hasher.update(file_id);
    if revision >= 4 && !encrypt_metadata {
        hasher.update([0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let mut hash = hasher.finalize().to_vec();

    if revision >= 3 {
        for _ in 0..50 {
            let digest = Md5::digest(&hash[..key_length_bytes]);
            hash = digest.to_vec();
        }
    }

    hash.truncate(key_length_bytes);
    hash
}

/// Algorithm 3 (partial): Compute the RC4 key derived from the owner password.
fn compute_o_key(owner_password: &[u8], key_length_bytes: usize, revision: i64) -> Vec<u8> {
    let padded = pad_password(owner_password);
    let mut hash = Md5::digest(padded).to_vec();

    if revision >= 3 {
        for _ in 0..50 {
            let digest = Md5::digest(&hash[..key_length_bytes]);
            hash = digest.to_vec();
        }
    }

    hash.truncate(key_length_bytes);
    hash
}

/// Algorithm 4/5: Compute the U value for password verification.
pub fn compute_u_value(key: &[u8], file_id: &[u8], revision: i64) -> Vec<u8> {
    if revision == 2 {
        // Algorithm 4: RC4 encrypt the padding string
        rc4_transform(key, &PASSWORD_PADDING)
    } else {
        // Algorithm 5: R3/R4
        let mut hasher = Md5::new();
        hasher.update(PASSWORD_PADDING);
        hasher.update(file_id);
        let hash = hasher.finalize().to_vec();

        let mut result = rc4_transform(key, &hash);
        for i in 1..=19u8 {
            let modified_key: Vec<u8> = key.iter().map(|&b| b ^ i).collect();
            result = rc4_transform(&modified_key, &result);
        }

        // Pad to 32 bytes with arbitrary data
        result.resize(32, 0);
        result
    }
}

/// Verify a user password for R2/R3/R4. Returns the file encryption key on success.
#[allow(clippy::too_many_arguments)]
pub fn verify_user_password_legacy(
    password: &[u8],
    u_value: &[u8],
    o_value: &[u8],
    p_value: i32,
    file_id: &[u8],
    key_length_bytes: usize,
    revision: i64,
    encrypt_metadata: bool,
) -> Option<Vec<u8>> {
    let key = compute_encryption_key(
        password,
        o_value,
        p_value,
        file_id,
        key_length_bytes,
        revision,
        encrypt_metadata,
    );
    let computed_u = compute_u_value(&key, file_id, revision);

    if revision == 2 {
        if computed_u == u_value {
            Some(key)
        } else {
            None
        }
    } else {
        // For R3/R4, only compare the first 16 bytes
        if computed_u.len() >= 16 && u_value.len() >= 16 && computed_u[..16] == u_value[..16] {
            Some(key)
        } else {
            None
        }
    }
}

/// Verify an owner password for R2/R3/R4.
/// Decrypts the O value to recover the user password, then verifies it.
#[allow(clippy::too_many_arguments)]
pub fn verify_owner_password_legacy(
    password: &[u8],
    u_value: &[u8],
    o_value: &[u8],
    p_value: i32,
    file_id: &[u8],
    key_length_bytes: usize,
    revision: i64,
    encrypt_metadata: bool,
) -> Option<Vec<u8>> {
    let o_key = compute_o_key(password, key_length_bytes, revision);

    // Decrypt O value to recover padded user password
    let mut user_password = o_value.to_vec();
    if revision == 2 {
        user_password = rc4_transform(&o_key, &user_password);
    } else {
        // R3/R4: iterate RC4 in reverse order
        for i in (0..=19u8).rev() {
            let modified_key: Vec<u8> = o_key.iter().map(|&b| b ^ i).collect();
            user_password = rc4_transform(&modified_key, &user_password);
        }
    }

    // Verify with the recovered user password
    verify_user_password_legacy(
        &user_password,
        u_value,
        o_value,
        p_value,
        file_id,
        key_length_bytes,
        revision,
        encrypt_metadata,
    )
}

/// RC4 encrypt/decrypt (symmetric). Manual implementation for variable-length keys.
pub fn rc4_transform(key: &[u8], data: &[u8]) -> Vec<u8> {
    // KSA (Key-Scheduling Algorithm)
    let mut s: Vec<u8> = (0u16..=255).map(|i| i as u8).collect();
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    let mut i: u8 = 0;
    j = 0;
    let mut output = data.to_vec();
    for byte in output.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(s[i as usize]);
        s.swap(i as usize, j as usize);
        let k = s[(s[i as usize].wrapping_add(s[j as usize])) as usize];
        *byte ^= k;
    }
    output
}

/// Compute a per-object decryption key for RC4 (R3/R4 with V2).
/// Algorithm 1 from the PDF spec.
#[cfg(test)]
pub fn compute_object_key_rc4(file_key: &[u8], obj_num: u32, gen_num: u16) -> Vec<u8> {
    let mut data = file_key.to_vec();
    data.push((obj_num & 0xFF) as u8);
    data.push(((obj_num >> 8) & 0xFF) as u8);
    data.push(((obj_num >> 16) & 0xFF) as u8);
    data.push((gen_num & 0xFF) as u8);
    data.push(((gen_num >> 8) & 0xFF) as u8);

    let hash = Md5::digest(&data);
    let key_len = (file_key.len() + 5).min(16);
    hash[..key_len].to_vec()
}

/// Compute a per-object decryption key for AES-128 (R4 with AESV2).
/// Algorithm 1 with the extra "sAlT" suffix.
#[cfg(test)]
pub fn compute_object_key_aes128(file_key: &[u8], obj_num: u32, gen_num: u16) -> Vec<u8> {
    let mut data = file_key.to_vec();
    data.push((obj_num & 0xFF) as u8);
    data.push(((obj_num >> 8) & 0xFF) as u8);
    data.push(((obj_num >> 16) & 0xFF) as u8);
    data.push((gen_num & 0xFF) as u8);
    data.push(((gen_num >> 8) & 0xFF) as u8);
    data.extend_from_slice(b"sAlT");

    let hash = Md5::digest(&data);
    let key_len = (file_key.len() + 5).min(16);
    hash[..key_len].to_vec()
}

/// Decrypt data with AES-128-CBC. First 16 bytes are IV, strips PKCS#7 padding.
#[cfg(test)]
pub fn decrypt_stream_aes128(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < 32 {
        bail!("Ciphertext too short for AES-128-CBC");
    }
    let iv = &ciphertext[..16];
    let ct = &ciphertext[16..];
    if ct.is_empty() || ct.len() % 16 != 0 {
        bail!("Invalid ciphertext length for AES-128-CBC");
    }

    let mut buf = ct.to_vec();
    let result = Aes128CbcDec::new_from_slices(key, iv)
        .map_err(|_| anyhow::anyhow!("AES-128-CBC key/iv init failed"))?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| anyhow::anyhow!("AES-128-CBC decryption failed"))?;
    let decrypted = result.to_vec();

    // Strip PKCS#7 padding
    if let Some(&pad_byte) = decrypted.last() {
        let pad_len = pad_byte as usize;
        if pad_len > 0
            && pad_len <= 16
            && pad_len <= decrypted.len()
            && decrypted[decrypted.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_byte)
        {
            return Ok(decrypted[..decrypted.len() - pad_len].to_vec());
        }
    }

    Ok(decrypted)
}

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

pub fn compute_u_ue_r6(password: &[u8], file_key: &[u8; KEY_LEN]) -> ([u8; 48], [u8; 32]) {
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

pub fn compute_perms_r6(
    file_key: &[u8; KEY_LEN],
    p_value: i32,
    encrypt_metadata: bool,
) -> [u8; 16] {
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
#[cfg(test)]
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

    // --- R3/R4 tests ---

    #[test]
    fn test_rc4_roundtrip() {
        let key = b"testkey123";
        let plaintext = b"Hello, PDF encryption with RC4!";
        let ciphertext = rc4_transform(key, plaintext);
        let decrypted = rc4_transform(key, &ciphertext);
        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_rc4_empty_data() {
        let key = b"key";
        let ciphertext = rc4_transform(key, b"");
        assert!(ciphertext.is_empty());
    }

    #[test]
    fn test_pad_password_short() {
        let padded = pad_password(b"abc");
        assert_eq!(&padded[..3], b"abc");
        assert_eq!(&padded[3..], &PASSWORD_PADDING[..29]);
    }

    #[test]
    fn test_pad_password_empty() {
        let padded = pad_password(b"");
        assert_eq!(padded, PASSWORD_PADDING);
    }

    #[test]
    fn test_pad_password_full() {
        let pass = [0x41u8; 32]; // 32 'A's
        let padded = pad_password(&pass);
        assert_eq!(padded, pass);
    }

    #[test]
    fn test_pad_password_too_long() {
        let pass = [0x42u8; 64]; // 64 bytes, should be truncated to 32
        let padded = pad_password(&pass);
        assert_eq!(padded, [0x42u8; 32]);
    }

    #[test]
    fn test_legacy_user_password_r3_roundtrip() {
        // Simulate an R3 encryption setup and verify the user password
        let password = b"testpass";
        let file_id = b"0123456789abcdef";
        let key_length_bytes = 16; // 128-bit
        let revision = 3i64;
        let p_value = -4i32; // typical
        let encrypt_metadata = true;

        // Compute O value (Algorithm 3): encrypt padded user password with owner key
        let owner_password = b"ownerpass";
        let o_key = super::compute_o_key(owner_password, key_length_bytes, revision);
        let padded_user = pad_password(password);
        let mut o_value = rc4_transform(&o_key, &padded_user);
        for i in 1..=19u8 {
            let modified_key: Vec<u8> = o_key.iter().map(|&b| b ^ i).collect();
            o_value = rc4_transform(&modified_key, &o_value);
        }

        // Compute encryption key
        let key = compute_encryption_key(
            password,
            &o_value,
            p_value,
            file_id,
            key_length_bytes,
            revision,
            encrypt_metadata,
        );
        assert_eq!(key.len(), key_length_bytes);

        // Compute U value
        let u_value = compute_u_value(&key, file_id, revision);
        assert_eq!(u_value.len(), 32);

        // Verify user password
        let recovered = verify_user_password_legacy(
            password,
            &u_value,
            &o_value,
            p_value,
            file_id,
            key_length_bytes,
            revision,
            encrypt_metadata,
        );
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), key);

        // Wrong password should fail
        let wrong = verify_user_password_legacy(
            b"wrongpass",
            &u_value,
            &o_value,
            p_value,
            file_id,
            key_length_bytes,
            revision,
            encrypt_metadata,
        );
        assert!(wrong.is_none());
    }

    #[test]
    fn test_legacy_owner_password_r3_roundtrip() {
        let user_password = b"userpass";
        let owner_password = b"ownerpass";
        let file_id = b"abcdef0123456789";
        let key_length_bytes = 16;
        let revision = 3i64;
        let p_value = -4i32;
        let encrypt_metadata = true;

        // Compute O value
        let o_key = super::compute_o_key(owner_password, key_length_bytes, revision);
        let padded_user = pad_password(user_password);
        let mut o_value = rc4_transform(&o_key, &padded_user);
        for i in 1..=19u8 {
            let modified_key: Vec<u8> = o_key.iter().map(|&b| b ^ i).collect();
            o_value = rc4_transform(&modified_key, &o_value);
        }

        // Compute encryption key from user password
        let key = compute_encryption_key(
            user_password,
            &o_value,
            p_value,
            file_id,
            key_length_bytes,
            revision,
            encrypt_metadata,
        );
        let u_value = compute_u_value(&key, file_id, revision);

        // Verify owner password recovers the same key
        let recovered = verify_owner_password_legacy(
            owner_password,
            &u_value,
            &o_value,
            p_value,
            file_id,
            key_length_bytes,
            revision,
            encrypt_metadata,
        );
        assert!(recovered.is_some());
        assert_eq!(recovered.unwrap(), key);
    }

    #[test]
    fn test_per_object_key_rc4() {
        let file_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let key1 = compute_object_key_rc4(&file_key, 1, 0);
        let key2 = compute_object_key_rc4(&file_key, 2, 0);
        // Different objects should produce different keys
        assert_ne!(key1, key2);
        // Key length should be min(file_key.len() + 5, 16)
        assert_eq!(key1.len(), 16);
    }

    #[test]
    fn test_per_object_key_aes128() {
        let file_key = vec![
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];
        let key_rc4 = compute_object_key_rc4(&file_key, 1, 0);
        let key_aes = compute_object_key_aes128(&file_key, 1, 0);
        // AES key includes "sAlT" so should differ from RC4 key
        assert_ne!(key_rc4, key_aes);
    }

    #[test]
    fn test_aes128_decrypt_roundtrip() {
        // Encrypt with AES-128-CBC then decrypt
        let key = [0x42u8; 16];
        let plaintext = b"Hello AES-128!";

        // Manually encrypt: IV + AES-128-CBC + PKCS#7 padding
        let iv = [0x00u8; 16];
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(vec![pad_len as u8; pad_len]);

        let encrypted = super::aes128_cbc_encrypt(&key, &iv, &padded);
        let mut ciphertext = iv.to_vec();
        ciphertext.extend(encrypted);

        let decrypted = decrypt_stream_aes128(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext.to_vec());
    }
}
