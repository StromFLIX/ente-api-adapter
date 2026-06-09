//! Ente-compatible cryptographic primitives.
//!
//! All operations mirror Ente's reference implementation (libsodium) so that
//! keys, tokens and file payloads produced by the official apps decrypt
//! byte-for-byte. Backed by the pure-Rust, libsodium-compatible `dryoc` crate.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE};
use base64::Engine;

use dryoc::classic::crypto_box::crypto_box_seal_open;
use dryoc::classic::crypto_kdf::crypto_kdf_derive_from_key;
use dryoc::classic::crypto_pwhash::{crypto_pwhash, PasswordHashAlgorithm};
use dryoc::classic::crypto_secretbox::crypto_secretbox_open_easy;
use dryoc::classic::crypto_secretstream_xchacha20poly1305::{
    crypto_secretstream_xchacha20poly1305_init_pull,
    crypto_secretstream_xchacha20poly1305_pull, State,
};
use dryoc::constants::CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL;

const ABYTES: usize = 17;
/// Ente encrypts file blobs in 4 MiB plaintext chunks.
pub const DECRYPTION_CHUNK_SIZE: usize = 4 * 1024 * 1024 + ABYTES;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("base64 decode failed: {0}")]
    Base64(String),
    #[error("crypto operation failed")]
    Crypto,
    #[error("invalid key/nonce length")]
    Length,
}

/// Decode a standard base64 string, tolerating missing padding.
pub fn b64decode(value: &str) -> Result<Vec<u8>, CryptoError> {
    // Re-pad if needed; standard alphabet.
    let trimmed = value.trim_end_matches('=');
    STANDARD_NO_PAD
        .decode(trimmed)
        .map_err(|e| CryptoError::Base64(e.to_string()))
}

pub fn b64encode(value: &[u8]) -> String {
    STANDARD.encode(value)
}

/// URL-safe base64 *with* padding (matches Go `base64.URLEncoding`).
pub fn b64encode_url(value: &[u8]) -> String {
    URL_SAFE.encode(value)
}

/// Derive the key-encryption-key (KEK) from the user's password via Argon2id.
pub fn derive_key_encryption_key(
    password: &str,
    kek_salt_b64: &str,
    mem_limit: usize,
    ops_limit: u64,
) -> Result<[u8; 32], CryptoError> {
    let salt = b64decode(kek_salt_b64)?;
    let mut out = [0u8; 32];
    crypto_pwhash(
        &mut out,
        password.as_bytes(),
        &salt,
        ops_limit,
        mem_limit,
        PasswordHashAlgorithm::Argon2id13,
    )
    .map_err(|_| CryptoError::Crypto)?;
    Ok(out)
}

/// Derive the 16-byte SRP login key from the KEK (libsodium KDF, ctx "loginctx", id 1).
pub fn derive_login_key(kek: &[u8; 32]) -> Result<[u8; 16], CryptoError> {
    let mut subkey = [0u8; 32];
    crypto_kdf_derive_from_key(&mut subkey, 1, b"loginctx", kek)
        .map_err(|_| CryptoError::Crypto)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&subkey[..16]);
    Ok(out)
}

/// Open a libsodium secretbox (combined/"easy" mode, MAC prepended).
pub fn secretbox_open(
    cipher_b64: &str,
    nonce_b64: &str,
    key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = b64decode(cipher_b64)?;
    let nonce_vec = b64decode(nonce_b64)?;
    let nonce: [u8; 24] = nonce_vec.try_into().map_err(|_| CryptoError::Length)?;
    let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::Length)?;
    if cipher.len() < 16 {
        return Err(CryptoError::Length);
    }
    let mut out = vec![0u8; cipher.len() - 16];
    crypto_secretbox_open_easy(&mut out, &cipher, &nonce, &key)
        .map_err(|_| CryptoError::Crypto)?;
    Ok(out)
}

/// Open a libsodium sealed (anonymous) box.
pub fn sealed_box_open(
    cipher_b64: &str,
    public_key: &[u8],
    secret_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = b64decode(cipher_b64)?;
    let pk: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::Length)?;
    let sk: [u8; 32] = secret_key.try_into().map_err(|_| CryptoError::Length)?;
    if cipher.len() < 48 {
        return Err(CryptoError::Length);
    }
    let mut out = vec![0u8; cipher.len() - 48];
    crypto_box_seal_open(&mut out, &cipher, &pk, &sk).map_err(|_| CryptoError::Crypto)?;
    Ok(out)
}

/// Decrypt a single-message secretstream payload (used for metadata).
pub fn decrypt_chacha(
    data_b64: &str,
    key: &[u8],
    header_b64: &str,
) -> Result<Vec<u8>, CryptoError> {
    let data = b64decode(data_b64)?;
    let header_vec = b64decode(header_b64)?;
    let header: [u8; 24] = header_vec.try_into().map_err(|_| CryptoError::Length)?;
    let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::Length)?;

    let mut state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);
    let mut out = vec![0u8; data.len().saturating_sub(ABYTES)];
    let mut tag = 0u8;
    crypto_secretstream_xchacha20poly1305_pull(&mut state, &mut out, &mut tag, &data, None)
        .map_err(|_| CryptoError::Crypto)?;
    Ok(out)
}

/// Decrypt a full file blob encrypted with libsodium secretstream.
pub fn decrypt_file_stream(
    encrypted: &[u8],
    key: &[u8],
    header: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let header: [u8; 24] = header.try_into().map_err(|_| CryptoError::Length)?;
    let key: [u8; 32] = key.try_into().map_err(|_| CryptoError::Length)?;

    let mut state = State::new();
    crypto_secretstream_xchacha20poly1305_init_pull(&mut state, &header, &key);

    let mut out = Vec::with_capacity(encrypted.len());
    let mut offset = 0usize;
    let total = encrypted.len();
    while offset < total {
        let end = (offset + DECRYPTION_CHUNK_SIZE).min(total);
        let chunk = &encrypted[offset..end];
        offset = end;
        let mut plain = vec![0u8; chunk.len().saturating_sub(ABYTES)];
        let mut tag = 0u8;
        crypto_secretstream_xchacha20poly1305_pull(
            &mut state, &mut plain, &mut tag, chunk, None,
        )
        .map_err(|_| CryptoError::Crypto)?;
        out.extend_from_slice(&plain);
        if tag == CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors.json");
        let data = std::fs::read_to_string(path).expect("run gen_vectors.py first");
        serde_json::from_str(&data).expect("valid vectors.json")
    }

    fn dec(v: &Value, key: &str) -> Vec<u8> {
        b64decode(v.get(key).unwrap().as_str().unwrap()).unwrap()
    }
    fn s(v: &Value, key: &str) -> String {
        v.get(key).unwrap().as_str().unwrap().to_string()
    }

    #[test]
    fn argon2_matches_libsodium() {
        let v = vectors();
        let a = &v["argon2"];
        let kek = derive_key_encryption_key(
            a["password"].as_str().unwrap(),
            a["salt_b64"].as_str().unwrap(),
            a["mem"].as_u64().unwrap() as usize,
            a["ops"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(kek.to_vec(), dec(a, "kek_b64"));
    }

    #[test]
    fn kdf_login_key_matches_libsodium() {
        let v = vectors();
        let k = &v["kdf"];
        let kek_vec = dec(k, "kek_b64");
        let kek: [u8; 32] = kek_vec.try_into().unwrap();
        let login_key = derive_login_key(&kek).unwrap();
        assert_eq!(login_key.to_vec(), dec(k, "login_key_b64"));
    }

    #[test]
    fn secretbox_matches_libsodium() {
        let v = vectors();
        let sb = &v["secretbox"];
        let key = dec(sb, "key_b64");
        let plain = secretbox_open(&s(sb, "cipher_b64"), &s(sb, "nonce_b64"), &key).unwrap();
        assert_eq!(plain, dec(sb, "plain_b64"));
    }

    #[test]
    fn sealedbox_matches_libsodium() {
        let v = vectors();
        let b = &v["sealedbox"];
        let pk = dec(b, "pk_b64");
        let sk = dec(b, "sk_b64");
        let plain = sealed_box_open(&s(b, "cipher_b64"), &pk, &sk).unwrap();
        assert_eq!(plain, dec(b, "plain_b64"));
    }

    #[test]
    fn secretstream_metadata_matches_libsodium() {
        let v = vectors();
        let m = &v["secretstream_meta"];
        let key = dec(m, "key_b64");
        let plain = decrypt_chacha(&s(m, "cipher_b64"), &key, &s(m, "header_b64")).unwrap();
        assert_eq!(plain, dec(m, "plain_b64"));
    }

    #[test]
    fn secretstream_file_matches_libsodium() {
        let v = vectors();
        let f = &v["secretstream_file"];
        let key = dec(f, "key_b64");
        let cipher = dec(f, "cipher_b64");
        let header = dec(f, "header_b64");
        let plain = decrypt_file_stream(&cipher, &key, &header).unwrap();
        assert_eq!(plain, dec(f, "plain_b64"));
    }
}

