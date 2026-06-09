//! SRP-6a client matching Ente's server (a port of node-srp, NOT RFC 5054).
//!
//! See the Python reference; the math must match exactly:
//! * group: 4096-bit, g = 5, hash = SHA-256, N length = 512 bytes
//! * k  = H( PAD(N) || PAD(g) )
//! * x  = H( salt || H(identity || ":" || login_key) )   (full digest, unreduced)
//! * u  = H( A.minimal_bytes || B.minimal_bytes )
//! * S  = (B - k * g^x) ^ (a + u*x) mod N                 (then padded to 512 bytes)
//! * M1 = H( A.minimal_bytes || B_raw_bytes || S.padded )

use num_bigint::BigUint;
use num_traits::Zero;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08",
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B",
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9",
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6",
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8",
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D",
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C",
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718",
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D",
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D",
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226",
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C",
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC",
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26",
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB",
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2",
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127",
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199",
    "FFFFFFFFFFFFFFFF",
);

const N_LEN_BYTES: usize = 512; // 4096 bits

struct Params {
    n: BigUint,
    g: BigUint,
    k: BigUint,
}

static PARAMS: LazyLock<Params> = LazyLock::new(|| {
    let n = BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid N");
    let g = BigUint::from(5u32);
    let k = BigUint::from_bytes_be(&h(&[&pad(&n), &pad(&g)]));
    Params { n, g, k }
});

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// Left-zero-pad a big-endian integer to the modulus length.
fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    if bytes.len() >= N_LEN_BYTES {
        return bytes;
    }
    let mut out = vec![0u8; N_LEN_BYTES - bytes.len()];
    out.extend_from_slice(&bytes);
    out
}

/// Minimal big-endian representation (matches Go big.Int.Bytes()).
fn minimal(value: &BigUint) -> Vec<u8> {
    if value.is_zero() {
        return Vec::new();
    }
    value.to_bytes_be()
}

#[derive(Debug, thiserror::Error)]
pub enum SrpError {
    #[error("invalid server B value")]
    InvalidB,
}

/// Stateful SRP-6a client for a single login attempt.
pub struct SrpClient {
    x: BigUint,
    a: BigUint,
    a_pub: BigUint,
}

impl SrpClient {
    pub fn new(identity: &[u8], salt: &[u8], login_key: &[u8]) -> Self {
        let mut a_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut a_bytes);
        Self::with_a(identity, salt, login_key, BigUint::from_bytes_be(&a_bytes))
    }

    fn with_a(identity: &[u8], salt: &[u8], login_key: &[u8], a: BigUint) -> Self {
        let inner = h(&[identity, b":", login_key]);
        let x = BigUint::from_bytes_be(&h(&[salt, &inner]));
        let a_pub = PARAMS.g.modpow(&a, &PARAMS.n);
        Self { x, a, a_pub }
    }

    /// Client public value A, minimal big-endian bytes.
    pub fn a_bytes(&self) -> Vec<u8> {
        minimal(&self.a_pub)
    }

    /// Process the server's B (exact decoded bytes) and return M1 (raw bytes).
    pub fn compute_m1(&self, b_bytes: &[u8]) -> Result<Vec<u8>, SrpError> {
        let b = BigUint::from_bytes_be(b_bytes);
        if b.is_zero() || b >= PARAMS.n {
            return Err(SrpError::InvalidB);
        }

        let a_min = self.a_bytes();
        let u = BigUint::from_bytes_be(&h(&[&a_min, &minimal(&b)]));

        let gx = PARAMS.g.modpow(&self.x, &PARAMS.n);
        // base = (B - k * g^x) mod N, kept non-negative.
        let kgx = (&PARAMS.k * &gx) % &PARAMS.n;
        let base = (&b + &PARAMS.n - kgx) % &PARAMS.n;
        let exponent = &self.a + &u * &self.x;
        let s = base.modpow(&exponent, &PARAMS.n);
        let s_padded = pad(&s);

        Ok(h(&[&a_min, b_bytes, &s_padded]).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde_json::Value;

    fn hexd(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn srp_matches_python_reference() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/srp_vector.json");
        let data = std::fs::read_to_string(path).expect("run srp vector generator first");
        let v: Value = serde_json::from_str(&data).unwrap();

        let identity = hexd(v["identity_hex"].as_str().unwrap());
        let salt = hexd(v["salt_hex"].as_str().unwrap());
        let login_key = hexd(v["login_key_hex"].as_str().unwrap());
        let a = BigUint::parse_bytes(v["a_hex"].as_str().unwrap().as_bytes(), 16).unwrap();

        let client = SrpClient::with_a(&identity, &salt, &login_key, a);

        let a_b64 = STANDARD.encode(client.a_bytes());
        assert_eq!(a_b64, v["A_b64"].as_str().unwrap(), "A mismatch");

        let b_bytes = STANDARD.decode(v["B_b64"].as_str().unwrap()).unwrap();
        let m1 = client.compute_m1(&b_bytes).unwrap();
        assert_eq!(
            STANDARD.encode(&m1),
            v["M1_b64"].as_str().unwrap(),
            "M1 mismatch"
        );
    }
}

