"""Generate crypto test vectors from the Python/pysodium reference.

Prints a JSON object the Rust test suite checks against, ensuring byte-for-byte
compatibility of every primitive the adapter relies on.
"""
import base64
import json

import pysodium

b64 = lambda b: base64.standard_b64encode(b).decode()

out = {}

# --- Argon2id KEK derivation ---
password = "correct horse battery staple"
kek_salt = pysodium.randombytes(pysodium.crypto_pwhash_SALTBYTES)  # 16
mem = pysodium.crypto_pwhash_MEMLIMIT_INTERACTIVE
ops = pysodium.crypto_pwhash_OPSLIMIT_INTERACTIVE
kek = pysodium.crypto_pwhash(
    32, password.encode(), kek_salt, ops, mem, pysodium.crypto_pwhash_ALG_ARGON2ID13
)
out["argon2"] = {
    "password": password,
    "salt_b64": b64(kek_salt),
    "mem": mem,
    "ops": ops,
    "kek_b64": b64(kek),
}

# --- KDF login key ---
subkey = pysodium.crypto_kdf_derive_from_key(32, 1, b"loginctx", kek)
out["kdf"] = {"kek_b64": b64(kek), "login_key_b64": b64(subkey[:16])}

# --- secretbox (easy/combined) ---
sb_key = pysodium.randombytes(32)
sb_nonce = pysodium.randombytes(pysodium.crypto_secretbox_NONCEBYTES)
sb_msg = b"the quick brown fox jumps over the lazy dog"
sb_cipher = pysodium.crypto_secretbox(sb_msg, sb_nonce, sb_key)
out["secretbox"] = {
    "key_b64": b64(sb_key),
    "nonce_b64": b64(sb_nonce),
    "cipher_b64": b64(sb_cipher),
    "plain_b64": b64(sb_msg),
}

# --- sealed box ---
pk, sk = pysodium.crypto_box_keypair()
seal_msg = b"sealed secret token bytes 1234567890"
sealed = pysodium.crypto_box_seal(seal_msg, pk)
out["sealedbox"] = {
    "pk_b64": b64(pk),
    "sk_b64": b64(sk),
    "cipher_b64": b64(sealed),
    "plain_b64": b64(seal_msg),
}

# --- secretstream single message (metadata) ---
ss_key = pysodium.randombytes(pysodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
state, header = pysodium.crypto_secretstream_xchacha20poly1305_init_push(ss_key)
meta_msg = json.dumps({"title": "IMG_0001.jpg", "fileType": 0}).encode()
meta_cipher = pysodium.crypto_secretstream_xchacha20poly1305_push(
    state, meta_msg, None, pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
)
out["secretstream_meta"] = {
    "key_b64": b64(ss_key),
    "header_b64": b64(header),
    "cipher_b64": b64(meta_cipher),
    "plain_b64": b64(meta_msg),
}

# --- secretstream multi-chunk file blob (4MiB chunks) ---
CHUNK = 4 * 1024 * 1024
fs_key = pysodium.randombytes(pysodium.crypto_secretstream_xchacha20poly1305_KEYBYTES)
state2, header2 = pysodium.crypto_secretstream_xchacha20poly1305_init_push(fs_key)
# 1.5 chunks of plaintext -> 2 ciphertext chunks
plain = bytes((i * 7 + 3) & 0xFF for i in range(CHUNK + CHUNK // 2))
parts = []
off = 0
total = len(plain)
while off < total:
    piece = plain[off : off + CHUNK]
    off += CHUNK
    tag = (
        pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL
        if off >= total
        else pysodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
    )
    parts.append(
        pysodium.crypto_secretstream_xchacha20poly1305_push(state2, piece, None, tag)
    )
file_cipher = b"".join(parts)
out["secretstream_file"] = {
    "key_b64": b64(fs_key),
    "header_b64": b64(header2),
    "cipher_b64": b64(file_cipher),
    "plain_b64": b64(plain),
}

print(json.dumps(out))
