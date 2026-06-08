"""Ente-compatible cryptographic primitives.

All operations mirror Ente's reference implementation (the Go CLI / libsodium)
so that keys, tokens and file payloads produced by the official apps can be
decrypted byte-for-byte.

Dependencies: libsodium (via the ``pysodium`` binding). libsodium must be
installed on the host/container (see the Dockerfile).
"""

from __future__ import annotations

import base64

import pysodium

# Argon2id parameters used by libsodium's crypto_pwhash.
_ARGON2ID = pysodium.crypto_pwhash_ALG_ARGON2ID13

# secretstream constants.
_ABYTES = pysodium.crypto_secretstream_xchacha20poly1305_ABYTES  # 17
_TAG_FINAL = pysodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL

# Ente encrypts file blobs in 4 MiB plaintext chunks.
DECRYPTION_CHUNK_SIZE = 4 * 1024 * 1024 + _ABYTES


def b64decode(value: str) -> bytes:
    """Decode a standard base64 string, tolerating missing padding."""
    if value is None:
        raise ValueError("cannot base64-decode None")
    padding = "=" * (-len(value) % 4)
    return base64.standard_b64decode(value + padding)


def b64encode(value: bytes) -> str:
    return base64.standard_b64encode(value).decode("ascii")


def derive_key_encryption_key(
    password: str, kek_salt_b64: str, mem_limit: int, ops_limit: int
) -> bytes:
    """Derive the key-encryption-key (KEK) from the user's password.

    Mirrors Ente: Argon2id(password, salt, ops=opsLimit, mem=memLimit bytes,
    parallelism=1, out=32 bytes).
    """
    salt = b64decode(kek_salt_b64)
    return pysodium.crypto_pwhash(
        32,
        password.encode("utf-8"),
        salt,
        ops_limit,
        mem_limit,
        _ARGON2ID,
    )


def derive_login_key(key_encryption_key: bytes) -> bytes:
    """Derive the SRP login key from the KEK.

    Ente derives a 32-byte sub-key via libsodium's KDF (BLAKE2b) using
    context "loginctx" and sub-key id 1, then keeps the first 16 bytes.
    """
    subkey = pysodium.crypto_kdf_derive_from_key(32, 1, b"loginctx", key_encryption_key)
    return subkey[:16]


def secretbox_open(cipher_b64: str, nonce_b64: str, key: bytes) -> bytes:
    """Open a libsodium secretbox (combined mode, MAC prepended)."""
    return pysodium.crypto_secretbox_open(b64decode(cipher_b64), b64decode(nonce_b64), key)


def sealed_box_open(cipher_b64: str, public_key: bytes, secret_key: bytes) -> bytes:
    """Open a libsodium sealed (anonymous) box."""
    return pysodium.crypto_box_seal_open(b64decode(cipher_b64), public_key, secret_key)


def decrypt_chacha(data_b64: str, key: bytes, header_b64: str) -> bytes:
    """Decrypt a single-message secretstream payload (used for metadata).

    Ente encrypts metadata blobs as one secretstream message tagged FINAL.
    """
    state = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(
        b64decode(header_b64), key
    )
    plain, _tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(
        state, b64decode(data_b64), None
    )
    return plain


def decrypt_file_stream(encrypted: bytes, key: bytes, header: bytes) -> bytes:
    """Decrypt a full file blob encrypted with libsodium secretstream.

    The blob is a concatenation of (4 MiB + ABYTES) ciphertext chunks; the
    last chunk carries the FINAL tag.
    """
    state = pysodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key)
    out = bytearray()
    offset = 0
    total = len(encrypted)
    while offset < total:
        chunk = encrypted[offset : offset + DECRYPTION_CHUNK_SIZE]
        offset += DECRYPTION_CHUNK_SIZE
        plain, tag = pysodium.crypto_secretstream_xchacha20poly1305_pull(state, chunk, None)
        out.extend(plain)
        if tag == _TAG_FINAL:
            break
    return bytes(out)
