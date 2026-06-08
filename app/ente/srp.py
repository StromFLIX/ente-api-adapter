"""SRP-6a client matching Ente's server (a port of node-srp, NOT RFC 5054).

Ente's museum uses the ``kong/go-srp`` library, which is a port of node-srp.
Its hashing differs from RFC 5054 in several places, so a generic SRP library
(e.g. pysrp) will NOT interoperate. The exact rules implemented here:

* group: 4096-bit, g = 5, hash = SHA-256, N length = 512 bytes
* k  = H( PAD(N) || PAD(g) )
* x  = H( salt || H(identity || ":" || password) )   (full digest, unreduced)
* u  = H( A.minimal_bytes || B.minimal_bytes )
* S  = (B - k * g^x) ^ (a + u*x) mod N                (then padded to 512 bytes)
* M1 = H( A.minimal_bytes || B_raw_bytes || S.padded )

A is sent on the wire as its minimal big-endian bytes; B is used in M1 exactly
as received (decoded) from the server.
"""

from __future__ import annotations

import hashlib
import os

# 4096-bit group from kong/go-srp (RFC 3526 MODP group 16), g = 5.
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
    "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
    "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
    "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
    "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
    "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
    "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
    "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
    "FFFFFFFFFFFFFFFF"
)

_N = int(_N_HEX, 16)
_G = 5
_N_LEN_BYTES = 512  # 4096 bits


def _h(*parts: bytes) -> bytes:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.digest()


def _h_int(*parts: bytes) -> int:
    return int.from_bytes(_h(*parts), "big")


def _pad(value: int) -> bytes:
    """Left-zero-pad a big-endian integer to the modulus length."""
    return value.to_bytes(_N_LEN_BYTES, "big")


def _minimal(value: int) -> bytes:
    """Minimal big-endian representation (matches Go big.Int.Bytes())."""
    length = (value.bit_length() + 7) // 8
    return value.to_bytes(length, "big")


_K = _h_int(_pad(_N), _pad(_G))


class SrpClient:
    """Stateful SRP-6a client for a single login attempt."""

    def __init__(self, identity: bytes, salt: bytes, login_key: bytes) -> None:
        self._salt = salt
        self._x = _h_int(salt, _h(identity + b":" + login_key))
        self._a = int.from_bytes(os.urandom(32), "big")
        self._A = pow(_G, self._a, _N)
        self._M1: bytes | None = None

    @property
    def a_b64(self) -> bytes:
        """Client public value A, minimal big-endian bytes."""
        return _minimal(self._A)

    def compute_m1(self, b_bytes: bytes) -> bytes:
        """Process the server's B and return M1 (raw bytes).

        ``b_bytes`` must be the exact bytes decoded from the server's srpB.
        """
        B = int.from_bytes(b_bytes, "big")
        if B <= 0 or B >= _N:
            raise ValueError("invalid server B value")

        u = _h_int(self.a_b64, _minimal(B))
        gx = pow(_G, self._x, _N)
        base = (B - _K * gx) % _N
        exponent = self._a + u * self._x
        s = pow(base, exponent, _N)
        s_padded = _pad(s)

        self._M1 = _h(self.a_b64, b_bytes, s_padded)
        return self._M1
