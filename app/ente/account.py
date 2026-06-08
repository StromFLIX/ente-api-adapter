"""Ente login (SRP) and account-secret decryption.

Produces the long-lived secrets the adapter holds in memory: the user's
master key (needed to decrypt collection/file keys) and the museum auth token
(needed for every subsequent request).
"""

from __future__ import annotations

from dataclasses import dataclass

from .client import EnteApiError, MuseumClient
from .crypto import b64decode, b64encode, derive_key_encryption_key, derive_login_key
from .crypto import sealed_box_open, secretbox_open
from .srp import SrpClient


class LoginError(Exception):
    """Raised for any recoverable login failure (bad credentials, MFA, ...)."""


class TwoFactorRequired(LoginError):
    def __init__(self, session_id: str, kek: bytes) -> None:
        super().__init__("two-factor authentication required")
        self.session_id = session_id
        self.kek = kek


class UnsupportedLogin(LoginError):
    """Login requires a flow this adapter does not implement (passkey/email)."""


@dataclass
class AccountSecrets:
    user_id: int
    token: str
    master_key: bytes
    secret_key: bytes
    public_key: bytes


async def _get_srp_attributes(client: MuseumClient, email: str) -> dict:
    res = await client.get("/users/srp/attributes", params={"email": email})
    attrs = res.get("attributes")
    if not attrs:
        raise UnsupportedLogin("account has no SRP attributes (use email/passkey login)")
    return attrs


async def login(
    client: MuseumClient, email: str, password: str
) -> AccountSecrets:
    """Perform password (SRP) login.

    On success returns the decrypted account secrets. If the account has 2FA
    enabled, raises ``TwoFactorRequired`` (carrying the session id and KEK).
    Raises ``LoginError`` on any other failure.
    """
    attrs = await _get_srp_attributes(client, email)
    if attrs.get("isEmailMFAEnabled"):
        raise UnsupportedLogin("account uses email-based MFA, which is not supported")

    kek = derive_key_encryption_key(
        password, attrs["kekSalt"], int(attrs["memLimit"]), int(attrs["opsLimit"])
    )
    login_key = derive_login_key(kek)

    srp = SrpClient(
        identity=str(attrs["srpUserID"]).encode("utf-8"),
        salt=b64decode(attrs["srpSalt"]),
        login_key=login_key,
    )

    try:
        session = await client.post(
            "/users/srp/create-session",
            json={"srpUserID": str(attrs["srpUserID"]), "srpA": b64encode(srp.a_b64)},
        )
    except EnteApiError as exc:
        raise LoginError(f"failed to create SRP session: {exc.message}") from exc

    m1 = srp.compute_m1(b64decode(session["srpB"]))

    try:
        auth = await client.post(
            "/users/srp/verify-session",
            json={
                "srpUserID": str(attrs["srpUserID"]),
                "sessionID": session["sessionID"],
                "srpM1": b64encode(m1),
            },
        )
    except EnteApiError as exc:
        if exc.status_code in (401, 400):
            raise LoginError("incorrect email or password") from exc
        raise LoginError(f"SRP verification failed: {exc.message}") from exc

    if auth.get("passkeySessionID"):
        raise UnsupportedLogin("account requires passkey verification")
    if auth.get("twoFactorSessionID"):
        raise TwoFactorRequired(auth["twoFactorSessionID"], kek)

    return _decrypt_secrets(auth, kek)


async def verify_totp(client: MuseumClient, session_id: str, code: str, kek: bytes) -> AccountSecrets:
    """Complete a two-factor login with a TOTP code.

    ``kek`` is the key-encryption-key derived during the password step; it is
    required to decrypt the account secrets returned here.
    """
    try:
        auth = await client.post(
            "/users/two-factor/verify",
            json={"sessionID": session_id, "code": code},
        )
    except EnteApiError as exc:
        raise LoginError("invalid two-factor code") from exc
    return _decrypt_secrets(auth, kek)


def _decrypt_secrets(auth: dict, kek: bytes) -> AccountSecrets:
    key_attrs = auth.get("keyAttributes")
    if not key_attrs or not auth.get("encryptedToken"):
        raise LoginError("login response missing key attributes or token")

    master_key = secretbox_open(
        key_attrs["encryptedKey"], key_attrs["keyDecryptionNonce"], kek
    )
    secret_key = secretbox_open(
        key_attrs["encryptedSecretKey"], key_attrs["secretKeyDecryptionNonce"], master_key
    )
    public_key = b64decode(key_attrs["publicKey"])
    token_bytes = sealed_box_open(auth["encryptedToken"], public_key, secret_key)

    return AccountSecrets(
        user_id=int(auth["id"]),
        token=_encode_token(token_bytes),
        master_key=master_key,
        secret_key=secret_key,
        public_key=public_key,
    )


def _encode_token(token_bytes: bytes) -> str:
    """Encode the museum auth token as URL-safe base64 *with* padding.

    Matches Ente's ``base64.URLEncoding.EncodeToString`` (the format museum
    expects in the ``X-Auth-Token`` header).
    """
    import base64

    return base64.urlsafe_b64encode(token_bytes).decode("ascii")
