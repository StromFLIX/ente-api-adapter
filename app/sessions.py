"""In-memory session store.

Holds decrypted account secrets (master key + museum token) keyed by an opaque
session token we hand to the client. Nothing is persisted: secrets live only in
process memory and are lost on restart, by design.

Also holds short-lived "pending 2FA" entries between the password step and the
TOTP step.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from .ente.account import AccountSecrets
from .ente.files import ImageFile


@dataclass
class Session:
    secrets: AccountSecrets
    created_at: float
    last_used: float
    # Cached decrypted library; populated lazily on first /images call.
    library: dict[int, ImageFile] | None = None


@dataclass
class PendingTwoFactor:
    email: str
    two_factor_session_id: str
    kek: bytes
    created_at: float


class SessionStore:
    def __init__(self, ttl_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._sessions: dict[str, Session] = {}
        self._pending: dict[str, PendingTwoFactor] = {}
        self._guard = threading.Lock()

    # --- full sessions -------------------------------------------------
    def create(self, account: AccountSecrets) -> str:
        token = secrets.token_urlsafe(32)
        now = time.time()
        with self._guard:
            self._sessions[token] = Session(secrets=account, created_at=now, last_used=now)
        return token

    def get(self, token: str) -> Session | None:
        now = time.time()
        with self._guard:
            session = self._sessions.get(token)
            if session is None:
                return None
            if now - session.last_used > self._ttl:
                del self._sessions[token]
                return None
            session.last_used = now
            return session

    def delete(self, token: str) -> bool:
        with self._guard:
            return self._sessions.pop(token, None) is not None

    # --- pending 2FA ---------------------------------------------------
    def create_pending(self, email: str, two_factor_session_id: str, kek: bytes) -> str:
        token = secrets.token_urlsafe(24)
        with self._guard:
            self._pending[token] = PendingTwoFactor(
                email=email,
                two_factor_session_id=two_factor_session_id,
                kek=kek,
                created_at=time.time(),
            )
        return token

    def pop_pending(self, token: str) -> PendingTwoFactor | None:
        with self._guard:
            pending = self._pending.pop(token, None)
        if pending is None:
            return None
        # Pending 2FA is only valid for a few minutes.
        if time.time() - pending.created_at > 600:
            return None
        return pending
