"""Shared FastAPI dependencies."""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings, get_settings
from .ente.client import MuseumClient
from .sessions import Session, SessionStore

# Declaring this scheme registers Bearer auth in the OpenAPI spec, which gives
# the "Authorize" button in /docs. auto_error=False lets us return our own
# 401 messages.
bearer_scheme = HTTPBearer(auto_error=False, description="Token from POST /auth")


def get_store(request: Request) -> SessionStore:
    return request.app.state.store


def get_current_session(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    store: SessionStore = Depends(get_store),
) -> Session:
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    session = store.get(credentials.credentials)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return session


def make_authed_client(
    session: Session = Depends(get_current_session),
    settings: Settings = Depends(get_settings),
) -> MuseumClient:
    """A museum client authenticated with the session's museum token."""
    return MuseumClient(
        base_url=settings.api_base,
        timeout=settings.ente_timeout,
        token=session.secrets.token,
    )
