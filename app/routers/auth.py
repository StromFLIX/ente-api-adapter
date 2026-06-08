"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..config import Settings, get_settings
from ..deps import bearer_scheme, get_current_session, get_store
from ..ente.account import (
    LoginError,
    TwoFactorRequired,
    UnsupportedLogin,
    login,
    verify_totp,
)
from ..ente.client import EnteApiError, MuseumClient
from ..schemas import AuthRequest, AuthResponse, TwoFactorChallenge, TwoFactorRequest
from ..sessions import Session, SessionStore

router = APIRouter(tags=["auth"])


@router.post(
    "/auth",
    response_model=AuthResponse,
    responses={200: {"model": TwoFactorChallenge}},
    summary="Log in with credentials and receive a bearer token",
)
async def auth(
    body: AuthRequest,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_store),
):
    async with MuseumClient(settings.api_base, settings.ente_timeout) as client:
        try:
            secrets = await login(client, body.email, body.password)
        except TwoFactorRequired as exc:
            mfa_token = store.create_pending(body.email, exc.session_id, exc.kek)
            return TwoFactorChallenge(mfa_token=mfa_token)
        except UnsupportedLogin as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
        except LoginError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        except EnteApiError as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, exc.message) from exc

    token = store.create(secrets)
    return AuthResponse(token=token, user_id=secrets.user_id)


@router.post(
    "/auth/2fa",
    response_model=AuthResponse,
    summary="Complete two-factor login with a TOTP code",
)
async def auth_two_factor(
    body: TwoFactorRequest,
    settings: Settings = Depends(get_settings),
    store: SessionStore = Depends(get_store),
):
    pending = store.pop_pending(body.mfa_token)
    if pending is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired 2FA token")

    async with MuseumClient(settings.api_base, settings.ente_timeout) as client:
        try:
            secrets = await verify_totp(
                client, pending.two_factor_session_id, body.code, pending.kek
            )
        except LoginError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
        except EnteApiError as exc:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, exc.message) from exc

    token = store.create(secrets)
    return AuthResponse(token=token, user_id=secrets.user_id)


@router.delete("/auth/session", status_code=status.HTTP_204_NO_CONTENT, summary="Log out")
async def logout(
    session: Session = Depends(get_current_session),
    credentials=Depends(bearer_scheme),
    store: SessionStore = Depends(get_store),
):
    if credentials is not None:
        store.delete(credentials.credentials)
    return None
