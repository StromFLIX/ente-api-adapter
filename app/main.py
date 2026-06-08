"""FastAPI application entrypoint."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from .config import get_settings
from .routers import auth, images
from .sessions import SessionStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.store = SessionStore(ttl_seconds=settings.session_ttl)
    yield


app = FastAPI(
    title="Ente museum adapter",
    version="0.1.0",
    description=(
        "Adapter over a self-hosted Ente 'museum' instance. Authenticate with "
        "your Ente credentials to receive a bearer token, then list, fetch "
        "(decrypted) and delete images."
    ),
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(images.router)


@app.get("/health", tags=["meta"], summary="Liveness check")
async def health():
    return {"status": "ok"}
