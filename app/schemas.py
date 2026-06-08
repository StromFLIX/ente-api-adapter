"""Pydantic request/response models for the adapter API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    email: str
    password: str


class TwoFactorRequest(BaseModel):
    mfa_token: str = Field(..., description="Token returned by /auth when 2FA is required")
    code: str = Field(..., description="6-digit TOTP code")


class AuthResponse(BaseModel):
    token: str = Field(..., description="Bearer token for this adapter")
    user_id: int


class TwoFactorChallenge(BaseModel):
    two_factor_required: bool = True
    mfa_token: str = Field(..., description="Pass this back to /auth/2fa with your TOTP code")


class ImageSummary(BaseModel):
    id: int
    title: str | None = None
    album: str | None = None
    collectionId: int
    mediaType: str
    fileSize: int | None = None
    creationTime: int | None = None
    modificationTime: int | None = None
    latitude: float | None = None
    longitude: float | None = None
    hash: str | None = None
    faces: list = Field(default_factory=list)


class ImageListResponse(BaseModel):
    count: int
    images: list[ImageSummary]
