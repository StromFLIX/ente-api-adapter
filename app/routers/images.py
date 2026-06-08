"""Image listing, retrieval and deletion routes."""

from __future__ import annotations

import io

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from ..config import Settings, get_settings
from ..deps import get_current_session, make_authed_client
from ..ente import files as ente_files
from ..ente.client import EnteApiError, MuseumClient
from ..schemas import ImageListResponse, ImageSummary
from ..sessions import Session

router = APIRouter(tags=["images"])

# Minimal magic-byte sniffing so the response carries a sensible content type.
_MEDIA_SIGNATURES = [
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
]


async def _ensure_library(
    session: Session, client: MuseumClient, force: bool = False
) -> dict[int, ente_files.ImageFile]:
    if session.library is None or force:
        session.library = await ente_files.fetch_library(client, session.secrets.master_key)
    return session.library


@router.get(
    "/images",
    response_model=ImageListResponse,
    summary="List images, filterable by album, media type, time, location and filename",
)
async def list_images(
    session: Session = Depends(get_current_session),
    client: MuseumClient = Depends(make_authed_client),
    album: str | None = Query(None, description="Album name (substring match)"),
    media_type: str | None = Query(None, description="image | video | live_photo"),
    time_from: int | None = Query(None, description="Creation time >= (microseconds since epoch)"),
    time_to: int | None = Query(None, description="Creation time <= (microseconds since epoch)"),
    has_location: bool | None = Query(None, description="Only items with/without GPS coordinates"),
    min_lat: float | None = Query(None),
    max_lat: float | None = Query(None),
    min_lon: float | None = Query(None),
    max_lon: float | None = Query(None),
    filename: str | None = Query(None, description="Title/filename substring match"),
    refresh: bool = Query(False, description="Force a re-sync from the museum instance"),
    limit: int = Query(500, ge=1, le=10000),
    offset: int = Query(0, ge=0),
):
    try:
        async with client:
            library = await _ensure_library(session, client, force=refresh)
    except EnteApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, exc.message) from exc

    matched = ente_files.filter_images(
        library,
        album=album,
        media_type=media_type,
        time_from=time_from,
        time_to=time_to,
        has_location=has_location,
        min_lat=min_lat,
        max_lat=max_lat,
        min_lon=min_lon,
        max_lon=max_lon,
        filename=filename,
    )
    page = matched[offset : offset + limit]
    return ImageListResponse(
        count=len(matched),
        images=[ImageSummary(**f.as_dict()) for f in page],
    )


@router.get(
    "/images/{image_id}",
    summary="Download a single image, decrypted server-side",
    response_class=StreamingResponse,
)
async def get_image(
    image_id: int,
    session: Session = Depends(get_current_session),
    client: MuseumClient = Depends(make_authed_client),
):
    try:
        async with client:
            library = await _ensure_library(session, client)
            file = library.get(image_id)
            if file is None or file.is_deleted:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "image not found")
            settings: Settings = get_settings()
            data = await ente_files.download_image(client, settings, file)
    except EnteApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, exc.message) from exc

    media_type = _sniff_media_type(data)
    filename = file.title or f"{image_id}"
    headers = {"Content-Disposition": f'inline; filename="{filename}"'}
    return StreamingResponse(io.BytesIO(data), media_type=media_type, headers=headers)


@router.delete(
    "/images/{image_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete (trash) an image",
)
async def delete_image(
    image_id: int,
    session: Session = Depends(get_current_session),
    client: MuseumClient = Depends(make_authed_client),
):
    try:
        async with client:
            library = await _ensure_library(session, client)
            file = library.get(image_id)
            if file is None or file.is_deleted:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "image not found")
            await ente_files.delete_file(client, image_id, file.collection_id)
    except EnteApiError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, exc.message) from exc

    # Drop from the cached view so subsequent calls reflect the deletion.
    if session.library is not None:
        session.library.pop(image_id, None)
    return None


def _sniff_media_type(data: bytes) -> str:
    for signature, media_type in _MEDIA_SIGNATURES:
        if data.startswith(signature):
            return media_type
    # HEIC/HEIF and others use an ftyp box at offset 4.
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1", b"heim"):
            return "image/heic"
        if brand.startswith(b"avif"):
            return "image/avif"
    return "application/octet-stream"
