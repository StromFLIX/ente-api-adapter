"""Collection + file synchronisation, metadata decryption and downloads.

This builds an in-memory view of the user's library by:
1. fetching all collections (albums) and decrypting their keys/names,
2. paging through each collection's file diff and decrypting per-file keys
   and metadata,
3. exposing filtering helpers and a download-and-decrypt routine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .client import MuseumClient
from .crypto import (
    b64decode,
    decrypt_chacha,
    decrypt_file_stream,
    secretbox_open,
)

# Ente file types.
FILE_TYPE_IMAGE = 0
FILE_TYPE_VIDEO = 1
FILE_TYPE_LIVE_PHOTO = 2

_FILE_TYPE_NAMES = {
    FILE_TYPE_IMAGE: "image",
    FILE_TYPE_VIDEO: "video",
    FILE_TYPE_LIVE_PHOTO: "live_photo",
}


@dataclass
class Album:
    id: int
    name: str
    key: bytes
    is_deleted: bool = False


@dataclass
class ImageFile:
    id: int
    collection_id: int
    album_name: str
    key: bytes
    # secretstream header (nonce) for the encrypted blob.
    decryption_header: str
    file_size: int | None
    title: str | None
    file_type: int
    creation_time: int | None  # microseconds since epoch
    modification_time: int | None
    latitude: float | None
    longitude: float | None
    file_hash: str | None
    is_deleted: bool = False
    raw_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def media_type(self) -> str:
        return _FILE_TYPE_NAMES.get(self.file_type, "unknown")

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "album": self.album_name,
            "collectionId": self.collection_id,
            "mediaType": self.media_type,
            "fileSize": self.file_size,
            "creationTime": self.creation_time,
            "modificationTime": self.modification_time,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "hash": self.file_hash,
            # Face/ML data is not part of core file metadata in Ente; it lives
            # in a separately-derived ML dataset. Exposed as an empty list so
            # the field is stable for clients. See README for details.
            "faces": [],
        }


def _decrypt_album(raw: dict[str, Any], master_key: bytes) -> Album:
    key = secretbox_open(raw["encryptedKey"], raw["keyDecryptionNonce"], master_key)
    name = raw.get("name") or ""
    if not name and raw.get("encryptedName") and raw.get("nameDecryptionNonce"):
        name = secretbox_open(raw["encryptedName"], raw["nameDecryptionNonce"], key).decode(
            "utf-8", "replace"
        )
    if not name:
        magic = raw.get("magicMetadata")
        if magic and magic.get("data") and magic.get("header"):
            try:
                meta = json.loads(decrypt_chacha(magic["data"], key, magic["header"]))
                name = meta.get("name") or meta.get("title") or ""
            except Exception:  # noqa: BLE001 - best effort album name
                name = ""
    return Album(
        id=int(raw["id"]),
        name=name or f"album-{raw['id']}",
        key=key,
        is_deleted=bool(raw.get("isDeleted")),
    )


def _decode_metadata(attr: dict[str, Any] | None, key: bytes) -> dict[str, Any]:
    if not attr or not attr.get("encryptedData") or not attr.get("decryptionHeader"):
        return {}
    try:
        return json.loads(decrypt_chacha(attr["encryptedData"], key, attr["decryptionHeader"]))
    except Exception:  # noqa: BLE001 - tolerate undecryptable metadata
        return {}


def _decrypt_file(raw: dict[str, Any], album: Album) -> ImageFile | None:
    if raw.get("isDeleted"):
        return ImageFile(
            id=int(raw["id"]),
            collection_id=album.id,
            album_name=album.name,
            key=b"",
            decryption_header="",
            file_size=None,
            title=None,
            file_type=FILE_TYPE_IMAGE,
            creation_time=None,
            modification_time=None,
            latitude=None,
            longitude=None,
            file_hash=None,
            is_deleted=True,
        )

    file_key = secretbox_open(raw["encryptedKey"], raw["keyDecryptionNonce"], album.key)
    metadata = _decode_metadata(raw.get("metadata"), file_key)
    pub_magic = _decode_metadata(raw.get("pubMagicMetadata"), file_key)

    latitude = _coalesce_float(pub_magic.get("lat"), metadata.get("latitude"))
    longitude = _coalesce_float(pub_magic.get("long"), metadata.get("longitude"))
    if latitude == 0 and longitude == 0:
        latitude = longitude = None

    creation = pub_magic.get("editedTime") or metadata.get("creationTime")
    title = pub_magic.get("editedName") or metadata.get("title")

    info = raw.get("info") or {}

    return ImageFile(
        id=int(raw["id"]),
        collection_id=album.id,
        album_name=album.name,
        key=file_key,
        decryption_header=raw["file"]["decryptionHeader"],
        file_size=info.get("fileSize"),
        title=title,
        file_type=int(metadata.get("fileType", FILE_TYPE_IMAGE)),
        creation_time=_as_int(creation),
        modification_time=_as_int(metadata.get("modificationTime")),
        latitude=latitude,
        longitude=longitude,
        file_hash=metadata.get("hash"),
        raw_metadata=metadata,
    )


def _as_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _coalesce_float(*values: Any) -> float | None:
    for value in values:
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


async def fetch_library(client: MuseumClient, master_key: bytes) -> dict[int, ImageFile]:
    """Fetch and decrypt the full library; returns {file_id: ImageFile}.

    The latest entry wins when a file appears in multiple collection diffs.
    Deleted entries remove the file from the result.
    """
    collections = await client.get("/collections/v2", params={"sinceTime": 0})
    files: dict[int, ImageFile] = {}

    for raw_album in collections.get("collections", []):
        album = _decrypt_album(raw_album, master_key)
        if album.is_deleted:
            continue
        async for raw_file in _iter_collection_files(client, album.id):
            decrypted = _decrypt_file(raw_file, album)
            if decrypted is None:
                continue
            if decrypted.is_deleted:
                files.pop(decrypted.id, None)
            else:
                files[decrypted.id] = decrypted
    return files


async def _iter_collection_files(client: MuseumClient, collection_id: int):
    since = 0
    while True:
        page = await client.get(
            "/collections/v2/diff",
            params={"collectionID": collection_id, "sinceTime": since},
        )
        diff = page.get("diff", [])
        for entry in diff:
            yield entry
            since = max(since, int(entry.get("updationTime", since)))
        if not page.get("hasMore") or not diff:
            break


async def download_image(
    client: MuseumClient, settings, file: ImageFile
) -> bytes:
    """Download and decrypt a single file's bytes."""
    encrypted = await client.get_bytes(settings.download_url(file.id))
    return decrypt_file_stream(encrypted, file.key, b64decode(file.decryption_header))


def filter_images(
    files: dict[int, ImageFile],
    *,
    album: str | None = None,
    media_type: str | None = None,
    time_from: int | None = None,
    time_to: int | None = None,
    has_location: bool | None = None,
    min_lat: float | None = None,
    max_lat: float | None = None,
    min_lon: float | None = None,
    max_lon: float | None = None,
    filename: str | None = None,
) -> list[ImageFile]:
    """Filter the decrypted library by the supported fields.

    Time bounds are in microseconds since epoch (matching Ente metadata).
    """
    result: list[ImageFile] = []
    album_lc = album.lower() if album else None
    media_lc = media_type.lower() if media_type else None
    filename_lc = filename.lower() if filename else None

    for file in files.values():
        if file.is_deleted:
            continue
        if album_lc and album_lc not in file.album_name.lower():
            continue
        if media_lc and file.media_type != media_lc:
            continue
        if time_from is not None and (file.creation_time is None or file.creation_time < time_from):
            continue
        if time_to is not None and (file.creation_time is None or file.creation_time > time_to):
            continue
        located = file.latitude is not None and file.longitude is not None
        if has_location is not None and located != has_location:
            continue
        if min_lat is not None and (not located or file.latitude < min_lat):
            continue
        if max_lat is not None and (not located or file.latitude > max_lat):
            continue
        if min_lon is not None and (not located or file.longitude < min_lon):
            continue
        if max_lon is not None and (not located or file.longitude > max_lon):
            continue
        if filename_lc and (not file.title or filename_lc not in file.title.lower()):
            continue
        result.append(file)

    result.sort(key=lambda f: (f.creation_time or 0), reverse=True)
    return result


async def delete_file(client: MuseumClient, file_id: int, collection_id: int) -> None:
    """Move a file to trash (Ente's delete semantics)."""
    await client.post(
        "/files/trash",
        json={"items": [{"fileID": file_id, "collectionID": collection_id}]},
    )
