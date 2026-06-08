"""Thin async HTTP client for the Ente "museum" API."""

from __future__ import annotations

from typing import Any

import httpx

# Ente clients identify themselves with these headers. The mobile/photos app
# package is used; museum only requires the token header for authenticated
# routes, but sending a client package keeps behaviour consistent.
_CLIENT_PACKAGE = "io.ente.photos"


class EnteApiError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"museum returned {status_code}: {message}")
        self.status_code = status_code
        self.message = message


class MuseumClient:
    """Wraps a single self-hosted museum instance."""

    def __init__(self, base_url: str, timeout: float, token: str | None = None) -> None:
        headers = {
            "X-Client-Package": _CLIENT_PACKAGE,
            "Accept": "application/json",
        }
        if token:
            headers["X-Auth-Token"] = token
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, headers=headers)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "MuseumClient":
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    def set_token(self, token: str) -> None:
        self._client.headers["X-Auth-Token"] = token

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        resp = await self._request("GET", path, params=params)
        return self._json(resp)

    async def post(self, path: str, json: dict[str, Any]) -> dict[str, Any]:
        resp = await self._request("POST", path, json=json)
        return self._json(resp)

    async def delete(self, path: str, json: dict[str, Any] | None = None) -> None:
        resp = await self._request("DELETE", path, json=json)
        if resp.is_error:
            raise EnteApiError(resp.status_code, resp.text)

    async def get_bytes(self, url: str) -> bytes:
        """Download a file blob.

        museum's ``/files/download/{id}`` replies with a 307 redirect to the
        storage backend (MinIO/S3). We follow the redirect manually so we can
        drop the ``X-Auth-Token`` header before calling the storage URL (museum
        itself flags forwarding the token to another service as critical).
        """
        try:
            resp = await self._client.get(url, follow_redirects=False)
        except httpx.RequestError as exc:
            raise EnteApiError(502, f"cannot reach museum instance: {exc}") from exc

        if resp.is_redirect:
            location = resp.headers.get("location")
            if not location:
                raise EnteApiError(502, "museum redirect missing Location header")
            try:
                async with httpx.AsyncClient(timeout=self._client.timeout) as storage:
                    storage_resp = await storage.get(location, follow_redirects=True)
            except httpx.RequestError as exc:
                raise EnteApiError(502, f"cannot reach file storage: {exc}") from exc
            if storage_resp.is_error:
                # Strip the query string so we don't leak the presigned signature
                # while still surfacing which storage endpoint replied.
                safe_url = str(httpx.URL(location).copy_with(query=None))
                raise EnteApiError(
                    storage_resp.status_code,
                    f"storage backend rejected request ({safe_url}): {storage_resp.text}",
                )
            return storage_resp.content

        if resp.is_error:
            raise EnteApiError(resp.status_code, resp.text)
        return resp.content

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._client.request(method, url, **kwargs)
        except httpx.RequestError as exc:
            raise EnteApiError(502, f"cannot reach museum instance: {exc}") from exc

    @staticmethod
    def _json(resp: httpx.Response) -> dict[str, Any]:
        if resp.is_error:
            raise EnteApiError(resp.status_code, resp.text)
        return resp.json()
