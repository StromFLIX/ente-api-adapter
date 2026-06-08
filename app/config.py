"""Application configuration loaded from environment / .env."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ente_api_url: str = "http://localhost:8080"
    ente_download_url: str = ""
    ente_timeout: float = 60.0
    session_ttl: int = 86400
    host: str = "0.0.0.0"
    port: int = 8000

    @property
    def api_base(self) -> str:
        return self.ente_api_url.rstrip("/")

    def download_url(self, file_id: int) -> str:
        if self.ente_download_url:
            return f"{self.ente_download_url.rstrip('/')}/{file_id}"
        return f"{self.api_base}/files/download/{file_id}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
