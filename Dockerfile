# syntax=docker/dockerfile:1

FROM python:3.12-slim AS base

# libsodium is required by pysodium for Ente-compatible crypto.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libsodium23 \
    && rm -rf /var/lib/apt/lists/*

# Install uv (fast Python package manager).
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/usr/local

WORKDIR /app

# Install dependencies first for better layer caching.
COPY pyproject.toml ./
RUN uv pip install --system \
    "fastapi>=0.115" "uvicorn[standard]>=0.30" "httpx>=0.27" \
    "pysodium>=0.7.18" "pydantic>=2.7" "pydantic-settings>=2.3" "python-dotenv>=1.0"

COPY app ./app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
