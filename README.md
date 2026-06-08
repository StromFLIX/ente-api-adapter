# ente-api

A small **FastAPI** adapter in front of a single self-hosted
[Ente](https://github.com/ente-io/ente) **"museum"** instance.

It logs in with your Ente credentials (SRP, optional TOTP), keeps the decrypted
keys **in memory**, and exposes a simple REST API to **list**, **fetch
(decrypted)** and **delete** images. All end-to-end-encryption is handled
server-side so clients receive plaintext images.

> Ente's museum API is unpublished/undocumented. This adapter reimplements the
> auth and crypto flows from Ente's open-source Go CLI and uses **libsodium**
> for byte-for-byte compatibility.

## Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/auth` | Log in with `{email, password}`. Returns `{token, user_id}`, or a 2FA challenge `{two_factor_required, mfa_token}`. |
| `POST` | `/auth/2fa` | Complete 2FA with `{mfa_token, code}`. Returns `{token, user_id}`. |
| `DELETE` | `/auth/session` | Log out (drops in-memory keys for the token). |
| `GET` | `/images` | List/filter images. |
| `GET` | `/images/{id}` | Download a single image, **decrypted**. |
| `DELETE` | `/images/{id}` | Move an image to trash. |
| `GET` | `/health` | Liveness check. |

Authenticated routes expect `Authorization: Bearer <token>`.

### `GET /images` filters

All optional, combinable query params:

- `album` — album name (substring match)
- `media_type` — `image` | `video` | `live_photo`
- `time_from`, `time_to` — creation time bounds, **microseconds since epoch**
- `has_location` — `true`/`false` (items with/without GPS)
- `min_lat`, `max_lat`, `min_lon`, `max_lon` — bounding box
- `filename` — title/filename substring
- `refresh` — `true` to force a re-sync from museum
- `limit`, `offset` — pagination

**Detected faces:** Ente stores face/ML data in a *separately-derived* dataset
(not in core file metadata), and it is computed client-side. This adapter
returns a stable empty `faces: []` field on each image as a documented stub;
full face filtering would require replicating Ente's ML pipeline.

## How auth & decryption work

1. `GET /users/srp/attributes` → derive the key-encryption-key with Argon2id.
2. SRP-6a handshake (node-srp variant, 4096-bit, SHA-256) proves the password.
3. The login response yields the encrypted master/secret keys and token, which
   are decrypted locally (secretbox + sealed box) to obtain the museum
   `X-Auth-Token` and the **master key**.
4. The master key decrypts per-collection keys; collection keys decrypt
   per-file keys; file keys decrypt metadata and the file blob
   (XChaCha20-Poly1305 secretstream).

The adapter issues its **own opaque bearer token** and holds the decrypted keys
in process memory only. They are never written to disk and are lost on restart.

## Run with Docker (recommended)

libsodium is installed in the image.

```bash
cp .env.example .env          # set ENTE_API_URL to your museum instance
docker compose up --build
# API on http://localhost:8000  (docs at /docs)
```

Or with plain Docker:

```bash
docker build -t ente-api .
docker run --rm -p 8000:8000 -e ENTE_API_URL=https://api.ente.example.com ente-api
```

## Run locally with uv

Requires libsodium on the host (`apt install libsodium23` / `brew install libsodium`).

```bash
uv sync
cp .env.example .env
uv run uvicorn app.main:app --reload
```

## Configuration (.env)

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `ENTE_API_URL` | `http://localhost:8080` | Base URL of your museum instance. |
| `ENTE_DOWNLOAD_URL` | *(empty)* | Optional separate blob host; defaults to `ENTE_API_URL/files/download/{id}`. |
| `ENTE_TIMEOUT` | `60` | Upstream request timeout (seconds). |
| `SESSION_TTL` | `86400` | Session lifetime (seconds) for issued tokens. |

## Example

```bash
# 1. Log in
TOKEN=$(curl -s localhost:8000/auth \
  -H 'content-type: application/json' \
  -d '{"email":"me@example.com","password":"secret"}' | jq -r .token)

# 2. List images taken with a location, in album "Trips"
curl -s "localhost:8000/images?album=Trips&has_location=true" \
  -H "Authorization: Bearer $TOKEN" | jq

# 3. Download one (decrypted)
curl -s "localhost:8000/images/12345" \
  -H "Authorization: Bearer $TOKEN" -o photo.jpg

# 4. Delete one
curl -s -X DELETE "localhost:8000/images/12345" \
  -H "Authorization: Bearer $TOKEN"
```

## Security notes

- Decryption keys live only in memory, mapped to the issued bearer token.
- Run this adapter over HTTPS; the bearer token grants full access to the
  account's decrypted media for its lifetime.
- This talks to a **single** configured museum instance.
