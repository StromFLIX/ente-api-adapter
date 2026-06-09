# ente-api

A small, **single-binary Rust** adapter (built on [axum](https://github.com/tokio-rs/axum))
in front of a single self-hosted
[Ente](https://github.com/ente-io/ente) **"museum"** instance.

It logs in with your Ente credentials (SRP, optional TOTP), keeps the decrypted
keys **in memory**, and exposes a simple REST API to **list**, **fetch
(decrypted)** and **delete** images. All end-to-end-encryption is handled
server-side so clients receive plaintext images.

> Ente's museum API is unpublished/undocumented. This adapter reimplements the
> auth and crypto flows from Ente's open-source Go CLI. The crypto is built on
> the pure-Rust, libsodium-compatible [`dryoc`](https://crates.io/crates/dryoc)
> crate and is verified **byte-for-byte** against libsodium with test vectors.

## Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| `POST` | `/auth` | Log in with `{email, password}`. Returns `{token, user_id}`, or a 2FA challenge `{two_factor_required, mfa_token}`. |
| `POST` | `/auth/2fa` | Complete 2FA with `{mfa_token, code}`. Returns `{token, user_id}`. |
| `DELETE` | `/auth/session` | Log out (drops in-memory keys for the token). |
| `GET` | `/images` | List/filter images. |
| `GET` | `/images/{id}` | Download a single image, **decrypted**. |
| `DELETE` | `/images/{id}` | Move an image to trash. |
| `GET` | `/people` | List named people (faces) and their image counts. |
| `GET` | `/health` | Liveness check. |
| `GET` | `/openapi.json` | OpenAPI 3.1 schema. |
| `GET` | `/docs` | Swagger UI (assets loaded from a CDN). |

Authenticated routes expect `Authorization: Bearer <token>`.

### `GET /images` filters

All optional, combinable query params:

- `album` — album name (substring match)
- `media_type` — `image` | `video` | `live_photo`
- `time_from`, `time_to` — creation time bounds, **microseconds since epoch**
- `has_location` — `true`/`false` (items with/without GPS)
- `min_lat`, `max_lat`, `min_lon`, `max_lon` — bounding box
- `filename` — title/filename substring
- `has_faces` — `true`/`false` (items with/without detected faces)
- `min_faces` — only items with at least this many detected faces
- `person` — person name (substring match) of a detected face
- `refresh` — `true` to force a re-sync from museum
- `limit`, `offset` — pagination

**Detected faces:** Ente computes face/ML data client-side and stores it in a
*separately-derived* dataset (Ente's "mldata"), with named people kept as
encrypted `cgroup` user entities. This adapter fetches and decrypts both during
sync, so every image carries a real `faces` array. Each face includes its
bounding `box`, detection `score`, `blur`, and — when the face belongs to a
person you've named in Ente — the `personId` and `personName`. Each image also
exposes a `people` array (distinct names) and the `faceImageWidth`/
`faceImageHeight` the boxes are relative to. Use `GET /people` to list all named
people with how many images each appears in (handy for building per-person
highlights). Face fetching can be disabled with `ENTE_FETCH_FACES=false`.

### `GET /people`

Returns named people (those you've assigned a name to in Ente) sorted by image
count:

```json
{
  "count": 2,
  "people": [
    { "id": "<entity-id>", "name": "Alice", "imageCount": 87 },
    { "id": "<entity-id>", "name": "Bob", "imageCount": 41 }
  ]
}
```

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

## Footprint

The project compiles to a single static binary on a `scratch` image — no OS,
no runtime, no system libraries. For reference, here is how it compared to an
earlier Python/FastAPI prototype (`wrk`, 4 threads / 50 connections, `GET /health`):

| Metric | Python (FastAPI) | Rust (axum) | Improvement |
| ------ | ---------------- | ----------- | ----------- |
| Docker image | 281 MB | **3.3 MB** | ~85× smaller |
| Idle RAM | 41 MiB | **1.4 MiB** | ~29× less |
| RAM under load | 41.6 MiB | **3.2 MiB** | ~13× less |
| Throughput | 4,386 req/s | **39,704 req/s** | ~9× faster |
| Latency p50 | 12.15 ms | **1.01 ms** | ~12× lower |
| Latency p99 | 24.93 ms | **4.97 ms** | ~5× lower |

## Run with Docker (recommended)

The image is a static binary on `scratch`; nothing else is installed.

```bash
cp .env.example .env        # set ENTE_API_URL to your museum instance
docker compose up --build
# API on http://localhost:8000
```

Or with plain Docker:

```bash
docker build -t ente-api .
docker run --rm -p 8000:8000 -e ENTE_API_URL=https://api.ente.example.com ente-api
```

## Run locally with Cargo

Requires a [Rust toolchain](https://rustup.rs/) (stable). No system libraries
are needed — the crypto is pure Rust.

```bash
cp .env.example .env
cargo run --release
```

Run the crypto/SRP compatibility tests (vectors are checked into `tests/`):

```bash
cargo test
```

## Configuration (.env)

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `ENTE_API_URL` | `http://localhost:8080` | Base URL of your museum instance. |
| `ENTE_DOWNLOAD_URL` | *(empty)* | Optional separate blob host; defaults to `ENTE_API_URL/files/download/{id}`. |
| `ENTE_TIMEOUT` | `60` | Upstream request timeout (seconds). |
| `SESSION_TTL` | `86400` | Session lifetime (seconds) for issued tokens. |
| `ENTE_FETCH_FACES` | `true` | Fetch detected faces + named people during sync. |
| `ENTE_FACES_BATCH` | `200` | Files per batch when fetching face/ML data. |

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

# 5. List named people and their image counts
curl -s "localhost:8000/people" \
  -H "Authorization: Bearer $TOKEN" | jq

# 6. All photos of "Alice" that have at least 2 faces
curl -s "localhost:8000/images?person=Alice&min_faces=2" \
  -H "Authorization: Bearer $TOKEN" | jq
```

## Security notes

- Decryption keys live only in memory, mapped to the issued bearer token.
- Run this adapter over HTTPS; the bearer token grants full access to the
  account's decrypted media for its lifetime.
- This talks to a **single** configured museum instance.
