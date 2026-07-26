//! FastAPI-equivalent HTTP API built on axum.

mod account;
mod client;
mod config;
mod crypto;
mod faces;
mod files;
mod sessions;
mod srp;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};

use crate::account::{login, verify_totp, LoginError};
use crate::client::{EnteApiError, MuseumClient};
use crate::config::Settings;
use crate::files::ImageFilter;
use crate::sessions::SessionStore;

struct AppState {
    settings: Settings,
    store: SessionStore,
    /// Limits concurrent image download+decrypt operations. Provides
    /// backpressure so a burst of requests can't exhaust memory or starve the
    /// async runtime with CPU-bound decryption.
    download_sem: Arc<tokio::sync::Semaphore>,
    /// Separate, much larger budget for thumbnails. They are tens of KB, so
    /// sharing `download_sem` with multi-MB full images meant one slow photo
    /// could stall an entire grid of thumbnails behind it.
    thumb_sem: tokio::sync::Semaphore,
    /// Serializes the (expensive) library fetch so a burst of cold-cache
    /// requests can't fire N concurrent full-library refetches at museum.
    library_fetch_lock: tokio::sync::Mutex<()>,
}

/// Error type rendered as `{"detail": "..."}` (matches the FastAPI adapter).
struct AppError(StatusCode, String);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "detail": self.1 }))).into_response()
    }
}

impl From<EnteApiError> for AppError {
    fn from(e: EnteApiError) -> Self {
        AppError(StatusCode::BAD_GATEWAY, e.to_string())
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(axum::http::header::AUTHORIZATION)?.to_str().ok()?;
    let rest = value.strip_prefix("Bearer ").or_else(|| value.strip_prefix("bearer "))?;
    let rest = rest.trim();
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_string())
    }
}

fn require_token(headers: &HeaderMap) -> Result<String, AppError> {
    bearer_token(headers)
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "missing bearer token".into()))
}

// ----------------------------- OpenAPI ------------------------------------

/// Registers a `bearer` HTTP security scheme so Swagger UI shows an
/// "Authorize" button and adds the `Authorization` header to requests.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("opaque")
                        .description(Some("Token returned by POST /auth"))
                        .build(),
                ),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ente museum adapter",
        version = "0.1.0",
        description = "Adapter over a self-hosted Ente 'museum' instance. Authenticate \
            with your Ente credentials to receive a bearer token, then list, fetch \
            (decrypted) and delete images."
    ),
    paths(health, auth, auth_two_factor, logout, list_images, list_people, get_image, get_thumbnail, delete_image),
    components(schemas(
        AuthRequest,
        TwoFactorRequest,
        AuthResponse,
        TwoFactorChallenge,
        ImageSummary,
        ImageListResponse,
        FaceBox,
        Face,
        PersonSummary,
        PeopleListResponse,
        ErrorResponse,
        HealthResponse,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Login / logout"),
        (name = "images", description = "List, download and delete images"),
        (name = "people", description = "Named people (faces)"),
        (name = "meta", description = "Service metadata"),
    )
)]
struct ApiDoc;

/// The OpenAPI 3.1 spec (equivalent to FastAPI's `/openapi.json`).
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

/// Swagger UI page. Assets are loaded from a CDN to keep the binary/image tiny.
async fn swagger_ui() -> Html<&'static str> {
    Html(SWAGGER_UI_HTML)
}

const SWAGGER_UI_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Ente museum adapter — API docs</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js" crossorigin></script>
    <script>
      window.ui = SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
      });
    </script>
  </body>
</html>"##;

#[tokio::main]
async fn main() {
    // Self-contained healthcheck mode: `ente-api healthcheck` performs an HTTP
    // GET against the local /health endpoint and exits 0 (healthy) or 1.
    // This lets the `scratch` image be probed without a shell or curl.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(run_healthcheck().await);
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let settings = Settings::from_env();
    let addr = format!("{}:{}", settings.host, settings.port);
    let store = SessionStore::new(settings.session_ttl);
    let download_sem = Arc::new(tokio::sync::Semaphore::new(settings.max_concurrent_downloads));
    let thumb_sem = tokio::sync::Semaphore::new(settings.max_concurrent_thumbnails);
    let state = Arc::new(AppState {
        settings,
        store,
        download_sem,
        thumb_sem,
        library_fetch_lock: tokio::sync::Mutex::new(()),
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/auth", post(auth))
        .route("/auth/2fa", post(auth_two_factor))
        .route("/auth/session", delete(logout))
        .route("/images", get(list_images))
        .route("/images/:id", get(get_image))
        .route("/images/:id/thumbnail", get(get_thumbnail))
        .route("/images/:id", delete(delete_image))
        .route("/people", get(list_people))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(swagger_ui))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");
    tracing::info!("listening on {addr}");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Probe the local `/health` endpoint; returns a process exit code (0 = healthy).
async fn run_healthcheck() -> i32 {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8000".into());
    let url = format!("http://127.0.0.1:{port}/health");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 1,
    };
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => 0,
        _ => 1,
    }
}

/// Error body returned on failures, e.g. `{"detail": "invalid or expired token"}`.
#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    detail: String,
}

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    /// Always `"ok"`.
    status: String,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "meta",
    responses((status = 200, description = "Service is alive", body = HealthResponse))
)]
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

// ----------------------------- auth ---------------------------------------

#[derive(Deserialize, ToSchema)]
struct AuthRequest {
    /// Ente account email.
    email: String,
    /// Ente account password.
    password: String,
}

#[derive(Deserialize, ToSchema)]
struct TwoFactorRequest {
    /// Token returned by `/auth` when 2FA is required.
    mfa_token: String,
    /// 6-digit TOTP code.
    code: String,
}

/// Successful login response.
#[derive(Serialize, ToSchema)]
struct AuthResponse {
    /// Bearer token for this adapter.
    token: String,
    user_id: i64,
}

/// Returned by `/auth` when the account has 2FA enabled.
#[derive(Serialize, ToSchema)]
struct TwoFactorChallenge {
    two_factor_required: bool,
    /// Pass this back to `/auth/2fa` with your TOTP code.
    mfa_token: String,
}

#[utoipa::path(
    post,
    path = "/auth",
    tag = "auth",
    request_body = AuthRequest,
    responses(
        (status = 200, description = "Logged in (AuthResponse) or a 2FA challenge \
            (TwoFactorChallenge)", body = AuthResponse),
        (status = 400, description = "Unsupported login flow", body = ErrorResponse),
        (status = 401, description = "Incorrect email or password", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    )
)]
async fn auth(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthRequest>,
) -> Result<Json<Value>, AppError> {
    let client = MuseumClient::new(
        &state.settings.api_base(),
        state.settings.ente_timeout,
        None,
    );

    match login(&client, &body.email, &body.password).await {
        Ok(secrets) => {
            let user_id = secrets.user_id;
            let token = state.store.create(secrets);
            Ok(Json(json!({ "token": token, "user_id": user_id })))
        }
        Err(LoginError::TwoFactorRequired { session_id, kek }) => {
            let mfa_token = state.store.create_pending(session_id, kek);
            Ok(Json(json!({
                "two_factor_required": true,
                "mfa_token": mfa_token,
            })))
        }
        Err(LoginError::Unsupported(msg)) => {
            Err(AppError(StatusCode::BAD_REQUEST, msg))
        }
        Err(LoginError::Recoverable(msg)) => Err(AppError(StatusCode::UNAUTHORIZED, msg)),
        Err(LoginError::Api(e)) => Err(AppError(StatusCode::BAD_GATEWAY, e.to_string())),
    }
}

#[utoipa::path(
    post,
    path = "/auth/2fa",
    tag = "auth",
    request_body = TwoFactorRequest,
    responses(
        (status = 200, description = "Logged in", body = AuthResponse),
        (status = 401, description = "Invalid or expired 2FA token / code", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    )
)]
async fn auth_two_factor(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TwoFactorRequest>,
) -> Result<Json<Value>, AppError> {
    let pending = state
        .store
        .pop_pending(&body.mfa_token)
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired 2FA token".into()))?;

    let client = MuseumClient::new(
        &state.settings.api_base(),
        state.settings.ente_timeout,
        None,
    );

    match verify_totp(&client, &pending.two_factor_session_id, &body.code, &pending.kek).await {
        Ok(secrets) => {
            let user_id = secrets.user_id;
            let token = state.store.create(secrets);
            Ok(Json(json!({ "token": token, "user_id": user_id })))
        }
        Err(LoginError::Api(e)) => Err(AppError(StatusCode::BAD_GATEWAY, e.to_string())),
        Err(other) => Err(AppError(StatusCode::UNAUTHORIZED, other.to_string())),
    }
}

#[utoipa::path(
    delete,
    path = "/auth/session",
    tag = "auth",
    responses((status = 204, description = "Logged out")),
    security(("bearer" = []))
)]
async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    if let Some(token) = bearer_token(&headers) {
        state.store.delete(&token);
    }
    Ok(StatusCode::NO_CONTENT)
}

// ----------------------------- images -------------------------------------

#[derive(Deserialize, Default, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListQuery {
    /// Album name (substring match).
    album: Option<String>,
    /// `image` | `video` | `live_photo`.
    media_type: Option<String>,
    /// Creation time >= (microseconds since epoch).
    time_from: Option<i64>,
    /// Creation time <= (microseconds since epoch).
    time_to: Option<i64>,
    /// Only items with/without GPS coordinates.
    has_location: Option<bool>,
    min_lat: Option<f64>,
    max_lat: Option<f64>,
    min_lon: Option<f64>,
    max_lon: Option<f64>,
    /// Title/filename substring match.
    filename: Option<String>,
    /// Only items that have (`true`) or lack (`false`) detected faces.
    has_faces: Option<bool>,
    /// Only items with at least this many detected faces.
    min_faces: Option<usize>,
    /// Only items containing a detected person whose name matches (substring).
    person: Option<String>,
    /// Force a re-sync from the museum instance.
    #[serde(default)]
    refresh: bool,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

/// A bounding box for a detected face, relative to the face image dimensions.
#[derive(Serialize, ToSchema)]
struct FaceBox {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

/// A single detected face, annotated with the person it belongs to (if known).
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct Face {
    face_id: String,
    #[serde(rename = "box")]
    bounding_box: FaceBox,
    score: f64,
    blur: f64,
    person_id: Option<String>,
    person_name: Option<String>,
}

/// A single image's metadata.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct ImageSummary {
    id: i64,
    title: Option<String>,
    album: Option<String>,
    collection_id: i64,
    media_type: String,
    file_size: Option<i64>,
    creation_time: Option<i64>,
    modification_time: Option<i64>,
    latitude: Option<f64>,
    longitude: Option<f64>,
    hash: Option<String>,
    /// URL of the still-encrypted blob, so other apps can download it
    /// directly from the storage backend (e.g. the S3 bucket).
    download_url: String,
    /// Detected faces (with person names where known), from Ente's separate
    /// "mldata" dataset. Empty if face data is disabled or not yet computed.
    faces: Vec<Face>,
    /// Distinct names of people detected in this image.
    people: Vec<String>,
    /// Width of the image the face boxes are relative to.
    face_image_width: Option<i64>,
    /// Height of the image the face boxes are relative to.
    face_image_height: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct ImageListResponse {
    count: usize,
    images: Vec<ImageSummary>,
}

/// A named person and how many available images they appear in.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
struct PersonSummary {
    /// Stable Ente entity id for the person (cgroup id).
    id: String,
    /// Name the user assigned to this person.
    name: String,
    /// Number of (non-deleted) images in the library featuring this person.
    image_count: usize,
}

#[derive(Serialize, ToSchema)]
struct PeopleListResponse {
    count: usize,
    people: Vec<PersonSummary>,
}

fn default_limit() -> usize {
    500
}

/// Build an authed museum client for the given session's token.
fn authed_client(state: &AppState, token: &str) -> Result<MuseumClient, AppError> {
    let museum_token = state
        .store
        .with_session(token, |s| s.secrets.token.clone())
        .ok_or_else(|| {
            AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into())
        })?;
    Ok(MuseumClient::new(
        &state.settings.api_base(),
        state.settings.ente_timeout,
        Some(museum_token),
    ))
}

/// Ensure the session's library cache is populated; fetch + store if needed.
async fn ensure_library(
    state: &AppState,
    client: &MuseumClient,
    token: &str,
    force: bool,
) -> Result<(), AppError> {
    let needs_fetch = state
        .store
        .with_session(token, |s| force || s.library.is_none())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    if !needs_fetch {
        return Ok(());
    }

    // Single-flight: only one library fetch runs at a time. A startup burst of
    // cold-cache requests would otherwise each trigger a full library + faces
    // refetch from museum, flooding it and wedging the whole adapter.
    let _guard = state.library_fetch_lock.lock().await;

    // Re-check under the lock: another task may have just populated the cache
    // while we waited, in which case there's nothing to do (unless forced).
    if !force {
        let still_needed = state
            .store
            .with_session(token, |s| s.library.is_none())
            .ok_or_else(|| {
                AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into())
            })?;
        if !still_needed {
            return Ok(());
        }
    }

    let master_key = state
        .store
        .with_session(token, |s| s.secrets.master_key.clone())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    let library = files::fetch_library(client, &master_key).await?;

    state
        .store
        .with_session(token, |s| {
            s.library = Some(library);
            // A fresh library invalidates the people/face annotations attached to
            // the previous one; let the cheap/expensive paths re-derive them.
            s.people = None;
            s.faces_loaded = false;
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    Ok(())
}

/// Ensure named people are loaded and attached to the library. This is the
/// cheap path: it fetches the "cgroup" entities (named people) and derives each
/// file's people from them directly, without the expensive per-file mldata face
/// fetch. Used by `/people` and by person-filtered `/images`.
async fn ensure_people(
    state: &AppState,
    client: &MuseumClient,
    token: &str,
) -> Result<(), AppError> {
    if !state.settings.fetch_faces {
        return Ok(());
    }

    ensure_library(state, client, token, false).await?;

    let needs_fetch = state
        .store
        .with_session(token, |s| s.people.is_none())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    if !needs_fetch {
        return Ok(());
    }

    let _guard = state.library_fetch_lock.lock().await;
    let still_needed = state
        .store
        .with_session(token, |s| s.people.is_none())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    if !still_needed {
        return Ok(());
    }

    let master_key = state
        .store
        .with_session(token, |s| s.secrets.master_key.clone())
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    let people = match faces::fetch_people(client, &master_key).await {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("failed to load people: {e}");
            faces::PeopleIndex::default()
        }
    };

    state
        .store
        .with_session(token, |s| {
            if let Some(library) = s.library.as_mut() {
                faces::attach_people(library, &people);
            }
            s.people = Some(people);
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    Ok(())
}

/// Ensure detected face boxes (Ente's per-file "mldata") are loaded. This is the
/// expensive path — one decrypt per file, minutes on large libraries — and is
/// only needed for face-box detail or `has_faces`/`min_faces` filtering. People
/// listing and person filtering use the much cheaper `ensure_people`.
async fn ensure_faces(
    state: &AppState,
    client: &MuseumClient,
    token: &str,
) -> Result<(), AppError> {
    if !state.settings.fetch_faces {
        return Ok(());
    }

    // Named people (and their per-file assignments) first: cheap and always wanted.
    ensure_people(state, client, token).await?;

    let needs_fetch = state
        .store
        .with_session(token, |s| !s.faces_loaded)
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    if !needs_fetch {
        return Ok(());
    }

    let _guard = state.library_fetch_lock.lock().await;
    let still_needed = state
        .store
        .with_session(token, |s| !s.faces_loaded)
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    if !still_needed {
        return Ok(());
    }

    let (library, people) = state
        .store
        .with_session(token, |s| (s.library.clone(), s.people.clone()))
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    let library = library
        .ok_or_else(|| AppError(StatusCode::INTERNAL_SERVER_ERROR, "library missing".into()))?;
    let people = people.unwrap_or_default();

    let face_map = match faces::fetch_faces(
        client,
        &library,
        &people,
        state.settings.faces_batch_size,
    )
    .await
    {
        Ok(face_map) => face_map,
        Err(e) => {
            tracing::warn!("failed to load face data: {e}");
            Default::default()
        }
    };

    state
        .store
        .with_session(token, |s| {
            if let Some(library) = s.library.as_mut() {
                faces::attach_faces(library, face_map);
            }
            s.faces_loaded = true;
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;
    Ok(())
}

#[utoipa::path(
    get,
    path = "/images",
    tag = "images",
    params(ListQuery),
    responses(
        (status = 200, description = "Matching images", body = ImageListResponse),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    ),
    security(("bearer" = []))
)]
async fn list_images(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, AppError> {
    let token = require_token(&headers)?;
    let client = authed_client(&state, &token)?;
    ensure_library(&state, &client, &token, q.refresh).await?;

    // Named people are cheap to attach and let callers (e.g. the highlights
    // ingest) populate per-image people. Detected face boxes are only fetched
    // when explicitly filtering on face counts, since that is the slow path.
    ensure_people(&state, &client, &token).await?;
    if q.has_faces.is_some() || q.min_faces.is_some() {
        ensure_faces(&state, &client, &token).await?;
    }

    let filter = ImageFilter {
        album: q.album,
        media_type: q.media_type,
        time_from: q.time_from,
        time_to: q.time_to,
        has_location: q.has_location,
        min_lat: q.min_lat,
        max_lat: q.max_lat,
        min_lon: q.min_lon,
        max_lon: q.max_lon,
        filename: q.filename,
        has_faces: q.has_faces,
        min_faces: q.min_faces,
        person: q.person,
    };

    let limit = q.limit.clamp(1, 10000);
    let offset = q.offset;

    let result = state
        .store
        .with_session(&token, |s| {
            let library = s.library.as_ref().unwrap();
            let matched = files::filter_images(library, &filter);
            let count = matched.len();
            let page: Vec<Value> = matched
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|f| f.as_json(&state.settings.download_url(f.id)))
                .collect();
            json!({ "count": count, "images": page })
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;

    Ok(Json(result))
}

#[utoipa::path(
    get,
    path = "/people",
    tag = "people",
    responses(
        (status = 200, description = "Named people and their image counts",
            body = PeopleListResponse),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    ),
    security(("bearer" = []))
)]
async fn list_people(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    let token = require_token(&headers)?;
    let client = authed_client(&state, &token)?;
    ensure_people(&state, &client, &token).await?;

    let result = state
        .store
        .with_session(&token, |s| {
            let library = s.library.as_ref().unwrap();
            let people = match s.people.as_ref() {
                Some(p) => p.summaries(library),
                None => Vec::new(),
            };
            let list: Vec<Value> = people
                .into_iter()
                .map(|(id, name, image_count)| {
                    json!({ "id": id, "name": name, "imageCount": image_count })
                })
                .collect();
            json!({ "count": list.len(), "people": list })
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;

    Ok(Json(result))
}

#[utoipa::path(
    get,
    path = "/images/{id}",
    tag = "images",
    params(("id" = i64, Path, description = "Image id")),
    responses(
        (status = 200, description = "Decrypted image bytes",
            content_type = "application/octet-stream"),
        (status = 404, description = "Image not found", body = ErrorResponse),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    ),
    security(("bearer" = []))
)]
async fn get_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(image_id): Path<i64>,
) -> Result<Response, AppError> {
    let token = require_token(&headers)?;
    let client = authed_client(&state, &token)?;
    ensure_library(&state, &client, &token, false).await?;

    let file = state
        .store
        .with_session(&token, |s| {
            s.library
                .as_ref()
                .and_then(|l| l.get(&image_id).cloned())
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;

    let file = match file {
        Some(f) if !f.is_deleted => f,
        _ => return Err(AppError(StatusCode::NOT_FOUND, "image not found".into())),
    };

    // Backpressure: cap concurrent download+decrypt work. Excess requests wait
    // here rather than piling up unbounded heavy operations on the runtime.
    let permit = state
        .download_sem
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| AppError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    let (head, body) = files::download_image_stream(&client, &state.settings, &file).await?;
    let media_type = sniff_media_type(&head);
    let filename = file.title.clone().unwrap_or_else(|| image_id.to_string());
    let encrypted_url = state.settings.download_url(file.id);

    // The permit has to outlive the response body, not just this handler, or the
    // concurrency cap would stop capping anything the moment we start streaming.
    let body = async_stream::stream! {
        let _permit = permit;
        for await chunk in body {
            yield chunk;
        }
    };

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, media_type)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            format!("inline; filename=\"{filename}\""),
        )
        // Where the still-encrypted blob lives (e.g. the S3 bucket), so other
        // apps can fetch it directly instead of via this decrypting endpoint.
        .header("X-Encrypted-Download-Url", encrypted_url)
        .body(Body::from_stream(body))
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(response)
}

#[utoipa::path(
    get,
    path = "/images/{id}/thumbnail",
    tag = "images",
    params(("id" = i64, Path, description = "Image id")),
    responses(
        (status = 200, description = "Decrypted thumbnail bytes"),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse),
        (status = 404, description = "Thumbnail not found", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    ),
    security(("bearer" = []))
)]
async fn get_thumbnail(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(image_id): Path<i64>,
) -> Result<Response, AppError> {
    let token = require_token(&headers)?;
    let client = authed_client(&state, &token)?;
    ensure_library(&state, &client, &token, false).await?;

    let file = state
        .store
        .with_session(&token, |s| {
            s.library.as_ref().and_then(|l| l.get(&image_id).cloned())
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;

    let file = match file {
        Some(f) if !f.is_deleted => f,
        _ => return Err(AppError(StatusCode::NOT_FOUND, "image not found".into())),
    };

    let _permit = state
        .thumb_sem
        .acquire()
        .await
        .map_err(|e| AppError(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;

    let data = files::download_thumbnail(&client, &state.settings, &file).await?;
    let media_type = sniff_media_type(&data);
    let filename = format!(
        "{}-thumb",
        file.title.clone().unwrap_or_else(|| image_id.to_string())
    );

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, media_type)
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            format!("inline; filename=\"{filename}\""),
        )
        .body(Body::from(data))
        .map_err(|e| AppError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/images/{id}",
    tag = "images",
    params(("id" = i64, Path, description = "Image id")),
    responses(
        (status = 204, description = "Image moved to trash"),
        (status = 404, description = "Image not found", body = ErrorResponse),
        (status = 401, description = "Invalid or expired token", body = ErrorResponse),
        (status = 502, description = "Upstream museum error", body = ErrorResponse),
    ),
    security(("bearer" = []))
)]
async fn delete_image(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(image_id): Path<i64>,
) -> Result<StatusCode, AppError> {
    let token = require_token(&headers)?;
    let client = authed_client(&state, &token)?;
    ensure_library(&state, &client, &token, false).await?;

    let file = state
        .store
        .with_session(&token, |s| {
            s.library
                .as_ref()
                .and_then(|l| l.get(&image_id).cloned())
        })
        .ok_or_else(|| AppError(StatusCode::UNAUTHORIZED, "invalid or expired token".into()))?;

    let file = match file {
        Some(f) if !f.is_deleted => f,
        _ => return Err(AppError(StatusCode::NOT_FOUND, "image not found".into())),
    };

    files::delete_file(&client, image_id, file.collection_id).await?;

    state.store.with_session(&token, |s| {
        if let Some(lib) = s.library.as_mut() {
            lib.remove(&image_id);
        }
    });

    Ok(StatusCode::NO_CONTENT)
}

fn sniff_media_type(data: &[u8]) -> &'static str {
    const SIGS: &[(&[u8], &str)] = &[
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"BM", "image/bmp"),
    ];
    for (sig, mt) in SIGS {
        if data.starts_with(sig) {
            return mt;
        }
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let brand = &data[8..12];
        if matches!(brand, b"heic" | b"heix" | b"mif1" | b"heim") {
            return "image/heic";
        }
        if brand.starts_with(b"avif") {
            return "image/avif";
        }
    }
    "application/octet-stream"
}
