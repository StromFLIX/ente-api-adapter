//! Thin async HTTP client for the Ente "museum" API.

use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;

const CLIENT_PACKAGE: &str = "io.ente.photos";

/// Process-wide connection pools.
///
/// A `reqwest::Client` *owns* the connection pool, so building one per request
/// (which this used to do, both here and again inside `get_bytes` to follow the
/// storage redirect) throws keep-alive away and pays a fresh DNS + TCP + TLS
/// handshake on every single image. Cloning a `Client` is cheap -- it is an Arc
/// around the shared pool -- so build each one once and hand out clones.
///
/// No auth state lives on the `Client`: tokens are attached per request in
/// `apply_headers`, so one pool is safe to share across sessions and users.
static MUSEUM_POOL: OnceLock<Client> = OnceLock::new();
static STORAGE_POOL: OnceLock<Client> = OnceLock::new();

/// The museum pool. `timeout` comes from process settings and never changes at
/// runtime, so the first caller's value is the one that sticks.
fn museum_pool(timeout: u64) -> Client {
    MUSEUM_POOL
        .get_or_init(|| {
            Client::builder()
                .timeout(Duration::from_secs(timeout))
                // Redirects are followed manually so the auth token is dropped
                // before calling the storage backend.
                .redirect(Policy::none())
                .build()
                .expect("failed to build museum HTTP client")
        })
        .clone()
}

/// The storage-backend pool (e.g. S3). Follows redirects, sends no auth token.
fn storage_pool() -> Client {
    STORAGE_POOL
        .get_or_init(|| {
            Client::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("failed to build storage HTTP client")
        })
        .clone()
}

#[derive(Debug, thiserror::Error)]
pub enum EnteApiError {
    #[error("museum returned {0}: {1}")]
    Status(u16, String),
    #[error("cannot reach museum instance: {0}")]
    Transport(String),
    #[error("unexpected response: {0}")]
    Decode(String),
}

impl EnteApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            EnteApiError::Status(code, _) => *code,
            EnteApiError::Transport(_) => 502,
            EnteApiError::Decode(_) => 502,
        }
    }
}

/// Wraps a single self-hosted museum instance.
pub struct MuseumClient {
    base_url: String,
    client: Client,
    token: Option<String>,
}

impl MuseumClient {
    pub fn new(base_url: &str, timeout: u64, token: Option<String>) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client: museum_pool(timeout),
            token,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn apply_headers(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut req = req
            .header("X-Client-Package", CLIENT_PACKAGE)
            .header("Accept", "application/json");
        if let Some(token) = &self.token {
            req = req.header("X-Auth-Token", token);
        }
        req
    }

    pub async fn get(&self, path: &str, params: &[(&str, String)]) -> Result<Value, EnteApiError> {
        let req = self.apply_headers(self.client.get(self.url(path)).query(params));
        let resp = req
            .send()
            .await
            .map_err(|e| EnteApiError::Transport(e.to_string()))?;
        Self::json(resp).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, EnteApiError> {
        let req = self.apply_headers(self.client.post(self.url(path)).json(body));
        let resp = req
            .send()
            .await
            .map_err(|e| EnteApiError::Transport(e.to_string()))?;
        Self::json(resp).await
    }

    pub async fn post_no_content(&self, path: &str, body: &Value) -> Result<(), EnteApiError> {
        let req = self.apply_headers(self.client.post(self.url(path)).json(body));
        let resp = req
            .send()
            .await
            .map_err(|e| EnteApiError::Transport(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            let code = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            Err(EnteApiError::Status(code, text))
        }
    }

    /// Download a file blob, following museum's 307 redirect to storage manually
    /// (dropping the auth token before calling the storage backend).
    pub async fn get_bytes(&self, url: &str) -> Result<Vec<u8>, EnteApiError> {
        self.get_stream(url)
            .await?
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| EnteApiError::Transport(e.to_string()))
    }

    /// Same as [`get_bytes`], but hands back the response with its body still
    /// unread so the caller can consume it as it arrives.
    ///
    /// Buffering a whole blob before doing anything with it means the client's
    /// socket sits idle for the entire download, which both maximises
    /// time-to-first-byte and looks like a hung connection to any HTTP read
    /// timeout. Callers that can work incrementally should use this.
    pub async fn get_stream(&self, url: &str) -> Result<reqwest::Response, EnteApiError> {
        let req = self.apply_headers(self.client.get(url));
        let resp = req
            .send()
            .await
            .map_err(|e| EnteApiError::Transport(format!("cannot reach museum instance: {e}")))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    EnteApiError::Status(502, "museum redirect missing Location header".into())
                })?
                .to_string();

            // Clean client: follows redirects, no auth token forwarded.
            let storage_resp = storage_pool()
                .get(&location)
                .send()
                .await
                .map_err(|e| EnteApiError::Transport(format!("cannot reach file storage: {e}")))?;
            if !storage_resp.status().is_success() {
                let code = storage_resp.status().as_u16();
                // Presigned URLs carry credentials in the query string.
                let safe_url = location.split('?').next().unwrap_or(&location).to_string();
                let text = storage_resp.text().await.unwrap_or_default();
                return Err(EnteApiError::Status(
                    code,
                    format!("storage backend rejected request ({safe_url}): {text}"),
                ));
            }
            return Ok(storage_resp);
        }

        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(EnteApiError::Status(code, text));
        }
        Ok(resp)
    }

    async fn json(resp: reqwest::Response) -> Result<Value, EnteApiError> {
        let status = resp.status();
        if !status.is_success() && status != StatusCode::OK {
            let code = status.as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(EnteApiError::Status(code, text));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| EnteApiError::Decode(e.to_string()))
    }
}
