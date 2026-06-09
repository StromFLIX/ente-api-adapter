//! Thin async HTTP client for the Ente "museum" API.

use reqwest::redirect::Policy;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

const CLIENT_PACKAGE: &str = "io.ente.photos";

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
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout))
            .redirect(Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
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
            let storage = Client::builder()
                .timeout(self.client_timeout())
                .build()
                .map_err(|e| EnteApiError::Transport(e.to_string()))?;
            let storage_resp = storage
                .get(&location)
                .send()
                .await
                .map_err(|e| EnteApiError::Transport(format!("cannot reach file storage: {e}")))?;
            if !storage_resp.status().is_success() {
                let code = storage_resp.status().as_u16();
                let safe_url = location.split('?').next().unwrap_or(&location).to_string();
                let text = storage_resp.text().await.unwrap_or_default();
                return Err(EnteApiError::Status(
                    code,
                    format!("storage backend rejected request ({safe_url}): {text}"),
                ));
            }
            return storage_resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .map_err(|e| EnteApiError::Transport(e.to_string()));
        }

        if !resp.status().is_success() {
            let code = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            return Err(EnteApiError::Status(code, text));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| EnteApiError::Transport(e.to_string()))
    }

    fn client_timeout(&self) -> Duration {
        Duration::from_secs(60)
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
