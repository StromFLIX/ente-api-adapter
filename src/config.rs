//! Application configuration loaded from environment / .env.

use std::env;

#[derive(Clone)]
pub struct Settings {
    pub ente_api_url: String,
    pub ente_download_url: String,
    pub ente_timeout: u64,
    pub session_ttl: u64,
    pub host: String,
    pub port: u16,
    /// Whether to fetch detected faces + person names from museum during sync.
    pub fetch_faces: bool,
    /// Number of files per `/files/data/fetch` batch when loading face data.
    pub faces_batch_size: usize,
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(v) => matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

impl Settings {
    pub fn from_env() -> Self {
        Self {
            ente_api_url: env_or("ENTE_API_URL", "http://localhost:8080"),
            ente_download_url: env_or("ENTE_DOWNLOAD_URL", ""),
            ente_timeout: env_or("ENTE_TIMEOUT", "60").parse().unwrap_or(60),
            session_ttl: env_or("SESSION_TTL", "86400").parse().unwrap_or(86400),
            host: env_or("HOST", "0.0.0.0"),
            port: env_or("PORT", "8000").parse().unwrap_or(8000),
            fetch_faces: env_bool("ENTE_FETCH_FACES", true),
            faces_batch_size: env_or("ENTE_FACES_BATCH", "200").parse().unwrap_or(200),
        }
    }

    pub fn api_base(&self) -> String {
        self.ente_api_url.trim_end_matches('/').to_string()
    }

    pub fn download_url(&self, file_id: i64) -> String {
        if !self.ente_download_url.is_empty() {
            format!("{}/{}", self.ente_download_url.trim_end_matches('/'), file_id)
        } else {
            format!("{}/files/download/{}", self.api_base(), file_id)
        }
    }
}
