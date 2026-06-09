//! In-memory session store.
//!
//! Holds decrypted account secrets keyed by an opaque token, plus short-lived
//! pending-2FA entries. Nothing is persisted: secrets live only in process
//! memory and are lost on restart, by design.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;

use crate::account::AccountSecrets;
use crate::files::ImageFile;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn random_token(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(&buf)
}

pub struct Session {
    pub secrets: AccountSecrets,
    pub created_at: f64,
    pub last_used: f64,
    pub library: Option<HashMap<i64, ImageFile>>,
}

struct PendingTwoFactor {
    two_factor_session_id: String,
    kek: [u8; 32],
    created_at: f64,
}

pub struct PendingInfo {
    pub two_factor_session_id: String,
    pub kek: [u8; 32],
}

pub struct SessionStore {
    ttl: f64,
    sessions: Mutex<HashMap<String, Session>>,
    pending: Mutex<HashMap<String, PendingTwoFactor>>,
}

impl SessionStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl: ttl_seconds as f64,
            sessions: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn create(&self, account: AccountSecrets) -> String {
        let token = random_token(32);
        let t = now();
        let session = Session {
            secrets: account,
            created_at: t,
            last_used: t,
            library: None,
        };
        self.sessions.lock().unwrap().insert(token.clone(), session);
        token
    }

    /// Run `f` against a live (non-expired) session, refreshing its last-used
    /// time. Returns `None` if the session is missing or expired.
    pub fn with_session<R>(
        &self,
        token: &str,
        f: impl FnOnce(&mut Session) -> R,
    ) -> Option<R> {
        let mut guard = self.sessions.lock().unwrap();
        let expired = match guard.get(token) {
            Some(s) => now() - s.last_used > self.ttl,
            None => return None,
        };
        if expired {
            guard.remove(token);
            return None;
        }
        let session = guard.get_mut(token).unwrap();
        session.last_used = now();
        Some(f(session))
    }

    pub fn delete(&self, token: &str) -> bool {
        self.sessions.lock().unwrap().remove(token).is_some()
    }

    pub fn create_pending(&self, two_factor_session_id: String, kek: [u8; 32]) -> String {
        let token = random_token(24);
        self.pending.lock().unwrap().insert(
            token.clone(),
            PendingTwoFactor {
                two_factor_session_id,
                kek,
                created_at: now(),
            },
        );
        token
    }

    pub fn pop_pending(&self, token: &str) -> Option<PendingInfo> {
        let pending = self.pending.lock().unwrap().remove(token)?;
        if now() - pending.created_at > 600.0 {
            return None;
        }
        Some(PendingInfo {
            two_factor_session_id: pending.two_factor_session_id,
            kek: pending.kek,
        })
    }
}
