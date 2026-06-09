//! Ente login (SRP) and account-secret decryption.

use serde_json::{json, Value};

use crate::client::{EnteApiError, MuseumClient};
use crate::crypto::{
    b64decode, b64encode, b64encode_url, derive_key_encryption_key, derive_login_key,
    sealed_box_open, secretbox_open,
};
use crate::srp::SrpClient;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("{0}")]
    Recoverable(String),
    /// Login requires a flow this adapter does not implement (passkey/email).
    #[error("{0}")]
    Unsupported(String),
    /// 2FA required: carries session id and the KEK needed to decrypt later.
    #[error("two-factor authentication required")]
    TwoFactorRequired { session_id: String, kek: [u8; 32] },
    #[error(transparent)]
    Api(#[from] EnteApiError),
}

#[derive(Clone)]
pub struct AccountSecrets {
    pub user_id: i64,
    pub token: String,
    pub master_key: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

fn s(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

async fn get_srp_attributes(client: &MuseumClient, email: &str) -> Result<Value, LoginError> {
    let res = client
        .get("/users/srp/attributes", &[("email", email.to_string())])
        .await?;
    let attrs = res.get("attributes").cloned().ok_or_else(|| {
        LoginError::Unsupported("account has no SRP attributes (use email/passkey login)".into())
    })?;
    if attrs.is_null() {
        return Err(LoginError::Unsupported(
            "account has no SRP attributes (use email/passkey login)".into(),
        ));
    }
    Ok(attrs)
}

pub async fn login(
    client: &MuseumClient,
    email: &str,
    password: &str,
) -> Result<AccountSecrets, LoginError> {
    let attrs = get_srp_attributes(client, email).await?;

    if attrs.get("isEmailMFAEnabled").and_then(Value::as_bool) == Some(true) {
        return Err(LoginError::Unsupported(
            "account uses email-based MFA, which is not supported".into(),
        ));
    }

    let kek_salt = s(&attrs, "kekSalt")
        .ok_or_else(|| LoginError::Recoverable("missing kekSalt".into()))?;
    let mem_limit = attrs
        .get("memLimit")
        .and_then(Value::as_u64)
        .ok_or_else(|| LoginError::Recoverable("missing memLimit".into()))? as usize;
    let ops_limit = attrs
        .get("opsLimit")
        .and_then(Value::as_u64)
        .ok_or_else(|| LoginError::Recoverable("missing opsLimit".into()))?;

    let kek = derive_key_encryption_key(password, &kek_salt, mem_limit, ops_limit)
        .map_err(|e| LoginError::Recoverable(e.to_string()))?;
    let login_key = derive_login_key(&kek).map_err(|e| LoginError::Recoverable(e.to_string()))?;

    let srp_user_id = s(&attrs, "srpUserID")
        .ok_or_else(|| LoginError::Recoverable("missing srpUserID".into()))?;
    let srp_salt = s(&attrs, "srpSalt")
        .ok_or_else(|| LoginError::Recoverable("missing srpSalt".into()))?;
    let salt = b64decode(&srp_salt).map_err(|e| LoginError::Recoverable(e.to_string()))?;

    let srp = SrpClient::new(srp_user_id.as_bytes(), &salt, &login_key);

    let session = client
        .post(
            "/users/srp/create-session",
            &json!({"srpUserID": srp_user_id, "srpA": b64encode(&srp.a_bytes())}),
        )
        .await
        .map_err(|e| match e {
            EnteApiError::Status(_, msg) => {
                LoginError::Recoverable(format!("failed to create SRP session: {msg}"))
            }
            other => LoginError::Api(other),
        })?;

    let srp_b = s(&session, "srpB")
        .ok_or_else(|| LoginError::Recoverable("missing srpB".into()))?;
    let session_id = s(&session, "sessionID")
        .ok_or_else(|| LoginError::Recoverable("missing sessionID".into()))?;
    let b_bytes = b64decode(&srp_b).map_err(|e| LoginError::Recoverable(e.to_string()))?;
    let m1 = srp
        .compute_m1(&b_bytes)
        .map_err(|e| LoginError::Recoverable(e.to_string()))?;

    let auth = client
        .post(
            "/users/srp/verify-session",
            &json!({
                "srpUserID": srp_user_id,
                "sessionID": session_id,
                "srpM1": b64encode(&m1),
            }),
        )
        .await
        .map_err(|e| match e {
            EnteApiError::Status(code, _) if code == 401 || code == 400 => {
                LoginError::Recoverable("incorrect email or password".into())
            }
            EnteApiError::Status(_, msg) => {
                LoginError::Recoverable(format!("SRP verification failed: {msg}"))
            }
            other => LoginError::Api(other),
        })?;

    if let Some(pk) = s(&auth, "passkeySessionID") {
        if !pk.is_empty() {
            return Err(LoginError::Unsupported(
                "account requires passkey verification".into(),
            ));
        }
    }
    if let Some(tf) = s(&auth, "twoFactorSessionID") {
        if !tf.is_empty() {
            return Err(LoginError::TwoFactorRequired {
                session_id: tf,
                kek,
            });
        }
    }

    decrypt_secrets(&auth, &kek)
}

pub async fn verify_totp(
    client: &MuseumClient,
    session_id: &str,
    code: &str,
    kek: &[u8; 32],
) -> Result<AccountSecrets, LoginError> {
    let auth = client
        .post(
            "/users/two-factor/verify",
            &json!({"sessionID": session_id, "code": code}),
        )
        .await
        .map_err(|_| LoginError::Recoverable("invalid two-factor code".into()))?;
    decrypt_secrets(&auth, kek)
}

fn decrypt_secrets(auth: &Value, kek: &[u8; 32]) -> Result<AccountSecrets, LoginError> {
    let key_attrs = auth.get("keyAttributes").cloned().unwrap_or(Value::Null);
    let encrypted_token = s(auth, "encryptedToken");
    if key_attrs.is_null() || encrypted_token.is_none() {
        return Err(LoginError::Recoverable(
            "login response missing key attributes or token".into(),
        ));
    }

    let get = |k: &str| -> Result<String, LoginError> {
        s(&key_attrs, k).ok_or_else(|| LoginError::Recoverable(format!("missing {k}")))
    };

    let master_key = secretbox_open(&get("encryptedKey")?, &get("keyDecryptionNonce")?, kek)
        .map_err(|e| LoginError::Recoverable(e.to_string()))?;
    let secret_key = secretbox_open(
        &get("encryptedSecretKey")?,
        &get("secretKeyDecryptionNonce")?,
        &master_key,
    )
    .map_err(|e| LoginError::Recoverable(e.to_string()))?;
    let public_key =
        b64decode(&get("publicKey")?).map_err(|e| LoginError::Recoverable(e.to_string()))?;
    let token_bytes = sealed_box_open(&encrypted_token.unwrap(), &public_key, &secret_key)
        .map_err(|e| LoginError::Recoverable(e.to_string()))?;

    let user_id = auth
        .get("id")
        .and_then(Value::as_i64)
        .ok_or_else(|| LoginError::Recoverable("missing user id".into()))?;

    Ok(AccountSecrets {
        user_id,
        token: b64encode_url(&token_bytes),
        master_key,
        secret_key,
        public_key,
    })
}
