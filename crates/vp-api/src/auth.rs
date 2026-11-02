use crate::error::ApiError;
use axum::http::{HeaderMap, Uri};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use vp_product_domain::{ErrorCode, ErrorStage, SecretBytes, UserId};

/// Externally provisioned high-entropy bootstrap token, not a human password.
/// No default, generation, file loading, persistence or Debug/Serialize implementation.
/// Caller must supply at least 256 random bits encoded as 43+ URL-safe characters.
pub struct BootstrapCredential {
    username_digest: [u8; 32],
    token_digest: [u8; 32],
    principal: UserId,
}
impl BootstrapCredential {
    pub fn new(username: &str, token: SecretBytes) -> Result<Self, ApiError> {
        if username.is_empty()
            || username.len() > 128
            || username.chars().any(char::is_control)
            || !(43..=256).contains(&token.expose().len())
            || !token
                .expose()
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(b))
        {
            return Err(ApiError::invalid());
        }
        Ok(Self {
            username_digest: digest(username.as_bytes()),
            token_digest: digest(token.expose()),
            principal: UserId::new("bootstrap-administrator").map_err(|_| ApiError::internal())?,
        })
    }
    fn verify(&self, username: &str, password: &[u8]) -> bool {
        bool::from(
            self.username_digest.ct_eq(&digest(username.as_bytes()))
                & self.token_digest.ct_eq(&digest(password)),
        )
    }
}

/// A single explicit canonical web origin. CORS is deliberately not enabled.
#[derive(Clone)]
pub struct SecurityPolicy {
    pub(crate) origin: String,
    pub(crate) host: String,
}
impl SecurityPolicy {
    pub fn new(origin: &str) -> Result<Self, ApiError> {
        let uri: Uri = origin.parse().map_err(|_| ApiError::invalid())?;
        let scheme = uri.scheme_str().ok_or_else(ApiError::invalid)?;
        let authority = uri.authority().ok_or_else(ApiError::invalid)?;
        let local_http =
            scheme == "http" && matches!(authority.host(), "localhost" | "127.0.0.1" | "[::1]");
        if !(scheme == "https" || local_http)
            || authority.as_str().contains('@')
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || origin.ends_with('/')
            || origin.len() > 512
        {
            return Err(ApiError::invalid());
        }
        Ok(Self {
            origin: origin.to_owned(),
            host: authority.to_string(),
        })
    }
    pub(crate) fn check(&self, headers: &HeaderMap, mutation: bool) -> Result<(), ApiError> {
        if one_header(headers, "host")? != Some(self.host.as_str()) {
            return Err(ApiError::forbidden());
        }
        match one_header(headers, "origin")? {
            Some(origin) if origin != self.origin => return Err(ApiError::forbidden()),
            None if mutation => return Err(ApiError::forbidden()),
            _ => {}
        }
        if let Some(site) = one_header(headers, "sec-fetch-site")? {
            if site != "same-origin" && site != "none" {
                return Err(ApiError::forbidden());
            }
        }
        Ok(())
    }
}

pub(crate) fn one_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(ApiError::forbidden());
    }
    first
        .map(|h| h.to_str().map_err(|_| ApiError::forbidden()))
        .transpose()
}
fn cookie(headers: &HeaderMap) -> Result<Option<&str>, ApiError> {
    let Some(value) = one_header(headers, "cookie")? else {
        return Ok(None);
    };
    if value.len() > 4096 {
        return Err(ApiError::forbidden());
    }
    let mut found = None;
    for part in value.split(';') {
        let Some((name, value)) = part.trim().split_once('=') else {
            return Err(ApiError::forbidden());
        };
        if name == "vp_session" {
            if found.is_some() || value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(ApiError::unauthorized());
            }
            found = Some(value);
        }
    }
    Ok(found)
}
pub(crate) fn random_token() -> Result<String, ApiError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| ApiError::internal())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn digest(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[derive(Clone)]
pub(crate) struct Principal {
    pub id: UserId,
    session: [u8; 32],
}
struct Session {
    principal: UserId,
    csrf: [u8; 32],
    csrf_token: zeroize::Zeroizing<String>,
    created: Instant,
    touched: Instant,
}
struct AuthInner {
    sessions: BTreeMap<[u8; 32], Session>,
    attempts: u32,
    window: Instant,
}
pub(crate) struct Auth {
    credential: BootstrapCredential,
    inner: Mutex<AuthInner>,
}
impl Auth {
    pub fn new(credential: BootstrapCredential) -> Self {
        Self {
            credential,
            inner: Mutex::new(AuthInner {
                sessions: BTreeMap::new(),
                attempts: 0,
                window: Instant::now(),
            }),
        }
    }
    pub fn login(
        &self,
        username: &str,
        password: &[u8],
        second_factor: Option<&str>,
    ) -> Result<(String, String), ApiError> {
        let mut inner = self.inner.lock().map_err(|_| ApiError::internal())?;
        let now = Instant::now();
        if now.duration_since(inner.window) >= Duration::from_secs(60) {
            inner.window = now;
            inner.attempts = 0;
        }
        if inner.attempts >= 10 {
            return Err(ApiError::new(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                ErrorCode::AuthFailed,
                ErrorStage::Authenticate,
            ));
        }
        inner.attempts += 1;
        if username.len() > 128
            || password.len() > 256
            || second_factor.is_some()
            || !self.credential.verify(username, password)
        {
            return Err(ApiError::new(
                axum::http::StatusCode::UNAUTHORIZED,
                ErrorCode::AuthFailed,
                ErrorStage::Authenticate,
            ));
        }
        let token = random_token()?;
        let csrf = random_token()?;
        // Successful authentication rotates the administrator's entire session.
        inner.sessions.clear();
        inner.sessions.insert(
            digest(token.as_bytes()),
            Session {
                principal: self.credential.principal.clone(),
                csrf: digest(csrf.as_bytes()),
                csrf_token: zeroize::Zeroizing::new(csrf.clone()),
                created: now,
                touched: now,
            },
        );
        Ok((token, csrf))
    }
    pub fn authenticate(&self, headers: &HeaderMap, mutation: bool) -> Result<Principal, ApiError> {
        let token = cookie(headers)?.ok_or_else(ApiError::unauthorized)?;
        let key = digest(token.as_bytes());
        let mut inner = self.inner.lock().map_err(|_| ApiError::internal())?;
        let now = Instant::now();
        inner.sessions.retain(|_, s| {
            now.duration_since(s.created) < Duration::from_secs(1800)
                && now.duration_since(s.touched) < Duration::from_secs(600)
        });
        let session = inner
            .sessions
            .get_mut(&key)
            .ok_or_else(ApiError::unauthorized)?;
        if mutation {
            let csrf = one_header(headers, "x-vp-csrf")?.ok_or_else(ApiError::forbidden)?;
            if csrf.len() != 64 || !bool::from(session.csrf.ct_eq(&digest(csrf.as_bytes()))) {
                return Err(ApiError::forbidden());
            }
        }
        session.touched = now;
        Ok(Principal {
            id: session.principal.clone(),
            session: key,
        })
    }
    pub fn csrf_token(&self, principal: &Principal) -> Result<String, ApiError> {
        let inner = self.inner.lock().map_err(|_| ApiError::internal())?;
        let session = inner
            .sessions
            .get(&principal.session)
            .ok_or_else(ApiError::unauthorized)?;
        Ok(session.csrf_token.to_string())
    }
    pub fn logout(&self, principal: &Principal) -> Result<(), ApiError> {
        self.inner
            .lock()
            .map_err(|_| ApiError::internal())?
            .sessions
            .remove(&principal.session);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn expired_session_and_missing_origin_fail_closed() {
        let auth =
            Auth::new(BootstrapCredential::new("test", SecretBytes::new(vec![b'a'; 43])).unwrap());
        let (session, csrf) = auth.login("test", &[b'a'; 43], None).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("vp_session={session}").parse().unwrap());
        headers.insert("x-vp-csrf", csrf.parse().unwrap());
        assert!(auth.authenticate(&headers, true).is_ok());
        auth.inner
            .lock()
            .unwrap()
            .sessions
            .get_mut(&digest(session.as_bytes()))
            .unwrap()
            .touched = Instant::now() - Duration::from_secs(601);
        assert!(auth.authenticate(&headers, false).is_err());
        headers.insert("host", "localhost:9443".parse().unwrap());
        assert!(SecurityPolicy::new("https://localhost:9443")
            .unwrap()
            .check(&headers, true)
            .is_err());
        headers.insert("origin", "null".parse().unwrap());
        assert!(SecurityPolicy::new("https://localhost:9443")
            .unwrap()
            .check(&headers, true)
            .is_err());
    }
}
