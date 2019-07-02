use crate::{
    error::{self, Error},
    token::Token,
};

mod jwt;
use jwt::{Algorithm, Header, Key};

pub mod prelude {
    pub use super::{RequestReason, ServiceAccountAccess, ServiceAccountInfo, TokenOrRequest};
}

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Minimal parts needed from a GCP service acccount key
/// for token acquisition
#[derive(Deserialize, Debug, Clone)]
pub struct ServiceAccountInfo {
    pub private_key: String,
    pub client_email: String,
    pub token_uri: String,
}

impl ServiceAccountInfo {
    pub fn deserialize<T>(key_data: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        let slice = key_data.as_ref();

        let account_info: Self = serde_json::from_slice(slice)?;
        Ok(account_info)
    }
}

struct Entry {
    /// Hash of the _ordered_ scopes
    hash: u64,
    token: Token,
}

#[derive(Debug)]
pub enum RequestReason {
    /// An existing token has expired
    Expired,
    /// The requested scopes have never been seen before
    ScopesChanged,
}

/// Either a valid token, or an HTTP request that
/// can be used to acquire one
#[derive(Debug)]
pub enum TokenOrRequest {
    Token(Token),
    Request {
        request: http::Request<Vec<u8>>,
        reason: RequestReason,
        scope_hash: u64,
    },
}

use lock_api::{GuardSend, RawMutex};
use std::sync::atomic::{AtomicBool, Ordering};

struct RawSpinlock(AtomicBool);

unsafe impl RawMutex for RawSpinlock {
    const INIT: RawSpinlock = RawSpinlock(AtomicBool::new(false));

    // A spinlock guard can be sent to another thread and unlocked there
    type GuardMarker = GuardSend;

    fn lock(&self) {
        // Note: This isn't the best way of implementing a spinlock, but it
        // suffices for the sake of this example.
        while !self.try_lock() {}
    }

    fn try_lock(&self) -> bool {
        self.0.swap(true, Ordering::Acquire)
    }

    fn unlock(&self) {
        self.0.store(false, Ordering::Release);
    }
}

type Spinlock<T> = lock_api::Mutex<RawSpinlock, T>;
//type SpinlockGuard<'a, T> = lock_api::MutexGuard<'a, RawSpinlock, T>;

/// A key provider for a GCP service account.
pub struct ServiceAccountAccess {
    info: ServiceAccountInfo,
    priv_key: Vec<u8>,
    cache: Spinlock<Vec<Entry>>,
}

impl ServiceAccountAccess {
    pub fn new(info: ServiceAccountInfo) -> Result<Self, Error> {
        let key_string = info
            .private_key
            .splitn(5, "-----")
            .nth(2)
            .ok_or_else(|| Error::InvalidKeyFormat)?;

        // Strip out all of the newlines
        let key_string = key_string.split_whitespace().fold(
            String::with_capacity(key_string.len()),
            |mut s, line| {
                s.push_str(line);
                s
            },
        );

        let key_bytes = base64::decode_config(key_string.as_bytes(), base64::STANDARD)?;

        Ok(Self {
            info,
            cache: Spinlock::new(Vec::new()),
            priv_key: key_bytes,
        })
    }

    pub fn get_token<'a, S, I>(&self, scopes: I) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let (hash, scopes) = Self::serialize_scopes(scopes.into_iter());

        let reason = {
            let cache = self.cache.lock();
            match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
                Ok(i) => {
                    let token = &cache[i].token;

                    if !token.has_expired() {
                        return Ok(TokenOrRequest::Token(token.clone()));
                    }

                    RequestReason::Expired
                }
                Err(_) => RequestReason::ScopesChanged,
            }
        };

        let issued = chrono::Utc::now().timestamp();
        let expiry = issued + 3600 - 5; // Give us some wiggle room near the hour mark

        let claims = jwt::Claims {
            issuer: self.info.client_email.clone(),
            scope: scopes,
            //"https://www.googleapis.com/oauth2/v4/token".to_owned()
            audience: self.info.token_uri.clone(),
            expiration: expiry,
            issued_at: issued,
            sub: None,
        };

        let assertion = jwt::encode(
            &Header::new(Algorithm::RS256),
            &claims,
            Key::Pkcs8(&self.priv_key),
        )?;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", GRANT_TYPE)
            .append_pair("assertion", &assertion)
            .finish();

        let body = Vec::from(body);

        let request = http::Request::builder()
            .method("POST")
            .uri(&self.info.token_uri)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(body)?;

        Ok(TokenOrRequest::Request {
            reason,
            request,
            scope_hash: hash,
        })
    }

    pub fn parse_token_response<S>(
        &self,
        hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();

        if !parts.status.is_success() {
            let body_bytes = body.as_ref();

            if parts
                .headers
                .get(http::header::CONTENT_TYPE)
                .and_then(|ct| ct.to_str().ok())
                == Some("application/json; charset=utf-8")
            {
                if let Ok(auth_error) = serde_json::from_slice::<error::AuthError>(body_bytes) {
                    return Err(Error::AuthError(auth_error));
                }
            }

            return Err(Error::HttpStatus(parts.status));
        }

        let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;
        let token: Token = token_res.into();

        // Last token wins, which...should?...be fine
        {
            let mut cache = self.cache.lock();
            match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
                Ok(i) => cache[i].token = token.clone(),
                Err(i) => {
                    cache.insert(
                        i,
                        Entry {
                            hash,
                            token: token.clone(),
                        },
                    );
                }
            };
        }

        Ok(token)
    }

    fn serialize_scopes<'a, I, S>(scopes: I) -> (u64, String)
    where
        S: AsRef<str> + 'a,
        I: Iterator<Item = &'a S>,
    {
        use std::hash::Hasher;

        let scopes = scopes.map(|s| s.as_ref()).collect::<Vec<&str>>().join(" ");
        let hash = {
            let mut hasher = twox_hash::XxHash::default();
            hasher.write(scopes.as_bytes());
            hasher.finish()
        };

        (hash, scopes)
    }
}

/// This is the schema of the server's response.
#[derive(Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

impl Into<Token> for TokenResponse {
    fn into(self) -> Token {
        let expires_ts = chrono::Utc::now().timestamp() + self.expires_in;

        Token {
            access_token: self.access_token,
            token_type: self.token_type,
            refresh_token: String::new(),
            expires_in: Some(self.expires_in),
            expires_in_timestamp: Some(expires_ts),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hash_scopes() {
        use std::hash::Hasher;

        let expected = {
            let mut hasher = twox_hash::XxHash::default();
            hasher.write(b"scope1 ");
            hasher.write(b"scope2 ");
            hasher.write(b"scope3");
            hasher.finish()
        };

        let (hash, scopes) =
            ServiceAccountAccess::serialize_scopes(["scope1", "scope2", "scope3"].iter());

        assert_eq!(expected, hash);
        assert_eq!("scope1 scope2 scope3", scopes);

        let (hash, scopes) = ServiceAccountAccess::serialize_scopes(
            vec![
                "scope1".to_owned(),
                "scope2".to_owned(),
                "scope3".to_owned(),
            ]
            .iter(),
        );

        assert_eq!(expected, hash);
        assert_eq!("scope1 scope2 scope3", scopes);
    }

    //#[test]
    #[allow(dead_code)]
    fn test_token_retrieval() {
        const SERVICE_KEY: &str = include_str!("../../tests/svc_key.json");

        use bytes::BufMut;

        let acct_info = ServiceAccountInfo::deserialize(SERVICE_KEY).unwrap();
        let acct_access = ServiceAccountAccess::new(acct_info).unwrap();

        let token = match acct_access
            .get_token(&["https://www.googleapis.com/auth/pubsub"])
            .unwrap()
        {
            TokenOrRequest::Request {
                request,
                scope_hash,
                ..
            } => {
                let client = reqwest::Client::new();

                let (parts, body) = request.into_parts();
                let uri = parts.uri.to_string();

                let builder = match parts.method {
                    http::Method::GET => client.get(&uri),
                    http::Method::POST => client.post(&uri),
                    http::Method::DELETE => client.delete(&uri),
                    http::Method::PUT => client.put(&uri),
                    method => unimplemented!("{} not implemented", method),
                };

                let request = builder.headers(parts.headers).body(body).build().unwrap();

                let mut response = client.execute(request).unwrap();

                let mut writer = bytes::BytesMut::with_capacity(
                    response.content_length().unwrap_or(1024) as usize,
                )
                .writer();
                response.copy_to(&mut writer).unwrap();
                let buffer = writer.into_inner();

                let mut builder = http::Response::builder();

                builder
                    .status(response.status())
                    .version(response.version());

                let headers = builder.headers_mut().unwrap();

                headers.extend(
                    response
                        .headers()
                        .into_iter()
                        .map(|(k, v)| (k.clone(), v.clone())),
                );

                let response = builder.body(buffer.freeze()).unwrap();

                acct_access
                    .parse_token_response(scope_hash, response)
                    .unwrap()
            }
            _ => unreachable!(),
        };

        match acct_access
            .get_token(&["https://www.googleapis.com/auth/pubsub"])
            .unwrap()
        {
            TokenOrRequest::Token(tk) => assert_eq!(tk, token),
            _ => unreachable!(),
        }
    }
}
