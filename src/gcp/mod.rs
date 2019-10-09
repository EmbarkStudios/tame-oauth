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
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ServiceAccountInfo {
    /// The private key we use to sign
    pub private_key: String,
    /// The unique id used as the issuer of the JWT claim
    pub client_email: String,
    /// The URI we send the token requests to, eg https://oauth2.googleapis.com/token
    pub token_uri: String,
}

impl ServiceAccountInfo {
    /// Deserializes service account from a byte slice. This data
    /// is typically acquired by reading a service account JSON file
    /// from disk
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
    /// A valid token that can be supplied in an API request
    Token(Token),
    Request {
        /// The parts of an HTTP request that must be sent
        /// to acquire the token, in the client of your choice
        request: http::Request<Vec<u8>>,
        /// The reason we need to retrieve a new token
        reason: RequestReason,
        /// An opaque hash of the scope(s) for which the request
        /// was constructed
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
        // Note: This isn't the best way of implementing a spinlock
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

/// A token provider for a GCP service account.
pub struct ServiceAccountAccess {
    info: ServiceAccountInfo,
    priv_key: Vec<u8>,
    cache: Spinlock<Vec<Entry>>,
}

impl ServiceAccountAccess {
    /// Creates a new `ServiceAccountAccess` given the provided service
    /// account info. This can fail if the private key is encoded correctly.
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

    /// Attempts to retrieve a token that can be used in an API request, if we haven't
    /// already retrieved a token for the specified scopes, or the token has expired,
    /// an HTTP request is returned that can be used to retrieve a token.
    ///
    /// Note that the scopes are not sorted or in any other way manipulated, so any
    /// modifications to them will require a new token to be requested.
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

    /// Once a response has been received for a token request, call this
    /// method to deserialize the token and store it in the cache so that
    /// future API requests don't have to retrieve a new token, until it
    /// expires.
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

    /// Hashes a set of scopes to a numeric key we can use to have an in-memory
    /// cache of scopes -> token
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
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,
    /// The token type, pretty much always Header
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
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
}
