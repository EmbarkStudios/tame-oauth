use super::{
    jwt::{self, Algorithm, Header, Key},
    Entry, TokenResponse,
};
use crate::{
    error::{self, Error},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
};

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Minimal parts needed from a GCP service acccount key for token acquisition
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
    /// Deserializes service account from a byte slice. This data is typically
    /// acquired by reading a service account JSON file from disk
    pub fn deserialize<T>(key_data: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        let slice = key_data.as_ref();

        let account_info: Self = serde_json::from_slice(slice)?;
        Ok(account_info)
    }
}

/// A token provider for a GCP service account.
pub struct ServiceAccountAccess {
    info: ServiceAccountInfo,
    priv_key: Vec<u8>,
    cache: std::sync::Mutex<Vec<Entry>>,
}

impl ServiceAccountAccess {
    /// Creates a new `ServiceAccountAccess` given the provided service
    /// account info. This can fail if the private key is encoded incorrectly.
    pub fn new(info: ServiceAccountInfo) -> Result<Self, Error> {
        let key_string = info
            .private_key
            .splitn(5, "-----")
            .nth(2)
            .ok_or(Error::InvalidKeyFormat)?;

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
            cache: std::sync::Mutex::new(Vec::new()),
            priv_key: key_bytes,
        })
    }

    /// Gets the [`ServiceAccountInfo`] this was created for
    pub fn get_account_info(&self) -> &ServiceAccountInfo {
        &self.info
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

impl TokenProvider for ServiceAccountAccess {
    /// Like [`ServiceAccountAccess::get_token`], but allows the JWT "subject"
    /// to be passed in.
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        subject: Option<T>,
        scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
        T: Into<String>,
    {
        let (hash, scopes) = Self::serialize_scopes(scopes.into_iter());

        let reason = {
            let cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
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
            subject: subject.map(|s| s.into()),
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

    /// Handle responses from the token URI request we generated in
    /// `get_token`. This method deserializes the response and stores
    /// the token in a local cache, so that future lookups for the
    /// same scopes don't require new http requests.
    fn parse_token_response<S>(
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
                    return Err(Error::Auth(auth_error));
                }
            }

            return Err(Error::HttpStatus(parts.status));
        }

        let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;
        let token: Token = token_res.into();

        // Last token wins, which...should?...be fine
        {
            let mut cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
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
