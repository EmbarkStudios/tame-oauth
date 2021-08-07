use crate::{
    error::{self, AuthError, Error},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
};

mod jwt;
use jwt::{Algorithm, Header, Key};

pub mod prelude {
    pub use super::{
        EndUserCredentials, MetadataServerProvider, ServiceAccountAccess, ServiceAccountInfo,
    };
    pub use crate::token::{Token, TokenOrRequest, TokenProvider};
}

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

struct Entry {
    hash: u64,
    token: Token,
}

/// A token provider for a GCP service account.
pub struct ServiceAccountAccess {
    info: ServiceAccountInfo,
    priv_key: Vec<u8>,
    cache: std::sync::Mutex<Vec<Entry>>,
}

pub struct MetadataServerProvider {
    account_name: String,
}

/// Both the `ServiceAccountAccess` and `MetadataServerProvider` get
/// back JSON responses with this schema from their endpoints.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,
    /// The token type, pretty much always Header
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: i64,
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

impl MetadataServerProvider {
    pub fn new(account_name: Option<String>) -> Self {
        if let Some(name) = account_name {
            Self { account_name: name }
        } else {
            // GCP uses "default" as the name in URIs.
            Self {
                account_name: "default".to_string(),
            }
        }
    }
}

impl TokenProvider for MetadataServerProvider {
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
        // We can only support subject being none
        if subject.is_some() {
            return Err(Error::Auth(AuthError {
                error: Some("Unsupported".to_string()),
                error_description: Some(
                    "Metadata server tokens do not support jwt subjects".to_string(),
                ),
            }));
        }

        // Regardless of GCE or GAE, the token_uri is
        // computeMetadata/v1/instance/service-accounts/<name or
        // id>/token.
        let mut url = format!(
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/{}/token",
            self.account_name
        );

        // Merge all the scopes into a single string.
        let scopes_str = scopes
            .into_iter()
            .map(|s| s.as_ref())
            .collect::<Vec<&str>>()
            .join(",");

        // If we have any scopes, pass them along in the querystring.
        if !scopes_str.is_empty() {
            url.push_str("?scopes=");
            url.push_str(&scopes_str);
        }

        // Make an empty body, but as Vec<u8> to match the request in
        // TokenOrRequest.
        let empty_body: Vec<u8> = vec![];

        let request = http::Request::builder()
            .method("GET")
            .uri(url)
            // To get responses from GCE, we must pass along the
            // Metadata-Flavor header with a value of "Google".
            .header("Metadata-Flavor", "Google")
            .body(empty_body)?;

        Ok(TokenOrRequest::Request {
            request,
            reason: RequestReason::ScopesChanged,
            scope_hash: 0,
        })
    }

    fn parse_token_response<S>(
        &self,
        _hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();

        if !parts.status.is_success() {
            return Err(Error::HttpStatus(parts.status));
        }

        // Deserialize our response, or fail.
        let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;

        // Convert it into our output.
        let token: Token = token_res.into();
        Ok(token)
    }
}

/// The fields from a well formed `application_default_credentials.json`.
#[derive(serde::Deserialize, Debug, Clone)]
pub struct EndUserCredentials {
    /// The OAuth2 client_id
    pub client_id: String,
    /// The OAuth2 client_secret
    pub client_secret: String,
    /// The OAuth2 refresh_token
    pub refresh_token: String,
    /// The client type (the value must be authorized_user)
    #[serde(rename = "type")]
    pub client_type: String,
}

impl EndUserCredentials {
    /// Deserializes the `EndUserCredentials` from a byte slice. This
    /// data is typically acquired by reading an
    /// `application_default_credentials.json` file from disk.
    pub fn deserialize<T>(key_data: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        let slice = key_data.as_ref();

        let account_info: Self = serde_json::from_slice(slice)?;
        Ok(account_info)
    }
}

impl TokenProvider for EndUserCredentials {
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        subject: Option<T>,
        // EndUserCredentials only have the scopes they were granted
        // via their authorization. So whatever scopes you're asking
        // for, better have been handled when authorized. `gcloud auth
        // application-default login` will get the
        // https://www.googleapis.com/auth/cloud-platform which
        // includes all *GCP* APIs.
        _scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
        T: Into<String>,
    {
        // We can only support subject being none
        if subject.is_some() {
            return Err(Error::Auth(AuthError {
                error: Some("Unsupported".to_string()),
                error_description: Some(
                    "ADC / User tokens do not support jwt subjects".to_string(),
                ),
            }));
        }

        // To get an access token, we need to perform a refresh
        // following the instructions at
        // https://developers.google.com/identity/protocols/oauth2/web-server#offline
        // (i.e., POST our client data as a refresh_token request to
        // the /token endpoint).
        let url = "https://oauth2.googleapis.com/token";

        // Build up the parameters as a form encoded string.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.client_id)
            .append_pair("client_secret", &self.client_secret)
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &self.refresh_token)
            .finish();

        let body = Vec::from(body);

        let request = http::Request::builder()
            .method("POST")
            .uri(url)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(http::header::CONTENT_LENGTH, body.len())
            .body(body)?;

        Ok(TokenOrRequest::Request {
            request,
            reason: RequestReason::ScopesChanged,
            scope_hash: 0,
        })
    }

    fn parse_token_response<S>(
        &self,
        _hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();

        if !parts.status.is_success() {
            return Err(Error::HttpStatus(parts.status));
        }

        // Deserialize our response, or fail.
        let token_res: TokenResponse = serde_json::from_slice(body.as_ref())?;

        // TODO(boulos): The response also includes the set of scopes
        // (as "scope") that we're granted. We could check that
        // cloud-platform is in it.

        // Convert it into our output.
        let token: Token = token_res.into();
        Ok(token)
    }
}

impl From<TokenResponse> for Token {
    fn from(tr: TokenResponse) -> Self {
        let expires_ts = chrono::Utc::now().timestamp() + tr.expires_in;

        Self {
            access_token: tr.access_token,
            token_type: tr.token_type,
            refresh_token: String::new(),
            expires_in: Some(tr.expires_in),
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

    #[test]
    fn metadata_noscopes() {
        let provider = MetadataServerProvider::new(None);

        let scopes: Vec<&str> = vec![];

        let token_or_req = provider
            .get_token(&scopes)
            .expect("Should have gotten a request");

        match token_or_req {
            TokenOrRequest::Token(_) => panic!("Shouldn't have gotten a token"),
            TokenOrRequest::Request { request, .. } => {
                // Should be the metadata server
                assert_eq!(request.uri().host(), Some("metadata.google.internal"));
                // Since we had no scopes, no querystring.
                assert_eq!(request.uri().query(), None);
            }
        }
    }

    #[test]
    fn metadata_with_scopes() {
        let provider = MetadataServerProvider::new(None);

        let scopes: Vec<&str> = vec!["scope1", "scope2"];

        let token_or_req = provider
            .get_token(&scopes)
            .expect("Should have gotten a request");

        match token_or_req {
            TokenOrRequest::Token(_) => panic!("Shouldn't have gotten a token"),
            TokenOrRequest::Request { request, .. } => {
                // Should be the metadata server
                assert_eq!(request.uri().host(), Some("metadata.google.internal"));
                // Since we had some scopes, we should have a querystring.
                assert!(request.uri().query().is_some());

                let query_string = request.uri().query().unwrap();
                // We don't care about ordering, but the query_string
                // should be comma-separated and only include the
                // scopes.
                assert!(
                    query_string == "scopes=scope1,scope2"
                        || query_string == "scopes=scope2,scope1"
                );
            }
        }
    }

    #[test]
    fn end_user_credentials() {
        let provider = EndUserCredentials {
            client_id: "fake_client@domain.com".into(),
            client_secret: "TOP_SECRET".into(),
            refresh_token: "REFRESH_TOKEN".into(),
            client_type: "authorized_user".into(),
        };

        // End-user credentials don't let you override scopes.
        let scopes: Vec<&str> = vec!["better_not_be_there"];

        let token_or_req = provider
            .get_token(&scopes)
            .expect("Should have gotten a request");

        match token_or_req {
            TokenOrRequest::Token(_) => panic!("Shouldn't have gotten a token"),
            TokenOrRequest::Request { request, .. } => {
                // Should be the Google oauth2 API
                assert_eq!(request.uri().host(), Some("oauth2.googleapis.com"));
                // Scopes aren't passed for end user credentials
                assert_eq!(request.uri().query(), None);
            }
        }
    }
}
