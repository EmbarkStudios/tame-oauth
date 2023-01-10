use super::{
    jwt::{self, Algorithm, Header, Key},
    TokenResponse,
};
use crate::{
    error::{self, Error},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
    token_cache::CachedTokenProvider,
};

const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Minimal parts needed from a GCP service acccount key for token acquisition
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ServiceAccountInfo {
    /// The private key we use to sign
    pub private_key: String,
    /// The unique id used as the issuer of the JWT claim
    pub client_email: String,
    /// The URI we send the token requests to, eg <https://oauth2.googleapis.com/token>
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
/// Caches tokens internally.
pub type ServiceAccountProvider = CachedTokenProvider<ServiceAccountProviderInner>;
impl ServiceAccountProvider {
    pub fn new(info: ServiceAccountInfo) -> Result<Self, Error> {
        Ok(CachedTokenProvider::wrap(ServiceAccountProviderInner::new(
            info,
        )?))
    }

    /// Gets the [`ServiceAccountInfo`] this was created for
    pub fn get_account_info(&self) -> &ServiceAccountInfo {
        &self.inner().info
    }
}

/// A token provider for a GCP service account.
pub struct ServiceAccountProviderInner {
    info: ServiceAccountInfo,
    priv_key: Vec<u8>,
}

impl ServiceAccountProviderInner {
    /// Creates a new `ServiceAccountAccess` given the provided service
    /// account info. This can fail if the private key is encoded incorrectly.
    pub fn new(info: ServiceAccountInfo) -> Result<Self, Error> {
        let key_string = info
            .private_key
            .split("-----")
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
            priv_key: key_bytes,
        })
    }

    /// Gets the [`ServiceAccountInfo`] this was created for
    pub fn get_account_info(&self) -> &ServiceAccountInfo {
        &self.info
    }
}

impl TokenProvider for ServiceAccountProviderInner {
    /// Like [`ServiceAccountProviderInner::get_token`], but allows the JWT "subject"
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
        let scopes = scopes
            .into_iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(" ");

        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs() as i64;

        let claims = jwt::Claims {
            issuer: self.info.client_email.clone(),
            scope: scopes,
            audience: self.info.token_uri.clone(),
            expiration: issued_at + 3600 - 5, // Give us some wiggle room near the hour mark
            issued_at,
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
            reason: RequestReason::ScopesChanged,
            request,
            scope_hash: 0,
        })
    }

    /// Handle responses from the token URI request we generated in
    /// `get_token`. This method deserializes the response and stores
    /// the token in a local cache, so that future lookups for the
    /// same scopes don't require new http requests.
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

        Ok(token)
    }
}
