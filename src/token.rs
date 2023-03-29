use crate::{error::Error, token_cache::CacheableToken};
use std::time::SystemTime;

/// Represents a access token as returned by `OAuth2` servers.
///
/// * It is produced by all authentication flows.
/// * It authenticates certain operations, and must be refreshed once it has
///  reached its expiry date.
///
/// The type is tuned to be suitable for direct de-serialization from server
/// replies, as well as for serialization for later reuse. This is the reason
/// for the two fields dealing with expiry - once in relative in and once in
/// absolute terms.
#[derive(Clone, PartialEq, Eq, Debug, serde::Deserialize)]
pub struct Token {
    /// used when authenticating calls to oauth2 enabled services.
    pub access_token: String,
    /// used to refresh an expired access_token.
    pub refresh_token: String,
    /// The token type as string - usually 'Bearer'.
    pub token_type: String,
    /// access_token will expire after this amount of time.
    /// Prefer using expiry_date()
    pub expires_in: Option<i64>,
    /// timestamp is seconds since epoch indicating when the token will expire
    /// in absolute terms.
    pub expires_in_timestamp: Option<SystemTime>,
}

impl CacheableToken for Token {
    /// Returns true if we are expired.
    #[inline]
    fn has_expired(&self) -> bool {
        if self.access_token.is_empty() {
            return true;
        }

        let expiry = self.expires_in_timestamp.unwrap_or_else(SystemTime::now);

        expiry <= SystemTime::now()
    }
}

#[derive(Debug)]
pub enum RequestReason {
    /// An existing token has expired
    Expired,
    /// The requested scopes or audience have never been seen before
    ParametersChanged,
}

/// Either a valid token, or an HTTP request that can be used to acquire one
#[derive(Debug)]
pub enum TokenOrRequest {
    /// A valid token that can be supplied in an API request
    Token(Token),
    Request {
        /// The parts of an HTTP request that must be sent to acquire the token,
        /// in the client of your choice
        request: http::Request<Vec<u8>>,
        /// The reason we need to retrieve a new token
        reason: RequestReason,
        /// An opaque hash of the unique parameters for which the request was constructed
        scope_hash: u64,
    },
}

/// A `TokenProvider` has a single method to implement `get_token_with_subject`.
/// Implementations are free to perform caching or always return a `Request` in
/// the `TokenOrRequest`.
pub trait TokenProvider {
    /// Attempts to retrieve a token that can be used in an API request, if we
    /// haven't already retrieved a token for the specified scopes, or the token
    /// has expired, an HTTP request is returned that can be used to retrieve a
    /// token.
    ///
    /// Note that the scopes are not sorted or in any other way manipulated, so
    /// any modifications to them will require a new token to be requested.
    #[inline]
    fn get_token<'a, S, I>(&self, scopes: I) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S> + Clone,
    {
        self.get_token_with_subject::<S, I, String>(None, scopes)
    }

    /// Like [`TokenProvider::get_token`], but allows the JWT
    /// ["subject"](https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields)
    /// to be passed in.
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        subject: Option<T>,
        scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S> + Clone,
        T: Into<String>;

    /// Once a response has been received for a token request, call this method
    /// to deserialize the token (and potentially store it in a local cache for
    /// reuse until it expires).
    fn parse_token_response<S>(
        &self,
        hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>;
}

impl std::convert::TryInto<http::header::HeaderValue> for Token {
    type Error = crate::Error;

    fn try_into(self) -> Result<http::header::HeaderValue, crate::Error> {
        let auth_header_val = format!("{} {}", self.token_type, self.access_token);
        http::header::HeaderValue::from_str(&auth_header_val)
            .map_err(|e| crate::Error::from(http::Error::from(e)))
    }
}
