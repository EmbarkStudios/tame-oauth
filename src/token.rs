use chrono::{offset::TimeZone, DateTime, Utc};

/// Represents a token as returned by OAuth2 servers.
///
/// It is produced by all authentication flows.
/// It authenticates certain operations, and must be refreshed once
/// it reached its expiry date.
///
/// The type is tuned to be suitable for direct de-serialization from server
/// replies, as well as for serialization for later reuse. This is the reason
/// for the two fields dealing with expiry - once in relative in and once in
/// absolute terms.
///
/// Utility methods make common queries easier, see `expired()`.
#[derive(Clone, PartialEq, Debug, serde::Deserialize)]
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
    /// timestamp is seconds since epoch indicating when the token will expire in absolute terms.
    /// use expiry_date() to convert to DateTime.
    pub expires_in_timestamp: Option<i64>,
}

impl Token {
    /// Returns true if we are expired.
    pub fn has_expired(&self) -> bool {
        self.access_token.is_empty() || self.expiry_date() <= Utc::now()
    }

    /// Returns a DateTime object representing our expiry date.
    pub fn expiry_date(&self) -> DateTime<Utc> {
        match self.expires_in_timestamp {
            Some(ts) => Utc.timestamp(ts, 0),
            None => Utc::now(),
        }
    }
}

impl std::convert::TryInto<http::header::HeaderValue> for Token {
    type Error = crate::Error;

    fn try_into(self) -> Result<http::header::HeaderValue, crate::Error> {
        let auth_header_val = format!("{} {}", self.token_type, self.access_token);
        http::header::HeaderValue::from_str(&auth_header_val)
            .map_err(|e| crate::Error::from(http::Error::from(e)))
    }
}
