use std::time::SystemTime;

use crate::{token::RequestReason, token_cache::CacheableToken, Error};

/// Represents a id token as returned by `OAuth2` servers.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdToken {
    pub token: String,
    pub expiration: SystemTime,
}

impl IdToken {
    pub fn new(token: String) -> Result<IdToken, Error> {
        // Extract the exp claim from the token, so we can know if the token is expired or not.
        let claims = token.split('.').nth(1).ok_or(Error::InvalidTokenFormat)?;

        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD_NO_PAD.decode(claims)?;
        let claims: TokenClaims = serde_json::from_slice(&decoded)?;

        Ok(Self {
            token,
            expiration: SystemTime::UNIX_EPOCH
                .checked_add(std::time::Duration::from_secs(claims.exp))
                .unwrap_or(SystemTime::UNIX_EPOCH),
        })
    }
}

impl CacheableToken for IdToken {
    /// Returns true if token is expired.
    #[inline]
    fn has_expired(&self) -> bool {
        if self.token.is_empty() {
            return true;
        }

        self.expiration <= SystemTime::now()
    }
}

/// Either a valid token, or an HTTP request. With some token sources, two different
/// HTTP requests needs to be performed, one to get an access token and one to get
/// the actual id token.
pub enum IdTokenOrRequest {
    AccessTokenRequest {
        request: AccessTokenRequest,
        reason: RequestReason,
        audience_hash: u64,
    },
    IdTokenRequest {
        request: IdTokenRequest,
        reason: RequestReason,
        audience_hash: u64,
    },
    IdToken(IdToken),
}

pub type IdTokenRequest = http::Request<Vec<u8>>;
pub type AccessTokenRequest = http::Request<Vec<u8>>;

pub type AccessTokenResponse<S> = http::Response<S>;
pub type IdTokenResponse<S> = http::Response<S>;

/// A `IdTokenProvider` supplies all methods needed for all different flows to get a id token.
pub trait IdTokenProvider {
    /// Attempts to retrieve an id token that can be used when communicating via IAP etc.
    fn get_id_token(&self, audience: &str) -> Result<IdTokenOrRequest, Error>;

    /// Some token sources require a access token to be used to generte a id token.
    /// If `get_id_token` returns a `AccessTokenResponse`, this method should be called.
    fn get_id_token_with_access_token<S>(
        &self,
        audience: &str,
        response: AccessTokenResponse<S>,
    ) -> Result<IdTokenRequest, Error>
    where
        S: AsRef<[u8]>;

    /// Once a `IdTokenResponse` has been received for an id token request, call this method
    /// to deserialize the token.
    fn parse_id_token_response<S>(
        &self,
        hash: u64,
        response: IdTokenResponse<S>,
    ) -> Result<IdToken, Error>
    where
        S: AsRef<[u8]>;
}

#[derive(serde::Deserialize, Debug)]
struct TokenClaims {
    exp: u64,
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::IdToken;

    #[test]
    fn test_decode_jwt() {
        /* raw token claims
        {
            "aud": "my-aud",
            "azp": "123",
            "email": "test@example.com",
            "email_verified": true,
            "exp": 1676641773,
            "iat": 1676638173,
            "iss": "https://accounts.google.com",
            "sub": "123"
        }
        */

        let raw_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJteS1hdWQiLCJhenAiOiIxMjMiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNjc2NjQxNzczLCJpYXQiOjE2NzY2MzgxNzMsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjEyMyJ9.plHXcnUDNzWo4PVOAPiwoQJ7QIvecKhmCbfxaIsxpbbGyXFdOdLM2T0Qtbbm2FxwsryabNxv0DY_iQhXlCa1dv2ksusjZAj0MXEE3aEEi65rxxAhE_ew3eU03GheZOjG4oR2gMja8B_8_CoBOK7k7wt_Ggbph0iWIEG6_0YygjJdWHZhxeckn6ym6hQB2MkxYkv0MK2A_68e05edsar1VIvcpgOMcrMwcCNDClclx7A1Ci3pMk1vSdJ-1pHw_GAwb7XCEdB2E9Ccm9N7J0WddvC4W09CxXDYiOcVFxj2Lnr53wquHE0hJcNrp-6tYXKALfXUnx1Nn2XWA0a3ehpHMA";
        let id_token = IdToken::new(raw_token.to_owned()).unwrap();

        assert_eq!(id_token.token, raw_token);
        assert_eq!(
            id_token
                .expiration
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1676641773
        );
    }
}
