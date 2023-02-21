use std::time::SystemTime;

use crate::{token::RequestReason, Error, ExpiarableToken};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IDToken {
    pub token: String,
    pub expiration: u64,
}

impl IDToken {
    pub fn new(token: String) -> Result<IDToken, Error> {
        // Extract the exp claim from the token, so we can know if the token is expired or not.
        let claims = token
            .split('.').nth(1)
            .ok_or(Error::InvalidTokenFormat)?;

        let decoded = base64::decode(claims)?;
        let claims: TokenClaims = serde_json::from_slice(&decoded)?;

        Ok(Self {
            token,
            expiration: claims.exp,
        })
    }
}

impl ExpiarableToken for IDToken {
    /// Returns true if token is expired.
    #[inline]
    fn has_expired(&self) -> bool {
        if self.token.is_empty() {
            return true;
        }

        let expiry = SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(self.expiration))
            .unwrap_or(SystemTime::UNIX_EPOCH);

        expiry <= SystemTime::now()
    }
}

pub enum IDTokenOrRequest {
    AccessTokenRequest {
        request: AccessTokenRequest,
        reason: RequestReason,
        hash: u64,
    },
    IDTokenRequest {
        request: IDTokenRequest,
        reason: RequestReason,
        hash: u64,
    },
    IDToken(IDToken),
}

pub type IDTokenRequest = http::Request<Vec<u8>>;
pub type AccessTokenRequest = http::Request<Vec<u8>>;

pub type AccessTokenResponse<S> = http::Response<S>;
pub type IDTokenResponse<S> = http::Response<S>;

/// A `IDTokenProvider` has a single method to implement `get_token`.
/// Implementations are free to perform caching or always return a `Request` in
/// the `TokenOrRequest`.
pub trait IDTokenProvider {
    /// Attemps to retrieve an id token that can be used when communicating via IAP etc.
    fn get_id_token(&self, audience: &str) -> Result<IDTokenOrRequest, Error>;

    /// Some token sources require a access token to be used to generte a id token.
    /// If `get_id_token` returns a `AccessTokenResponse`, this method should be called.
    fn get_id_token_with_access_token<S>(
        &self,
        audience: &str,
        response: AccessTokenResponse<S>,
    ) -> Result<IDTokenRequest, Error>
    where
        S: AsRef<[u8]>;

    /// Once a response has been received for an id token requst, call this method
    /// to deserialize the token.
    fn parse_id_token_response<S>(
        &self,
        hash: u64,
        response: IDTokenResponse<S>,
    ) -> Result<IDToken, Error>
    where
        S: AsRef<[u8]>;
}

#[derive(serde::Deserialize, Debug)]
struct TokenClaims {
    exp: u64,
}

#[cfg(test)]
mod tests {
    use super::IDToken;

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
        let id_token = IDToken::new(raw_token.to_owned()).unwrap();

        assert_eq!(id_token.token, raw_token);
        assert_eq!(id_token.expiration, 1676641773);
    }
}
