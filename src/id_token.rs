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
            "sub": "1234"
        }
        */

        let raw_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYzEyMyIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJteS1hdWQiLCJhenAiOiIxMjMiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNjc2NjQxNzczLCJpYXQiOjE2NzY2MzgxNzMsImlzcyI6Imh0dHBzOi8vYWNjb3VudHMuZ29vZ2xlLmNvbSIsInN1YiI6IjEyMzQifQ.dLGpnM4MzMi3Lexoxo8hTxQWemnXvg4N_0Mn50vVWFfvI6bDu6v35RnXrJLa2SignICXeU9oVeU0z4h9tEjt_4I_SNiJJDLL0kQk045Faehx3dGJdh3IE0_fnMfTlD6K0W2ALLex3kOIg76RhAJ8kDkG1LlblCukheCH6JmYwzgefyTy9pwvnXoNlxbZQsLI5lB1ZufLEn62CA7Qto_e8wwps1t4zzm-GttSku9jREQZOnSaw3zHplPLjw9s7K7paS0qNcV0LsL02uHF5rjmpGuGhI3TkszXD-2SQLoNTfjZhFsCey0TAj2iBxAzY9x6UVHY5temMQW8EKsdDypjzA";

        // Make sure that the claims part base64 is encoded without padding, this is to make sure that padding is handled correctly.
        // Note that when changing the test token, this might fail, in that case, just add a character somewhere in the claims.
        let claims = raw_token.split('.').nth(1).unwrap();
        assert_ne!(claims.len() % 4, 0);

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
