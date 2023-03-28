use super::TokenResponse;
use crate::{
    error::{self, Error},
    id_token::{
        AccessTokenResponse, IdTokenOrRequest, IdTokenProvider, IdTokenRequest, IdTokenResponse,
    },
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
    token_cache::CachedTokenProvider,
    IdToken,
};

/// Provides tokens using
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
/// Caches tokens internally.
pub type EndUserCredentials = CachedTokenProvider<EndUserCredentialsInner>;
impl EndUserCredentials {
    pub fn new(info: EndUserCredentialsInfo) -> Self {
        CachedTokenProvider::wrap(EndUserCredentialsInner::new(info))
    }
}

/// Provides tokens using
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
#[derive(serde::Deserialize, Debug, Clone)]
pub struct EndUserCredentialsInfo {
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

impl EndUserCredentialsInfo {
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

/// A token provider for
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
/// Should not be used directly as it is not cached. Use `EndUserCredentials` instead.
pub struct EndUserCredentialsInner {
    info: EndUserCredentialsInfo,
}

impl std::fmt::Debug for EndUserCredentialsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndUserCredentialsInner")
            .finish_non_exhaustive()
    }
}

impl EndUserCredentialsInner {
    pub fn new(info: EndUserCredentialsInfo) -> Self {
        Self { info }
    }
}

#[derive(serde::Deserialize, Debug)]
struct IdTokenResponseBody {
    /// The actual token
    id_token: String,
}

impl EndUserCredentialsInner {
    fn prepare_token_request(&self) -> Result<http::Request<Vec<u8>>, Error> {
        // To get an access token or id_token, we need to perform a refresh
        // following the instructions at
        // https://developers.google.com/identity/protocols/oauth2/web-server#offline
        // (i.e., POST our client data as a refresh_token request to
        // the /token endpoint).
        // The response will include both a access token and a id token
        let url = "https://oauth2.googleapis.com/token";

        // Build up the parameters as a form encoded string.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &self.info.client_id)
            .append_pair("client_secret", &self.info.client_secret)
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", &self.info.refresh_token)
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

        Ok(request)
    }
}

impl TokenProvider for EndUserCredentialsInner {
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
            return Err(Error::Auth(error::AuthError {
                error: Some("Unsupported".to_string()),
                error_description: Some(
                    "ADC / User tokens do not support jwt subjects".to_string(),
                ),
            }));
        }

        let request = self.prepare_token_request()?;

        Ok(TokenOrRequest::Request {
            request,
            reason: RequestReason::ParametersChanged,
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

impl IdTokenProvider for EndUserCredentialsInner {
    fn get_id_token(&self, _audience: &str) -> Result<IdTokenOrRequest, Error> {
        let request = self.prepare_token_request()?;

        Ok(IdTokenOrRequest::IdTokenRequest {
            request,
            reason: RequestReason::ParametersChanged,
            audience_hash: 0,
        })
    }

    fn get_id_token_with_access_token<S>(
        &self,
        _audience: &str,
        _response: AccessTokenResponse<S>,
    ) -> Result<IdTokenRequest, Error>
    where
        S: AsRef<[u8]>,
    {
        // ID token via access token is not supported with user credentials
        // The token is fetched via the same token request as the access token
        Err(Error::Auth(error::AuthError {
            error: Some("Unsupported".to_string()),
            error_description: Some(
                "User credentials id tokens via access token not supported".to_string(),
            ),
        }))
    }

    fn parse_id_token_response<S>(
        &self,
        _hash: u64,
        response: IdTokenResponse<S>,
    ) -> Result<IdToken, Error>
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

        let token_res: IdTokenResponseBody = serde_json::from_slice(body.as_ref())?;
        let token = IdToken::new(token_res.id_token)?;

        Ok(token)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn end_user_credentials() {
        let provider = EndUserCredentialsInner::new(EndUserCredentialsInfo {
            client_id: "fake_client@domain.com".into(),
            client_secret: "TOP_SECRET".into(),
            refresh_token: "REFRESH_TOKEN".into(),
            client_type: "authorized_user".into(),
        });

        // End-user credentials don't let you override scopes.
        let scopes = vec!["better_not_be_there"];

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
