use super::TokenResponse;
use crate::{
    error::{self, Error},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
    token_cache::CachedTokenProvider,
};

/// Provides tokens using
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
/// Caches token internally.
pub type EndUserCredentials = CachedTokenProvider<EndUserCredentialsInner>;
impl EndUserCredentials {
    pub fn deserialize<T>(key_data: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        Ok(CachedTokenProvider::wrap(
            EndUserCredentialsInner::deserialize(key_data)?,
        ))
    }
}

/// Provides tokens using
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
#[derive(serde::Deserialize, Debug, Clone)]
pub struct EndUserCredentialsInner {
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

impl EndUserCredentialsInner {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn end_user_credentials() {
        let provider = EndUserCredentialsInner {
            client_id: "fake_client@domain.com".into(),
            client_secret: "TOP_SECRET".into(),
            refresh_token: "REFRESH_TOKEN".into(),
            client_type: "authorized_user".into(),
        };

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
