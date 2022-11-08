use std::collections::HashMap;

use super::TokenResponse;
use crate::{
    error::{self, Error},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
};

/*
Example credentials format generated by google-github-actions/auth

```json
    {
      type: 'external_account',
      audience: `//iam.googleapis.com/${this.#providerID}`,
      subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
      token_url: 'https://sts.googleapis.com/v1/token',
      service_account_impersonation_url: `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${
        this.#serviceAccount
      }:generateAccessToken`,
      credential_source: {
        url: requestURL,
        headers: {
          Authorization: `Bearer ${this.#oidcTokenRequestToken}`,
        },
        format: {
          type: 'json',
          subject_token_field_name: 'value',
        },
      },
    };
```
*/

#[derive(serde::Deserialize, Debug, Clone)]
pub struct Format {
    /// The credential type
    #[serde(rename = "type")]
    pub data_type: String,
    pub subject_token_field_name: String,
}

#[derive(serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum CredentialSource {
    Url {
        // Note that the URL here includes the audience.
        url: String,
        headers: HashMap<String, String>,
        format: Format,
    },
}

impl CredentialSource {
    fn get_token(&self) -> Result<String, Error> {
        match self {
            CredentialSource::Url {
                url,
                headers,
                format,
            } => {
                if format.data_type != "json" {
                    return Err(Error::InvalidKeyFormat); // not quite kosher, just for mocking
                }

                // TODO: call url with headers, get a jwt back.
                // use format.subject_token_field_name to grab the actual token from the response json
                Ok("this-is-not-a-jwt-token".to_owned())
            }
        }
    }
}
/// Provides tokens using
/// [default application credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
#[derive(serde::Deserialize, Debug, Clone)]
pub struct ExternalAccountCredentials {
    /// The credential type
    #[serde(rename = "type")]
    pub client_type: String,
    /// The audience
    pub audience: String,
    /// The token type of the oauth credentials
    pub subject_token_type: String,
    /// The url to call to retrieve an access token from
    pub token_url: String,
    /// The url of the credentials this token is pretending to be
    pub service_account_impersonation_url: String,
    /// The source for the actual credentials we want to use
    pub credential_source: CredentialSource,
}

impl ExternalAccountCredentials {
    /// Deserializes the `ExternalAccountCredentials` from a byte slice. This
    /// data is typically acquired by reading a credentials file.
    pub fn deserialize<T>(key_data: T) -> Result<Self, Error>
    where
        T: AsRef<[u8]>,
    {
        let slice = key_data.as_ref();

        let account_info: Self = serde_json::from_slice(slice)?;
        Ok(account_info)
    }
}

impl TokenProvider for ExternalAccountCredentials {
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        subject: Option<T>,
        // ExternalAccountCredentials get their scopes... from somewhere.
        _scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
        T: Into<String>,
    {
        // TODO[TSolberg]: Investigate whether we can have subjects for
        // ExternalAccountCredentials. Documentation says neither yay
        // or nay so assuming nay.
        if subject.is_some() {
            return Err(Error::Auth(error::AuthError {
                error: Some("Unsupported".to_string()),
                error_description: Some(
                    "External Account tokens do not support jwt subjects".to_string(),
                ),
            }));
        }

        let url = &self.token_url;
        let subject_token = self.credential_source.get_token()?;

        /* This is what the docs say
        curl https://sts.googleapis.com/v1/token \
          --data-urlencode "audience=//iam.googleapis.com/locations/global/workforcePools/WORKFORCE_POOL_ID/providers/PROVIDER_ID" \
          --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
          --data-urlencode "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
          --data-urlencode "scope=https://www.googleapis.com/auth/cloud-platform" \
          --data-urlencode "subject_token_type=SUBJECT_TOKEN_TYPE" \
          --data-urlencode "subject_token=EXTERNAL_SUBJECT_TOKEN"  \
          --data-urlencode "options={\"userProject\" :\"BILLING_PROJECT_NUMBER\"}"
        */
        // Build up the parameters as a form encoded string.
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("audience", &self.audience)
            .append_pair(
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            )
            .append_pair(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:access_token",
            )
            .append_pair("scope", "https://www.googleapis.com/auth/cloud-platform")
            .append_pair("subject_token_type", &self.subject_token_type)
            .append_pair("subject_token", &subject_token)
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

        // Convert it into our output.
        let token: Token = token_res.into();
        Ok(token)
    }
}
