use super::TokenResponse;
use crate::{
    error::{self, Error},
    id_token::{IdTokenOrRequest, IdTokenProvider},
    token::{RequestReason, Token, TokenOrRequest, TokenProvider},
    token_cache::CachedTokenProvider,
    IdToken,
};

const METADATA_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts";

/// [Provides tokens](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)
/// using the metadata server accessible when running from within GCP.
/// Caches tokens internally.
pub type MetadataServerProvider = CachedTokenProvider<MetadataServerProviderInner>;
impl MetadataServerProvider {
    pub fn new(account_name: Option<String>) -> Self {
        CachedTokenProvider::wrap(MetadataServerProviderInner::new(account_name))
    }
}

/// [Provides tokens](https://cloud.google.com/compute/docs/instances/verifying-instance-identity)
/// using the metadata server accessible when running from within GCP. Should not be used directly as it
/// is not cached. Use `MetadataServerProvider` instead.
#[derive(Debug)]
pub struct MetadataServerProviderInner {
    account_name: String,
}

impl MetadataServerProviderInner {
    pub fn new(account_name: Option<String>) -> Self {
        Self {
            account_name: account_name.unwrap_or_else(|| "default".into()),
        }
    }
}

impl TokenProvider for MetadataServerProviderInner {
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
            return Err(Error::Auth(error::AuthError {
                error: Some("Unsupported".to_string()),
                error_description: Some(
                    "Metadata server tokens do not support jwt subjects".to_string(),
                ),
            }));
        }

        // Regardless of GCE or GAE, the token_uri is
        // `computeMetadata/v1/instance/service-accounts/<name or id>/token`.
        let mut url = format!("{}/{}/token", METADATA_URL, self.account_name);

        // Merge all the scopes into a single string.
        let scopes_str = scopes
            .into_iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(",");

        // If we have any scopes, pass them along in the querystring.
        if !scopes_str.is_empty() {
            url.push_str("?scopes=");
            url.push_str(&scopes_str);
        }

        let request = http::Request::builder()
            .method("GET")
            .uri(url)
            // To get responses from GCE, we must pass along the
            // Metadata-Flavor header with a value of "Google".
            .header("Metadata-Flavor", "Google")
            .body(Vec::new())?;

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

        // Convert it into our output.
        let token: Token = token_res.into();
        Ok(token)
    }
}

impl IdTokenProvider for MetadataServerProviderInner {
    fn get_id_token(&self, audience: &str) -> Result<IdTokenOrRequest, error::Error> {
        let url = format!(
            "{}/{}/identity?audience={}",
            METADATA_URL, self.account_name, audience,
        );

        let request = http::Request::builder()
            .method("GET")
            .uri(url)
            .header("Metadata-Flavor", "Google")
            .body(Vec::new())?;

        Ok(IdTokenOrRequest::IdTokenRequest {
            request,
            reason: RequestReason::ParametersChanged,
            audience_hash: 0,
        })
    }

    fn parse_id_token_response<S>(
        &self,
        _hash: u64,
        response: http::Response<S>,
    ) -> Result<IdToken, Error>
    where
        S: AsRef<[u8]>,
    {
        let (parts, body) = response.into_parts();

        if !parts.status.is_success() {
            return Err(Error::HttpStatus(parts.status));
        }

        let token = IdToken::new(String::from_utf8_lossy(body.as_ref()).into_owned())?;

        Ok(token)
    }

    fn get_id_token_with_access_token<S>(
        &self,
        _audience: &str,
        _access_token_resp: crate::id_token::AccessTokenResponse<S>,
    ) -> Result<crate::id_token::IdTokenRequest, Error>
    where
        S: AsRef<[u8]>,
    {
        // ID token via access token is not supported in the metadata service
        // The token can be fetched directly via the metadataservice.
        Err(Error::Auth(error::AuthError {
            error: Some("Unsupported".to_string()),
            error_description: Some(
                "Metadata server id tokens via access token not supported".to_string(),
            ),
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn metadata_noscopes() {
        let provider = MetadataServerProvider::new(None);

        let scopes: &[&str] = &[];

        let token_or_req = provider
            .get_token(scopes)
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

        let scopes = ["scope1", "scope2"];

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
    fn wrapper_dispatch() {
        // Wrap the metadata server provider.
        let provider =
            crate::gcp::TokenProviderWrapperInner::Metadata(MetadataServerProviderInner::new(None));

        // And then have the same test as metadata_with_scopes
        let scopes = ["scope1", "scope2"];

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
}
