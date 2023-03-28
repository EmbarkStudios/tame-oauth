//! Provides functionality for
//! [Google oauth](https://developers.google.com/identity/protocols/oauth2)

use crate::token_cache::CachedTokenProvider;
use crate::{error::Error, jwt};

pub mod end_user;
pub mod metadata_server;
pub mod service_account;

use end_user as eu;
use metadata_server as ms;
use service_account as sa;

pub use crate::id_token::{
    AccessTokenResponse, IdToken, IdTokenOrRequest, IdTokenProvider, IdTokenRequest,
    IdTokenResponse,
};
pub use crate::token::{Token, TokenOrRequest, TokenProvider};
pub use {
    end_user::{EndUserCredentials, EndUserCredentialsInfo},
    metadata_server::MetadataServerProvider,
    service_account::{ServiceAccountInfo, ServiceAccountProvider},
};

/// Both the [`ServiceAccountProvider`] and [`MetadataServerProvider`] get back
/// JSON responses with this schema from their endpoints.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,
    /// The token type, pretty much always Header
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: i64,
}

pub type TokenProviderWrapper = CachedTokenProvider<TokenProviderWrapperInner>;
impl TokenProviderWrapper {
    /// Get a `TokenProvider` following the "Google Default Credentials"
    /// flow, in order:
    ///
    /// * If the `GOOGLE_APPLICATION_CREDENTIALS` environment variable is
    ///   set, use that as a path to a [`ServiceAccountInfo`](sa::ServiceAccountInfo).
    ///
    /// * Check for a gcloud's
    /// [Application Default Credentials](https://cloud.google.com/sdk/gcloud/reference/auth/application-default)
    /// for [`EndUserCredentials`](eu::EndUserCredentials)
    ///
    /// * If we're running on GCP, use the local metadata server.
    ///
    /// * Otherwise, return None.
    ///
    /// If it appears that a method is being used, but is actually invalid,
    /// eg `GOOGLE_APPLICATION_CREDENTIALS` is set but the file doesn't exist or
    /// contains invalid JSON, an error is returned with the details
    pub fn get_default_provider() -> Result<Option<Self>, Error> {
        TokenProviderWrapperInner::get_default_provider()
            .map(|provider| provider.map(CachedTokenProvider::wrap))
    }

    /// Gets the kind of token provider
    pub fn kind(&self) -> &'static str {
        self.inner().kind()
    }

    pub fn is_service_account_provider(&self) -> bool {
        self.inner().is_service_account_provider()
    }
    pub fn is_metadata_server_provider(&self) -> bool {
        self.inner().is_metadata_server_provider()
    }
    pub fn is_end_user_credentials_provider(&self) -> bool {
        self.inner().is_end_user_credentials_provider()
    }
}

/// Wrapper around the different providers that are supported. Implements both `TokenProvider` and `IdTokenProvider`.
/// Should not be used directly as it is not cached. Use `TokenProviderWrapper` instead.
#[derive(Debug)]
pub enum TokenProviderWrapperInner {
    EndUser(eu::EndUserCredentialsInner),
    Metadata(ms::MetadataServerProviderInner),
    ServiceAccount(sa::ServiceAccountProviderInner),
}

impl TokenProviderWrapperInner {
    /// Get a `TokenProvider` following the "Google Default Credentials" flow.
    /// Returns a uncached token provider, use `TokenProviderWrapper::get_default_provider`
    /// instead.
    pub fn get_default_provider() -> Result<Option<Self>, Error> {
        use std::{fs::read_to_string, path::PathBuf};

        // If the environment variable is present, try to open it as a
        // Service Account.
        if let Some(cred_path) = std::env::var_os("GOOGLE_APPLICATION_CREDENTIALS") {
            let key_data = match read_to_string(&cred_path) {
                Ok(kd) => kd,
                Err(e) => {
                    return Err(Error::InvalidCredentials {
                        file: cred_path.into(),
                        error: Box::new(Error::Io(e)),
                    });
                }
            };

            let sa_info = match sa::ServiceAccountInfo::deserialize(key_data) {
                Ok(si) => si,
                Err(e) => {
                    return Err(Error::InvalidCredentials {
                        file: cred_path.into(),
                        error: Box::new(e),
                    });
                }
            };

            return Ok(Some(TokenProviderWrapperInner::ServiceAccount(
                sa::ServiceAccountProviderInner::new(sa_info).map_err(|e| {
                    Error::InvalidCredentials {
                        file: cred_path.into(),
                        error: Box::new(e),
                    }
                })?,
            )));
        }

        /// Get the path to the gcloud `application_default_credentials.json`
        /// file. This function respects the `CLOUDSDK_CONFIG` environment
        /// variable. If unset, it looks in the platform-specific gcloud
        /// configuration directories
        fn gcloud_config_file() -> Option<PathBuf> {
            let cred_file = "application_default_credentials.json";

            // If the user has set CLOUDSDK_CONFIG, that overrides the default directory.
            if let Some(override_dir) = std::env::var_os("CLOUDSDK_CONFIG") {
                let mut pb = PathBuf::from(override_dir);
                pb.push(cred_file);
                return Some(pb);
            }

            // Otherwise, use the default for the platform.
            // * Windows - %APPDATA%/gcloud/<file>
            // * Unix - $HOME/.config/gcloud/<file>
            if cfg!(windows) {
                std::env::var_os("APPDATA").map(PathBuf::from)
            } else {
                std::env::var_os("HOME").map(|pb| {
                    let mut pb = PathBuf::from(pb);
                    pb.push(".config");
                    pb
                })
            }
            .map(|mut bd| {
                bd.push("gcloud");
                bd.push(cred_file);
                bd
            })
        }

        if let Some(gcloud_file) = gcloud_config_file() {
            match read_to_string(&gcloud_file) {
                Ok(json_data) => {
                    let end_user_credentials = eu::EndUserCredentialsInfo::deserialize(json_data)
                        .map_err(|e| Error::InvalidCredentials {
                        file: gcloud_file,
                        error: Box::new(e),
                    })?;

                    return Ok(Some(TokenProviderWrapperInner::EndUser(
                        eu::EndUserCredentialsInner::new(end_user_credentials),
                    )));
                }
                // Skip not found errors, and fall back to the metadata server check
                Err(nf) if nf.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(Error::InvalidCredentials {
                        file: gcloud_file,
                        error: Box::new(Error::Io(err)),
                    });
                }
            }
        }

        // Finally, if we are on GCP, use the metadata server. If we're not on
        // GCP, this will just fail to read the file.
        if let Ok(full_name) = read_to_string("/sys/class/dmi/id/product_name") {
            // The product name can annoyingly include a newline...
            let trimmed = full_name.trim();
            match trimmed {
                // This matches the Golang client. If new products
                // add additional values, this will need to be updated.
                "Google" | "Google Compute Engine" => {
                    return Ok(Some(TokenProviderWrapperInner::Metadata(
                        ms::MetadataServerProviderInner::new(None),
                    )));
                }
                _ => {}
            }
        }

        // None of our checks worked. Give up.
        Ok(None)
    }

    /// Gets the kind of token provider
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EndUser(_) => "End User",
            Self::Metadata(_) => "Metadata Server",
            Self::ServiceAccount(_) => "Service Account",
        }
    }

    pub fn is_service_account_provider(&self) -> bool {
        matches!(self, TokenProviderWrapperInner::ServiceAccount(_))
    }
    pub fn is_metadata_server_provider(&self) -> bool {
        matches!(self, TokenProviderWrapperInner::Metadata(_))
    }
    pub fn is_end_user_credentials_provider(&self) -> bool {
        matches!(self, TokenProviderWrapperInner::EndUser(_))
    }
}

impl TokenProvider for TokenProviderWrapperInner {
    fn get_token_with_subject<'a, S, I, T>(
        &self,
        subject: Option<T>,
        scopes: I,
    ) -> Result<TokenOrRequest, Error>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S> + Clone,
        T: Into<String>,
    {
        match self {
            Self::EndUser(token_provider) => token_provider.get_token_with_subject(subject, scopes),
            Self::Metadata(token_provider) => {
                token_provider.get_token_with_subject(subject, scopes)
            }
            Self::ServiceAccount(token_provider) => {
                token_provider.get_token_with_subject(subject, scopes)
            }
        }
    }

    fn parse_token_response<S>(
        &self,
        hash: u64,
        response: http::Response<S>,
    ) -> Result<Token, Error>
    where
        S: AsRef<[u8]>,
    {
        match self {
            Self::EndUser(token_provider) => token_provider.parse_token_response(hash, response),
            Self::Metadata(token_provider) => token_provider.parse_token_response(hash, response),
            Self::ServiceAccount(token_provider) => {
                token_provider.parse_token_response(hash, response)
            }
        }
    }
}

impl IdTokenProvider for TokenProviderWrapperInner {
    fn get_id_token(&self, audience: &str) -> Result<IdTokenOrRequest, Error> {
        match self {
            Self::EndUser(token_provider) => token_provider.get_id_token(audience),
            Self::Metadata(token_provider) => token_provider.get_id_token(audience),
            Self::ServiceAccount(token_provider) => token_provider.get_id_token(audience),
        }
    }

    fn get_id_token_with_access_token<S>(
        &self,
        audience: &str,
        response: AccessTokenResponse<S>,
    ) -> Result<IdTokenRequest, Error>
    where
        S: AsRef<[u8]>,
    {
        match self {
            Self::EndUser(token_provider) => {
                token_provider.get_id_token_with_access_token(audience, response)
            }
            Self::Metadata(token_provider) => {
                token_provider.get_id_token_with_access_token(audience, response)
            }
            Self::ServiceAccount(token_provider) => {
                token_provider.get_id_token_with_access_token(audience, response)
            }
        }
    }

    fn parse_id_token_response<S>(
        &self,
        hash: u64,
        response: http::Response<S>,
    ) -> Result<IdToken, Error>
    where
        S: AsRef<[u8]>,
    {
        match self {
            Self::EndUser(token_provider) => token_provider.parse_id_token_response(hash, response),
            Self::Metadata(token_provider) => {
                token_provider.parse_id_token_response(hash, response)
            }
            Self::ServiceAccount(token_provider) => {
                token_provider.parse_id_token_response(hash, response)
            }
        }
    }
}

impl From<TokenResponse> for Token {
    fn from(tr: TokenResponse) -> Self {
        Self {
            access_token: tr.access_token,
            token_type: tr.token_type,
            refresh_token: String::new(),
            expires_in: Some(tr.expires_in),
            expires_in_timestamp: std::time::SystemTime::now()
                .checked_add(std::time::Duration::from_secs(tr.expires_in as u64)),
        }
    }
}
