//! Provides functionality for
//! [Google oauth](https://developers.google.com/identity/protocols/oauth2)

use crate::{error::Error, jwt};

mod end_user;
mod metadata_server;
mod service_account;

use end_user as eu;
use metadata_server as ms;
use service_account as sa;

pub use crate::token::{Token, TokenOrRequest, TokenProvider};
pub use {
    eu::EndUserCredentials,
    ms::MetadataServerProvider,
    sa::{ServiceAccountInfo, ServiceAccountProvider},
};

struct Entry {
    hash: u64,
    token: Token,
}

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

/// Wrapper around the different providers that are supported
pub enum TokenProviderWrapper {
    EndUser(eu::EndUserCredentials),
    Metadata(ms::MetadataServerProvider),
    ServiceAccount(sa::ServiceAccountProvider),
}

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

            return Ok(Some(TokenProviderWrapper::ServiceAccount(
                sa::ServiceAccountProvider::new(sa_info).map_err(|e| {
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
                    let end_user_credentials = eu::EndUserCredentials::deserialize(json_data)
                        .map_err(|e| Error::InvalidCredentials {
                            file: gcloud_file,
                            error: Box::new(e),
                        })?;

                    return Ok(Some(TokenProviderWrapper::EndUser(end_user_credentials)));
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

        // Finaly, if we are on GCP, use the metadata server. If we're not on
        // GCP, this will just fail to read the file.
        if let Ok(full_name) = read_to_string("/sys/class/dmi/id/product_name") {
            // The product name can annoyingly include a newline...
            let trimmed = full_name.trim();
            match trimmed {
                // This matches the Golang client. If new products
                // add additional values, this will need to be updated.
                "Google" | "Google Compute Engine" => {
                    return Ok(Some(TokenProviderWrapper::Metadata(
                        ms::MetadataServerProvider::new(None),
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
}

impl TokenProvider for TokenProviderWrapper {
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
        match self {
            Self::EndUser(x) => x.get_token_with_subject(subject, scopes),
            Self::Metadata(x) => x.get_token_with_subject(subject, scopes),
            Self::ServiceAccount(x) => x.get_token_with_subject(subject, scopes),
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
            Self::EndUser(x) => x.parse_token_response(hash, response),
            Self::Metadata(x) => x.parse_token_response(hash, response),
            Self::ServiceAccount(x) => x.parse_token_response(hash, response),
        }
    }
}

impl From<TokenResponse> for Token {
    fn from(tr: TokenResponse) -> Self {
        let expires_ts = chrono::Utc::now().timestamp() + tr.expires_in;

        Self {
            access_token: tr.access_token,
            token_type: tr.token_type,
            refresh_token: String::new(),
            expires_in: Some(tr.expires_in),
            expires_in_timestamp: Some(expires_ts),
        }
    }
}
