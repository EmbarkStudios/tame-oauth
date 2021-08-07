use crate::{
    error::Error,
    token::{Token, TokenOrRequest, TokenProvider},
};

mod end_user;
mod jwt;
mod metadata_server;
mod service_account;

use end_user as eu;
use metadata_server as ms;
use service_account as sa;

pub mod prelude {
    pub use super::{
        eu::EndUserCredentials,
        get_default_google_credentials,
        ms::MetadataServerProvider,
        sa::{ServiceAccountAccess, ServiceAccountInfo},
        TokenProviderWrapper,
    };
    pub use crate::token::{Token, TokenOrRequest, TokenProvider};
}

struct Entry {
    hash: u64,
    token: Token,
}

/// Both the `ServiceAccountAccess` and `MetadataServerProvider` get
/// back JSON responses with this schema from their endpoints.
#[derive(serde::Deserialize, Debug)]
struct TokenResponse {
    /// The actual token
    access_token: String,
    /// The token type, pretty much always Header
    token_type: String,
    /// The time until the token expires and a new one needs to be requested
    expires_in: i64,
}

/// Simple wrapper of our three GCP token providers.
pub enum TokenProviderWrapper {
    EndUser(eu::EndUserCredentials),
    Metadata(ms::MetadataServerProvider),
    ServiceAccount(sa::ServiceAccountAccess),
}

/// Implement `TokenProvider` for `TokenProviderWrapper` so that
/// clients don't have to do the dispatch themselves.
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

/// Get the path to the gcloud `application_default_credentials.json`
/// file. This function respects the `CLOUDSDK_CONFIG` environment
/// variable. If unset, it looks in the platform-specific gcloud
/// configuration directories (%APPDATA%/gcloud on Windows or
/// $HOME/.config/gcloud otherwise).
fn gcloud_config_file() -> Result<std::path::PathBuf, std::env::VarError> {
    let cred_file = "application_default_credentials.json";
    // If the user has set CLOUDSDK_CONFIG, that overrides the default directory.
    let env_key = "CLOUDSDK_CONFIG";
    let override_dir_or_none = std::env::var(env_key);

    if let Ok(override_dir) = override_dir_or_none {
        return Ok(std::path::Path::new(&override_dir).join(cred_file));
    }

    // Otherwise, use the default for the
    // platform. %APPDATA%/gcloud/<file> on Windows and
    // $HOME/.config/gcloud/<file> elsewhere.
    let base_dir = if cfg!(windows) {
        std::path::Path::new(&std::env::var("APPDATA")?).to_path_buf()
    } else {
        std::path::Path::new(&std::env::var("HOME")?).join(".config")
    };

    Ok(base_dir.join("gcloud").join(cred_file))
}

/// Get a `TokenProvider` following the "Google Default Credentials"
/// flow, in order:
///
///  * If the `GOOGLE_APPLICATION_CREDENTIALS` environment variable is
///    set. Use that as a path to a service account JSON file.
///
///  * Check for a gcloud config file (see `gcloud_config_file`) to
///    get `EndUserCredentials`.
///
///  * If we're running on GCP, use the local metadata server.
///
///  * Otherwise, return None.
pub fn get_default_google_credentials() -> Option<TokenProviderWrapper> {
    // Read in the usual key file.
    let env_key = "GOOGLE_APPLICATION_CREDENTIALS";
    // Use var_os to get the path.
    let cred_env = std::env::var_os(env_key);

    // If the environment variable is present, try to open it as a
    // Service Account. Otherwise, proceed to step 2 (checking the
    // gcloud credentials).
    if let Some(cred_path) = cred_env {
        let key_data = std::fs::read_to_string(cred_path).expect("Failed to read credential file");
        let acct_info = sa::ServiceAccountInfo::deserialize(key_data)
            .expect("Failed to decode credential file");

        return Some(TokenProviderWrapper::ServiceAccount(
            sa::ServiceAccountAccess::new(acct_info)
                .expect("failed to create OAuth Token Provider"),
        ));
    }

    let gcloud_file = gcloud_config_file();
    if let Ok(gcloud_file) = gcloud_file {
        let gcloud_data = std::fs::read_to_string(gcloud_file);

        match gcloud_data {
            Ok(json_data) => {
                let end_user_credentials = eu::EndUserCredentials::deserialize(json_data)
                    .expect("Failed to decode application_default_credentials.json");
                return Some(TokenProviderWrapper::EndUser(end_user_credentials));
            }
            Err(error) => match error.kind() {
                // Skip not found errors, so we fall to the metadata server check.
                std::io::ErrorKind::NotFound => {}
                other_error => panic!(
                    "Failed to open gcloud credential file. Error {:?}",
                    other_error
                ),
            },
        }
    }

    // Finaly, if we are on GCP, use the metadata server. If we're not
    // on GCP, this will just fail to read the file.
    let product_file = "/sys/class/dmi/id/product_name";
    let product_name = std::fs::read_to_string(product_file);

    if let Ok(full_name) = product_name {
        // The product name can annoyingly include a newline...
        let trimmed = full_name.trim();
        match trimmed {
            // This matches the Golang client. If new products
            // add additional values, this will need to be updated.
            "Google" | "Google Compute Engine" => {
                return Some(TokenProviderWrapper::Metadata(
                    ms::MetadataServerProvider::new(None),
                ));
            }
            _ => {}
        }
    }

    // None of our checks worked. Give up.
    None
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
