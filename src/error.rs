use err_derive::Error as Err;

#[derive(Err, Debug)]
pub enum Error {
    #[error(display = "{}", _0)]
    Io(#[error(cause)] std::io::Error),
    #[cfg(feature = "jwt")]
    #[error(display = "The key format is invalid or unknown")]
    InvalidKeyFormat,
    #[error(display = "{}", _0)]
    Base64Decode(#[error(cause)] base64::DecodeError),
    #[error(display = "{}", _0)]
    Http(#[error(cause)] http::Error),
    #[error(display = "HTTP error status: {}", _0)]
    HttpStatus(http::StatusCode),
    #[error(display = "{}", _0)]
    Json(#[error(cause)] serde_json::Error),
    #[error(display = "Auth error {}", _0)]
    AuthError(#[error(cause)] AuthError),
    #[cfg(feature = "jwt")]
    #[error(display = "RSA key is invalid")]
    InvalidRsaKey,
}

#[derive(serde::Deserialize, Debug, Err)]
#[error(display = "Auth error {:?}", error_description)]
pub struct AuthError {
    /// Top level error type
    error: Option<String>,
    /// More specific details on the error
    error_description: Option<String>,
}
