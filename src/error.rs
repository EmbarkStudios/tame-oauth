#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "{}", _0)]
    Io(#[fail(cause)] std::io::Error),
    #[fail(display = "The key format is invalid or unknown")]
    InvalidKeyFormat,
    #[fail(display = "{}", _0)]
    Base64Decode(#[fail(cause)] base64::DecodeError),
    #[cfg(feature = "gcp")]
    #[fail(display = "{}", _0)]
    Jwt(#[fail(cause)] jsonwebtoken::errors::Error),
    #[fail(display = "{}", _0)]
    Http(#[fail(cause)] http::Error),
    #[fail(display = "HTTP error status: {}", _0)]
    HttpStatus(http::StatusCode),
    #[fail(display = "{}", _0)]
    Json(#[fail(cause)] serde_json::Error),
    #[fail(display = "Auth error {}", _0)]
    AuthError(#[fail(cause)] AuthError),
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64Decode(e)
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Error::Http(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

#[cfg(feature = "gcp")]
impl From<jsonwebtoken::errors::Error> for Error {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        Error::Jwt(e)
    }
}

#[derive(Deserialize, Debug, Fail)]
#[fail(display = "Auth error {:?}", error_description)]
pub struct AuthError {
    /// Top level error type
    error: Option<String>,
    /// More specific details on the error
    error_description: Option<String>,
}
