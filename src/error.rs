use std::{error::Error as Err, fmt};

#[derive(Debug)]
pub enum Error {
    /// The private_key field in the [Service Account Key](https://cloud.google.com/iam/docs/creating-managing-service-account-keys)
    /// is invalid and cannot be parsed
    #[cfg(feature = "jwt")]
    InvalidKeyFormat,
    /// Unable to deserialize the base64 encoded RSA key
    Base64Decode(base64::DecodeError),
    /// An error occurred trying to create an HTTP request
    Http(http::Error),
    /// Failed to authenticate and retrieve an oauth token, and were unable to
    /// deserialize a more exact reason from the error response
    HttpStatus(http::StatusCode),
    /// Failed to de/serialize JSON
    Json(serde_json::Error),
    /// Failed to authenticate and retrieve an oauth token
    Auth(AuthError),
    /// The RSA key seems valid, but is unable to sign a payload
    #[cfg(feature = "jwt")]
    InvalidRsaKey(ring::error::Unspecified),
    /// The RSA key is invalid and cannot be used to sign
    #[cfg(feature = "jwt")]
    InvalidRsaKeyRejected(ring::error::KeyRejected),
    /// A mutex has been poisoned due to a panic while a lock was held
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #![allow(clippy::enum_glob_use)]
        use Error::*;

        match self {
            #[cfg(feature = "jwt")]
            InvalidKeyFormat => f.write_str("The key format is invalid or unknown"),
            Base64Decode(err) => write!(f, "{}", err),
            Http(err) => write!(f, "{}", err),
            HttpStatus(sc) => write!(f, "HTTP error status: {}", sc),
            Json(err) => write!(f, "{}", err),
            Auth(err) => write!(f, "{}", err),
            #[cfg(feature = "jwt")]
            InvalidRsaKey(_err) => f.write_str("RSA key is invalid"),
            #[cfg(feature = "jwt")]
            InvalidRsaKeyRejected(err) => write!(f, "RSA key is invalid: {}", err),
            Poisoned => f.write_str("A mutex is poisoned"),
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn Err> {
        use Error::{Auth, Base64Decode, Http, Json};

        match self {
            Base64Decode(err) => Some(err as &dyn Err),
            Http(err) => Some(err as &dyn Err),
            Json(err) => Some(err as &dyn Err),
            Auth(err) => Some(err as &dyn Err),
            _ => None,
        }
    }

    fn source(&self) -> Option<&(dyn Err + 'static)> {
        use Error::{Auth, Base64Decode, Http, Json};

        match self {
            Base64Decode(err) => Some(err as &dyn Err),
            Http(err) => Some(err as &dyn Err),
            Json(err) => Some(err as &dyn Err),
            Auth(err) => Some(err as &dyn Err),
            _ => None,
        }
    }
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

#[derive(serde::Deserialize, Debug)]
pub struct AuthError {
    /// Top level error type
    pub error: Option<String>,
    /// More specific details on the error
    pub error_description: Option<String>,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref err) = self.error {
            write!(f, "{}", err)?;

            if let Some(ref desc) = self.error_description {
                write!(f, "desc: {}", desc)?;
            }
        }

        Ok(())
    }
}

impl std::error::Error for AuthError {}
