use std::{error::Error as Err, fmt};

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    #[cfg(feature = "jwt")]
    InvalidKeyFormat,
    Base64Decode(base64::DecodeError),
    Http(http::Error),
    HttpStatus(http::StatusCode),
    Json(serde_json::Error),
    Auth(AuthError),
    #[cfg(feature = "jwt")]
    InvalidRsaKey(ring::error::Unspecified),
    #[cfg(feature = "jwt")]
    InvalidRsaKeyRejected(ring::error::KeyRejected),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #![allow(clippy::enum_glob_use)]
        use Error::*;

        match self {
            Io(err) => write!(f, "{}", err),
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
        }
    }
}

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn Err> {
        use Error::{Auth, Base64Decode, Http, Io, Json};

        match self {
            Io(err) => Some(err as &dyn Err),
            Base64Decode(err) => Some(err as &dyn Err),
            Http(err) => Some(err as &dyn Err),
            Json(err) => Some(err as &dyn Err),
            Auth(err) => Some(err as &dyn Err),
            _ => None,
        }
    }

    fn source(&self) -> Option<&(dyn Err + 'static)> {
        use Error::{Auth, Base64Decode, Http, Io, Json};

        match self {
            Io(err) => Some(err as &dyn Err),
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
    error: Option<String>,
    /// More specific details on the error
    error_description: Option<String>,
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
