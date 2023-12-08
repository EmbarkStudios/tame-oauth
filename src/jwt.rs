use crate::Error;
use crate::sign::{sign, Algorithm, Key};
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Claims {
    #[serde(rename = "iss")]
    pub(crate) issuer: String,
    #[serde(rename = "aud")]
    pub(crate) audience: String,
    #[serde(rename = "exp")]
    pub(crate) expiration: i64,
    #[serde(rename = "iat")]
    pub(crate) issued_at: i64,
    #[serde(rename = "sub")]
    pub(crate) subject: Option<String>,
    pub(crate) scope: String,
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct Header {
    /// The type of JWS: it can only be "JWT" here
    ///
    /// Defined in [RFC7515#4.1.9](https://tools.ietf.org/html/rfc7515#section-4.1.9).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// The algorithm used
    ///
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    pub alg: Algorithm,
    /// Content type
    ///
    /// Defined in [RFC7519#5.2](https://tools.ietf.org/html/rfc7519#section-5.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cty: Option<String>,
    /// JSON Key URL
    ///
    /// Defined in [RFC7515#4.1.2](https://tools.ietf.org/html/rfc7515#section-4.1.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jku: Option<String>,
    /// Key ID
    ///
    /// Defined in [RFC7515#4.1.4](https://tools.ietf.org/html/rfc7515#section-4.1.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// X.509 URL
    ///
    /// Defined in [RFC7515#4.1.5](https://tools.ietf.org/html/rfc7515#section-4.1.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    /// X.509 certificate thumbprint
    ///
    /// Defined in [RFC7515#4.1.7](https://tools.ietf.org/html/rfc7515#section-4.1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
}

impl Header {
    /// Returns a JWT header with the algorithm given
    pub fn new(algorithm: Algorithm) -> Header {
        Header {
            typ: Some("JWT".to_string()),
            alg: algorithm,
            cty: None,
            jku: None,
            kid: None,
            x5u: None,
            x5t: None,
        }
    }
}

impl Default for Header {
    /// Returns a JWT header using the default Algorithm, HS256
    fn default() -> Self {
        Header::new(Algorithm::default())
    }
}

/// Serializes to JSON and encodes to base64
pub fn to_jwt_part<T: Serialize>(input: &T) -> Result<String, Error> {
    let json = serde_json::to_string(input)?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(json.as_bytes()))
}

pub fn encode<T: Serialize>(header: &Header, claims: &T, key: Key<'_>) -> Result<String, Error> {
    let encoded_header = to_jwt_part(&header)?;
    let encoded_claims = to_jwt_part(&claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&signing_input, key, header.alg)?;

    Ok([signing_input, signature].join("."))
}
