use crate::Error;
use ring::signature;
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
    pub(crate) sub: Option<String>,
    pub(crate) scope: String,
}

/// A basic JWT header, the alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
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

/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Copy, Clone, Serialize, serde::Deserialize)]
pub enum Algorithm {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// ECDSA using SHA-256
    ES256,
    /// ECDSA using SHA-384
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,

    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm::HS256
    }
}

/// The supported RSA key formats, see the documentation for ring::signature::RsaKeyPair
/// for more information
pub enum Key<'a> {
    /// An unencrypted PKCS#8-encoded key. Can be used with both ECDSA and RSA
    /// algorithms when signing. See ring for information.
    Pkcs8(&'a [u8]),
}

/// Serializes to JSON and encodes to base64
pub fn to_jwt_part<T: Serialize>(input: &T) -> Result<String, Error> {
    let encoded = serde_json::to_string(input)?;
    Ok(base64::encode_config(
        encoded.as_bytes(),
        base64::URL_SAFE_NO_PAD,
    ))
}

/// The actual RSA signing + encoding
/// Taken from Ring doc https://briansmith.org/rustdoc/ring/signature/index.html
fn sign_rsa(
    alg: &'static dyn signature::RsaEncoding,
    key: Key<'_>,
    signing_input: &str,
) -> Result<String, Error> {
    let key_pair = match key {
        Key::Pkcs8(bytes) => {
            signature::RsaKeyPair::from_pkcs8(bytes).map_err(|_| Error::InvalidRsaKey)?
        }
    };

    let key_pair = std::sync::Arc::new(key_pair);
    let mut signature = vec![0; key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(|_| Error::InvalidRsaKey)?;

    Ok(base64::encode_config::<[u8]>(
        &signature,
        base64::URL_SAFE_NO_PAD,
    ))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
pub fn sign(signing_input: &str, key: Key<'_>, algorithm: Algorithm) -> Result<String, Error> {
    match algorithm {
        Algorithm::RS256 => sign_rsa(&signature::RSA_PKCS1_SHA256, key, signing_input),
        Algorithm::RS384 => sign_rsa(&signature::RSA_PKCS1_SHA384, key, signing_input),
        Algorithm::RS512 => sign_rsa(&signature::RSA_PKCS1_SHA512, key, signing_input),

        Algorithm::PS256 => sign_rsa(&signature::RSA_PSS_SHA256, key, signing_input),
        Algorithm::PS384 => sign_rsa(&signature::RSA_PSS_SHA384, key, signing_input),
        Algorithm::PS512 => sign_rsa(&signature::RSA_PSS_SHA512, key, signing_input),
        _ => unimplemented!(),
    }
}

pub fn encode<T: Serialize>(header: &Header, claims: &T, key: Key<'_>) -> Result<String, Error> {
    let encoded_header = to_jwt_part(&header)?;
    let encoded_claims = to_jwt_part(&claims)?;
    let signing_input = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = sign(&*signing_input, key, header.alg)?;

    Ok([signing_input, signature].join("."))
}
