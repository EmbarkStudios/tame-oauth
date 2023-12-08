use crate::Error;
#[cfg(feature = "sign-ssl")]
use openssl::{pkey::PKey, sign::Signer, hash::MessageDigest};
#[cfg(feature = "sign-ring")]
use ring::signature;

use serde::Serialize;

/// The algorithms supported for signing/verifying
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, serde::Deserialize)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Default)]
pub enum Algorithm {
    /// HMAC using SHA-256
    #[default]
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

/// The supported RSA key formats, see the documentation for [`ring::signature::RsaKeyPair`]
/// for more information
pub enum Key<'a> {
    /// An unencrypted PKCS#8-encoded key. Can be used with both ECDSA and RSA
    /// algorithms when signing. See ring for information.
    Pkcs8(&'a [u8]),
}

/// The actual RSA signing + encoding
/// Taken from Ring doc <https://briansmith.org/rustdoc/ring/signature/index.html>
#[cfg(feature = "sign-ring")]
fn sign_rsa(
    alg: &'static dyn signature::RsaEncoding,
    key: Key<'_>,
    signing_input: &str,
) -> Result<String, Error> {
    let key_pair = match key {
        Key::Pkcs8(bytes) => {
            signature::RsaKeyPair::from_pkcs8(bytes).map_err(Error::InvalidRsaKeyRejected)?
        }
    };

    let key_pair = std::sync::Arc::new(key_pair);
    let mut signature = vec![0; key_pair.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key_pair
        .sign(alg, &rng, signing_input.as_bytes(), &mut signature)
        .map_err(Error::InvalidRsaKey)?;

    Ok(data_encoding::BASE64_NOPAD.encode(&signature))
}
#[cfg(feature = "sign-ssl")]
fn sign_rsa(
    alg: MessageDigest,
    key: Key<'_>,
    signing_input: &str,
) -> Result<String, Error> {
    let key_pair = match key {
        Key::Pkcs8(bytes) => {
            PKey::private_key_from_pkcs8(bytes).map_err(Error::InvalidRsaKeyRejected)?
        }
    };

    let mut signer = Signer::new(alg, &key_pair).map_err(Error::InvalidRsaKey)?;
    let _ = signer.update(signing_input.as_bytes()).map_err(Error::InvalidRsaKey)?;
    let signature = signer.sign_to_vec().map_err(Error::InvalidRsaKey)?;

    Ok(data_encoding::BASE64_NOPAD.encode(&signature))
}

/// Take the payload of a JWT, sign it using the algorithm given and return
/// the base64 url safe encoded of the result.
///
/// Only use this function if you want to do something other than JWT.
#[cfg(feature = "sign-ring")]
pub fn sign(signing_input: &str, key: Key<'_>, algorithm: Algorithm) -> Result<String, Error> {
    match algorithm {
        Algorithm::RS256 => sign_rsa(&signature::RSA_PKCS1_SHA256, key, signing_input),
        Algorithm::RS384 => sign_rsa(&signature::RSA_PKCS1_SHA384, key, signing_input),
        Algorithm::RS512 => sign_rsa(&signature::RSA_PKCS1_SHA512, key, signing_input),

        Algorithm::PS256 => sign_rsa(&signature::RSA_PSS_SHA256, key, signing_input),
        Algorithm::PS384 => sign_rsa(&signature::RSA_PSS_SHA384, key, signing_input),
        Algorithm::PS512 => sign_rsa(&signature::RSA_PSS_SHA512, key, signing_input),
        _ => panic!("Unsupported algorithm {:?}", algorithm),
    }
}
#[cfg(feature = "sign-ssl")]
pub fn sign(signing_input: &str, key: Key<'_>, algorithm: Algorithm) -> Result<String, Error> {
    match algorithm {
        Algorithm::RS256 => sign_rsa(MessageDigest::sha256(), key, signing_input),
        _ => panic!("Unsupported algorithm {:?}", algorithm),
    }
}

mod test {
    #[test]
    fn test_sign() {
        use super::{sign, Key, Algorithm};
        let signing_intput = "test data";
        let enckey = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDX1h/UiSbHBf3c5L3hAb4QUZ5/nL9CTY11m8uXmWAGaAhjlE7vv15jTaxhjKm+RpfJW3shZao0lxSJgayYY8Ub5Kx3npPfToff/N/sBV7RmZ4FYb6b1XsZpjTy4Bt1LpRtSq/L4lH+boPGCBdJv7uwJkdBTRPBJRnynlpNOreJ08fo80G6qaQn2ZA3P8YusonIS72hW+tdnhrrpxvbIJT/NN2dFfVXxs3KkL6Qu3FuaqvEARqdjuPOdjDkDRwA4gfTlagGPtJVQ4gUl6rgXRTX2o0iGLXIxehHfLrbYP5UOjrfpAiTRdf+E3Ho5KJps09MrHk5yVzauKEUauJ9M+a3AgMBAAECggEBALvM1GVZ8SO7UuihH5ZorbgFTKQ8/y3xzORIax29lo/8dVAv+38gRECjlRpMCmZFhkzuDHVCwJaB3pzG+CagqSFcF7T9hi0HZ7K9lRkIkzhNMfH82p09Y58tv2SVG08a+IsgMVZ11mJMRtxIrfq9mdHrfJSVPFsSrUEuB+Sq8og45KpU/kcPQQ+nlCKzrXwgMi2cqj+cb+9/jnm200VRUFq2iC3lLKtyhVhluCzg0ecpSIpIFHB8mNgDiiLrmV99UCeVoa/E2MrZQTpzQeCA52pIBvMf8LEDLjRNrWq+HRxANuTrPYRJRLlDhVVKwXW5bCLZBvTFXHmV8ejFOsaZQAECgYEA81UftXi+BbXTxdgexBYms4h77KWJTLh5H12MU/U6epfsiZSq7OeWO9sOchUNUK8v3sUDL7FZPg/vSEIbkp5KQzbX6poy/uVrzL7niR+bJGssycaxxGsFJ6QZIMVtlPpLVcBAU96c1fhqMYs85/obVNZSY47qMBeSEZfEP849wzcCgYEA4xKP2I7cWsl42B3fbVaLoQiUhZRbvnvYRyZb8ZOPz4DSqKDHt6CbO7D3vL2mqcL8hqi40tJGRRztU+quUiudA16CzFacmHdgJ0cWJWY9cz9bXofDAtEFkY5u8XbeZu806iCsPh4TRmRwXmw8dOckCZAv8tcQOo7rdxIYin7juIECgYEAkqUSXwNNQZO69NiyceoHmNsAFDYO8LWcCVMPZum7PHaijqeR+wP2fkweAJK/W4i4iMCikvOGnOhthFaS12Gdz7QVm8UiRots1A+Y6gKqNOCCNXgRWhZFHQbAPge9arMNA7jBC8p1Kl5zYThQlF0ea5pePLG8YQ9TcFbOZsWcYzECgYEAsRJufe+ZwmpOBCn3a2oL5H2uZCR3DqnA1GsDU/VANg49OCZ416c0pm2wIsy5xLQ6/D9iMXSsO4T9RW1Clu1Puarf0LzRzMt6feafTHbYAKEtfR/dYLri3sj1lvKdKCPtXY4xAxes7D2yqs84rej5X0PDQFmZXDDLScUgwg+FQQECgYBFaDzuYxNpiBG6RzFiaNfaJ1GNuIZgkI86HTwSma2XttuiOGpgWumfz0JPwercewKNhyu/2QkavPQlf6OQ7gbeOrA+LqEisLkyBSwzFghQItU7/OoTspe1P4+yVEbNGD3bSNsu1xe5p3mSw8/tVQWfhniMeji3k4Lv96kLfYXcZA==";
        let pkey = data_encoding::BASE64.decode(enckey.as_bytes()).unwrap();
        let signature = sign(signing_intput, Key::Pkcs8(&pkey), Algorithm::RS256).unwrap();
        let expected_signature = String::from("DJW80W1MFFp+GAB3dh/TIfwXykHiuzLPuaJaHLVL6qVoCQg2go9cfiXfMS+x2Yp17e4B/bO5qO3ARyQZgIKwOnO+jzP5P0JKq14Ce6g04etxe9xg83iByZeZkf0UDGN6Mn8RLcK2SEECkztP8+aVHvmpTYE4zxRlb0hXxhIR8947LxK6C1ovCMBFBeMWzneYzLrioZSCDHZ9TeADk38zYsX8B6u9gsq1LGnwSaTqJlNiiq6g8iuDZ0cGtys9ovwyZqGG6XZubE8LkQhH8NMRk8KFonZDVI0Mj8WkbeHi8hTVdAuzP+jFiaBMwqzfshhvnDfgV3z3RKp3zpiJNutLNg");
        assert_eq!(signature, expected_signature);
    }
}