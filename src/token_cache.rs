use crate::token::{TokenOrRequest, TokenProvider};
use crate::{error::Error, token::RequestReason, Token};

use std::hash::Hasher;
use std::sync::RwLock;

type Hash = u64;

struct Entry {
    hash: Hash,
    token: Token,
}

/// An in-memory cache for caching tokens.
pub struct TokenCache {
    cache: RwLock<Vec<Entry>>,
}

pub enum TokenOrRequestReason {
    Token(Token),
    RequestReason(RequestReason),
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(Vec::new()),
        }
    }

    /// Get a token from the cache that matches the hash
    pub fn get(&self, hash: Hash) -> Result<TokenOrRequestReason, Error> {
        let reason = {
            let cache = self.cache.read().map_err(|_e| Error::Poisoned)?;
            match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
                Ok(i) => {
                    let token = &cache[i].token;

                    if !token.has_expired() {
                        return Ok(TokenOrRequestReason::Token(token.clone()));
                    }

                    RequestReason::Expired
                }
                Err(_) => RequestReason::ScopesChanged,
            }
        };

        Ok(TokenOrRequestReason::RequestReason(reason))
    }

    /// Insert a token into the cache
    pub fn insert(&self, token: Token, hash: Hash) -> Result<(), Error> {
        // Last token wins, which...should?...be fine
        let mut cache = self.cache.write().map_err(|_e| Error::Poisoned)?;
        match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
            Ok(i) => cache[i].token = token,
            Err(i) => {
                cache.insert(i, Entry { hash, token });
            }
        };

        Ok(())
    }
}

/// Wraps a `TokenProvider` in a cache, only invokes the inner `TokenProvider` if
/// the token in cache is expired, or if it doesn't exsist.
pub struct CachedTokenProvider<P> {
    cache: TokenCache,
    inner: P,
}

impl<P> CachedTokenProvider<P> {
    pub fn wrap(token_provider: P) -> Self {
        Self {
            cache: TokenCache::new(),
            inner: token_provider,
        }
    }
}

impl<P> TokenProvider for CachedTokenProvider<P>
where
    P: TokenProvider,
{
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
        let hash = hash_scopes(&scopes);

        let reason = match self.cache.get(hash)? {
            TokenOrRequestReason::Token(token) => return Ok(TokenOrRequest::Token(token)),
            TokenOrRequestReason::RequestReason(reason) => reason,
        };

        match self.inner.get_token_with_subject(subject, scopes)? {
            TokenOrRequest::Token(token) => Ok(TokenOrRequest::Token(token)),
            TokenOrRequest::Request { request, .. } => Ok(TokenOrRequest::Request {
                request,
                reason,
                scope_hash: hash,
            }),
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
        let token = self.inner.parse_token_response(hash, response)?;

        self.cache.insert(token.clone(), hash)?;
        Ok(token)
    }
}

fn hash_scopes<'a, I, S>(scopes: &I) -> Hash
where
    S: AsRef<str> + 'a,
    I: IntoIterator<Item = &'a S> + Clone,
{
    let scopes_str = scopes
        .clone()
        .into_iter()
        .map(|s| s.as_ref())
        .collect::<Vec<_>>()
        .join("|");

    let hash = {
        let mut hasher = twox_hash::XxHash::default();
        hasher.write(scopes_str.as_bytes());
        hasher.finish()
    };

    hash
}

#[cfg(test)]
mod test {
    use std::{
        ops::Add,
        ops::Sub,
        time::{Duration, SystemTime},
    };

    use super::*;

    #[test]
    fn test_hash_scopes() {
        use std::hash::Hasher;

        let expected = {
            let mut hasher = twox_hash::XxHash::default();
            hasher.write(b"scope1|");
            hasher.write(b"scope2|");
            hasher.write(b"scope3");
            hasher.finish()
        };

        let hash = hash_scopes(&["scope1", "scope2", "scope3"].iter());

        assert_eq!(expected, hash);

        let hash = hash_scopes(
            &vec![
                "scope1".to_owned(),
                "scope2".to_owned(),
                "scope3".to_owned(),
            ]
            .iter(),
        );

        assert_eq!(expected, hash);
    }

    #[test]
    fn test_cache() {
        let cache = TokenCache::new();
        let hash = hash_scopes(&["scope1", "scope2"].iter());
        let token = mock_token(100);
        let expired_token = mock_token(-100);

        assert!(matches!(
            cache.get(hash).unwrap(),
            TokenOrRequestReason::RequestReason(RequestReason::ScopesChanged)
        ));

        cache.insert(expired_token, hash).unwrap();

        assert!(matches!(
            cache.get(hash).unwrap(),
            TokenOrRequestReason::RequestReason(RequestReason::Expired)
        ));

        cache.insert(token, hash).unwrap();

        assert!(matches!(
            cache.get(hash).unwrap(),
            TokenOrRequestReason::Token(..)
        ));
    }

    #[test]
    fn test_cache_wrapper() {
        let cached_provider = CachedTokenProvider::wrap(PanicProvider);

        let hash = hash_scopes(&["scope1", "scope2"].iter());
        let token = mock_token(100);

        cached_provider.cache.insert(token, hash).unwrap();

        let tor = cached_provider.get_token(&["scope1", "scope2"]).unwrap();

        // check that a token in returned
        assert!(matches!(tor, TokenOrRequest::Token(..)));
    }

    fn mock_token(expires_in: i64) -> Token {
        let expires_in_timestamp = if expires_in > 0 {
            SystemTime::now().add(Duration::from_secs(expires_in as u64))
        } else {
            SystemTime::now().sub(Duration::from_secs(expires_in.unsigned_abs()))
        };

        Token {
            access_token: "access-token".to_string(),
            refresh_token: "refresh-token".to_string(),
            token_type: "token-type".to_string(),
            expires_in: Some(expires_in),
            expires_in_timestamp: Some(expires_in_timestamp),
        }
    }

    /// `PanicProvider` is a mock token provider that panics if called, as a way of
    /// testing that the cache wrapper handles the request.
    struct PanicProvider;
    impl TokenProvider for PanicProvider {
        fn get_token_with_subject<'a, S, I, T>(
            &self,
            _subject: Option<T>,
            _scopes: I,
        ) -> Result<TokenOrRequest, Error>
        where
            S: AsRef<str> + 'a,
            I: IntoIterator<Item = &'a S> + Clone,
            T: Into<String>,
        {
            panic!("should not have been reached")
        }

        fn parse_token_response<S>(
            &self,
            _hash: u64,
            _response: http::Response<S>,
        ) -> Result<Token, Error>
        where
            S: AsRef<[u8]>,
        {
            panic!("should not have been reached")
        }
    }
}
