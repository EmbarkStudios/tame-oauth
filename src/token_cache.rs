use crate::token::{TokenOrRequest, TokenProvider};
use crate::{error::Error, token::RequestReason, Token};

use std::hash::Hasher;
use std::sync::Mutex;

type Hash = u64;

struct Entry {
    hash: Hash,
    token: Token,
}

pub struct TokenCache {
    cache: Mutex<Vec<Entry>>,
}

pub enum TokenOrRequestReason {
    Token(Token),
    RequestReason(RequestReason),
}

impl TokenCache {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(Vec::new()),
        }
    }

    pub fn get(&self, hash: Hash) -> Result<TokenOrRequestReason, Error> {
        let reason = {
            let cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
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

    pub fn insert(&self, token: Token, hash: Hash) -> Result<(), Error> {
        // Last token wins, which...should?...be fine
        let mut cache = self.cache.lock().map_err(|_e| Error::Poisoned)?;
        match cache.binary_search_by(|i| i.hash.cmp(&hash)) {
            Ok(i) => cache[i].token = token,
            Err(i) => {
                cache.insert(i, Entry { hash, token });
            }
        };

        Ok(())
    }
}

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
    use super::*;

    #[test]
    fn hash_scopes_test() {
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
}
