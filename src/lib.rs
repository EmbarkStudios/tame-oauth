#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![allow(clippy::redundant_closure)] // https://github.com/EmbarkStudios/rust-ecosystem/issues/22#issuecomment-482290614

#[macro_use(Fail)]
extern crate failure;
#[macro_use(Deserialize)]
#[cfg_attr(feature = "gcp", macro_use(Serialize))]
extern crate serde;

#[cfg(feature = "gcp")]
mod gcp;

mod error;
mod token;

pub use error::Error;
pub use token::Token;

#[cfg(feature = "gcp")]
pub use gcp::{RequestReason, ServiceAccountAccess, ServiceAccountInfo, TokenOrRequest};

// As we are dependent on a fork of jsonwebtoken, expose it publicly so that
// downstream crates don't have to patch it themselves
#[cfg(feature = "gcp")]
pub use jsonwebtoken;
