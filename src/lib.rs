#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

#[macro_use(Fail)]
extern crate failure;
#[macro_use(Deserialize)]
extern crate serde;

#[cfg(feature = "gcp")]
mod gcp;

mod error;
mod token;

pub use error::Error;
pub use token::Token;

#[cfg(feature = "gcp")]
pub use gcp::{RequestReason, ServiceAccountAccess, ServiceAccountInfo, TokenOrRequest};
