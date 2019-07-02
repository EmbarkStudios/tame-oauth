#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

#[macro_use(Fail)]
extern crate failure;
#[macro_use(Deserialize)]
extern crate serde;

#[cfg(feature = "gcp")]
pub mod gcp;

mod error;
mod token;

pub use crate::{error::Error, token::Token};
