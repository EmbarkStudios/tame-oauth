#![warn(clippy::all)]
#![warn(rust_2018_idioms)]

//! # 🔐 tame-oauth
//!
//! [![Build Status](https://travis-ci.com/EmbarkStudios/tame-oauth.svg?branch=master)](https://travis-ci.com/EmbarkStudios/tame-oauth)
//! [![Latest version](https://img.shields.io/crates/v/tame-oauth.svg)](https://crates.io/crates/tame-oauth)
//! [![Docs](https://docs.rs/tame-oauth/badge.svg)](https://docs.rs/tame-oauth)
//!
//! `tame-oauth` is a small oauth crate that follows the [sans-io](https://sans-io.readthedocs.io/) approach.
//!
//! ## Why?
//!
//! * You want to control how you actually make oauth HTTP requests
//!
//! ## Why not?
//!
//! * The only auth flow that is currently implemented is the service account flow for GCP. Other flows
//! can be added, but right now that is the only one we need.
//! * There are several other oauth crates available that have many more features and are easier
//! to work with, if you don't care about what HTTP clients they use.
//! * This crate requires more boilerplate to work with
//!
//! ## Examples
//!
//! ### [svc_account](examples/svc_account.rs)
//!
//! Usage: `cargo run --example svc_account -- <key_path> <scope..>`
//!
//! A small example of using `tame-oauth` together with [reqwest](https://github.com/seanmonstar/reqwest). Given a key
//! file and 1 or more scopes, it will attempt to get a token that you could be used to access resources in those scopes.
//!
//! `cargo run --example svc_account -- ~/.secrets/super-sekret.json https://www.googleapis.com/auth/pubsub https://www.googleapis.com/auth/devstorage.read_only`
//!
//! ## License
//!
//! Licensed under either of
//!
//! * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
//! * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
//!
//! at your option.
//!
//! ### Contribution
//!
//! Unless you explicitly state otherwise, any contribution intentionally
//! submitted for inclusion in the work by you, as defined in the Apache-2.0
//! license, shall be dual licensed as above, without any additional terms or
//! conditions.

#[cfg(feature = "gcp")]
pub mod gcp;

mod error;
mod token;

pub use crate::{error::Error, token::Token};
