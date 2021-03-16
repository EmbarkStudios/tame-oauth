// BEGIN - Embark standard lints v0.3
// do not change or add/remove here, but one can add exceptions after this section
// for more info see: <https://github.com/EmbarkStudios/rust-ecosystem/issues/59>
#![warn(
    clippy::all,
    clippy::await_holding_lock,
    clippy::dbg_macro,
    clippy::debug_assert_with_mut_call,
    clippy::doc_markdown,
    clippy::empty_enum,
    clippy::exit,
    clippy::explicit_into_iter_loop,
    clippy::filter_map_next,
    clippy::fn_params_excessive_bools,
    clippy::if_let_mutex,
    clippy::imprecise_flops,
    clippy::inefficient_to_string,
    clippy::large_types_passed_by_value,
    clippy::let_unit_value,
    clippy::linkedlist,
    clippy::lossy_float_literal,
    clippy::macro_use_imports,
    clippy::map_err_ignore,
    clippy::map_flatten,
    clippy::map_unwrap_or,
    clippy::match_on_vec_items,
    clippy::match_same_arms,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::mismatched_target_os,
    clippy::needless_borrow,
    clippy::needless_continue,
    clippy::option_option,
    clippy::pub_enum_variant_names,
    clippy::ref_option_ref,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::string_add_assign,
    clippy::string_add,
    clippy::string_to_string,
    clippy::suboptimal_flops,
    clippy::todo,
    clippy::enum_glob_use,
    clippy::unimplemented,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::verbose_file_reads,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms
)]
// END - Embark standard lints v0.3
// crate-specific exceptions:

//! # 🔐 tame-oauth
//!
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
//! ### [`svc_account`](examples/svc_account.rs)
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
//! * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
//! * MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)
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
