//! The Aranya Policy Virtual Machine

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(feature = "error_in_core", feature(error_in_core))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

mod codemap;
mod compile;
mod data;
mod error;
mod ffi;
mod instructions;
mod io;
mod machine;
mod stack;
mod tests;

pub use codemap::*;
pub use compile::*;
pub use data::*;
pub use error::*;
pub use ffi::*;
pub use instructions::*;
pub use io::*;
pub use machine::*;
pub use stack::*;
