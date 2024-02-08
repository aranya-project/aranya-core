//! The `crypto` FFI module.

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(clippy::wildcard_imports, missing_docs)]

mod error;
mod ffi;
pub mod testing;
mod tests;

pub use error::*;
pub use ffi::*;
