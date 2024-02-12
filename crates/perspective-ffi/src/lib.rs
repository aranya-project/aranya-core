//! The `perspective` FFI module.

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![deny(clippy::wildcard_imports, missing_docs)]

mod ffi;
mod tests;

pub use ffi::*;
