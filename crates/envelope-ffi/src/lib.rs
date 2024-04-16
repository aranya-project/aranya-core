//! The `envelope` FFI module.

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod error;
mod ffi;
mod tests;

pub use ffi::*;
