// modules in this crate

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]
#![deny(clippy::arithmetic_side_effects)]

mod ffi;

#[cfg(feature = "alloc")]
pub use ffi::*;
