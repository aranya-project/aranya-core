// modules in this crate

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest)), no_std)]

mod ffi;

#[cfg(feature = "alloc")]
pub use ffi::*;
