// modules in this crate

#![cfg_attr(docs, feature(doc_cfg))]

mod ffi;

#[cfg(feature = "alloc")]
pub use ffi::*;
