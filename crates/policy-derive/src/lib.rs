//! A set of proc macros for policy lang compiler stuff.
//!
//! Do not use this crate directly. Use the `policy-vm` crate
//! instead.

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
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

mod attr;
mod ffi;

use proc_macro::TokenStream;
use syn::Error;

// See the `policy-vm` crate for documentation.
#[proc_macro_attribute]
#[allow(missing_docs)]
pub fn ffi(attr: TokenStream, item: TokenStream) -> TokenStream {
    crate::ffi::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
