//! A set of proc macros for policy lang compiler stuff.
//!
//! Do not use this crate directly. Use the `policy-vm` crate
//! instead.

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod attr;
mod ffi;

use proc_macro::TokenStream;
use syn::Error;

// See the `policy-vm` crate for documentation.
#[proc_macro_attribute]
#[allow(missing_docs)]
pub fn ffi(attr: TokenStream, item: TokenStream) -> TokenStream {
    ffi::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
