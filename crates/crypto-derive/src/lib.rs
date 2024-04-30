//! A proc macro so the `crypto` crate can generate algorithm
//! identifiers.

#![allow(unstable_name_collisions)]
#![cfg_attr(docs, feature(doc_cfg))]
#![warn(missing_docs)]

mod alg_id;

use proc_macro::TokenStream;
use syn::Error;

// See the `crypto` crate for documentation.
#[proc_macro_derive(AlgId, attributes(alg_id))]
#[allow(missing_docs)]
pub fn alg_id(item: TokenStream) -> TokenStream {
    alg_id::parse(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
