//! A set of proc macros used for policy lang text and identifier literals.
//!
//! Do not use this crate directly. Use the macros from `aranya-policy-ast`
//! or a re-export from e.g. `aranya-policy-vm`.

use proc_macro::TokenStream;
use syn::Error;

mod imp;

#[proc_macro]
pub fn validate_text(item: TokenStream) -> TokenStream {
    imp::validate_text(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro]
pub fn validate_identifier(item: TokenStream) -> TokenStream {
    imp::validate_identifier(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
