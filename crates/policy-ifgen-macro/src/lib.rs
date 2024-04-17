//! Proc macros used on policy structs, effects, and actions.

#![warn(
    clippy::arithmetic_side_effects,
    clippy::wildcard_imports,
    // TODO(jdygert): missing_docs
)]

use proc_macro::TokenStream;
use syn::Error;

mod actions;
mod common;
mod effect;
mod effects;
mod value;

#[proc_macro_attribute]
pub fn value(attr: TokenStream, item: TokenStream) -> TokenStream {
    crate::value::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn effect(attr: TokenStream, item: TokenStream) -> TokenStream {
    crate::effect::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn effects(attr: TokenStream, item: TokenStream) -> TokenStream {
    crate::effects::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn actions(attr: TokenStream, item: TokenStream) -> TokenStream {
    crate::actions::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
