//! Proc macros used on policy structs, effects, and actions.

#![warn(clippy::arithmetic_side_effects)]
#![warn(clippy::wildcard_imports)]
// TODO(jdygert): #![warn(missing_docs)]

use proc_macro::TokenStream;
use syn::Error;

mod action;
mod actions;
mod common;
mod effect;
mod effects;
mod value;

#[proc_macro_attribute]
pub fn value(attr: TokenStream, item: TokenStream) -> TokenStream {
    value::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn effect(attr: TokenStream, item: TokenStream) -> TokenStream {
    effect::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn effects(attr: TokenStream, item: TokenStream) -> TokenStream {
    effects::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn action(attr: TokenStream, item: TokenStream) -> TokenStream {
    action::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

#[proc_macro_attribute]
pub fn actions(attr: TokenStream, item: TokenStream) -> TokenStream {
    actions::parse(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
