//! A set of proc macros for requirements tracking.
//!
//! Do not use this crate directly. Use the `rtrack` crate
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

mod spira;

/// See the `rtrack` crate for documentation.
#[proc_macro_attribute]
#[cfg(feature = "spira")]
pub fn spira(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    match option_env!("SPIRA_ENABLED") {
        Some(_) => crate::spira::parse(attr.into(), item.into()).into(),
        None => item,
    }
}
