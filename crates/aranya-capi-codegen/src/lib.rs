//! Generate C APIs from Rust code.
//!
//! # Overview
//!
//! `capi-codegen` generates much of the Rust boilerplate needed
//! when exposing Rust to C.
//!
//! # Usage
//!
//! This crate is designed to be used from a [build script].
//!
//! [build script]: https://doc.rust-lang.org/cargo/reference/build-scripts.html

mod ast;
pub mod attr;
mod ctx;
mod error;
mod gen;
pub mod syntax;
mod util;

pub use error::BuildError;
pub use gen::{dump, format, Config};
pub use util::{IdentExt, KeyValPair};