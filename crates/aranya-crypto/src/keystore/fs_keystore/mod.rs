//! A file system backed [`KeyStore`][crate::KeyStore].

#![cfg(feature = "fs-keystore")]

mod error;
mod store;
mod tests;

pub use error::*;
pub use store::*;
