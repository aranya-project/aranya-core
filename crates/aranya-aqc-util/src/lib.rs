//! AQC support for Aranya.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod ffi;
mod handler;
mod shared;
pub mod testing;
mod tests;

pub use aranya_crypto::policy::LabelId;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use ffi::*;
pub use handler::*;
