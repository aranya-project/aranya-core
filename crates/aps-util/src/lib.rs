//! APS support for Aranya.

#![cfg_attr(docs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]

mod ffi;
mod handler;
mod shared;
pub mod testing;
mod tests;
mod transform;

#[cfg(feature = "alloc")]
#[cfg_attr(docs, doc(cfg(feature = "alloc")))]
pub use ffi::*;
pub use handler::*;
pub use transform::Transform;
