//! I/O provider for linear storage using `libc`.

#![cfg(feature = "libc")]
#![cfg_attr(docs, doc(cfg(feature = "libc")))]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::expect_used,
    clippy::implicit_saturating_sub,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::ptr_as_ptr,
    clippy::string_slice,
    clippy::transmute_ptr_to_ptr,
    clippy::undocumented_unsafe_blocks,
    clippy::unimplemented,
    clippy::unwrap_used,
    clippy::wildcard_imports,
    missing_docs
)]

mod error;
mod imp;
mod path;
mod sys;
mod tests;

pub use error::Error;
pub use imp::*;
pub use path::*;
