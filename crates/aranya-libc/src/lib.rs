//! A wrapper around parts of libc for Aranya Core.
//!
//! # Operating System Support
//!
//! - Linux
//! - MacOS
//! - VxWorks 6.9
//!
//! # Features
//!
//! - `std`: Enable [`std`] support.
//!
//! [`std`]: https://doc.rust-lang.org/std/

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(missing_docs)]
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

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

mod api;
mod errno;
mod path;
mod sys;

pub use api::*;
pub use errno::Errno;
pub use path::*;
