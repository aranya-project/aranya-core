//! A wrapper around parts of libc for Aranya Core.
//!
//! # Operating System Support
//!
//! - Android
//! - Linux
//! - MacOS
//!
//! # Features
//!
//! - `std`: Enable [`std`] support.
//!
//! [`std`]: https://doc.rust-lang.org/std/

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]
#![warn(clippy::alloc_instead_of_core)]
#![warn(clippy::expect_used)]
#![warn(clippy::implicit_saturating_sub)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::string_slice)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::unimplemented)]
#![warn(missing_docs)]

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
