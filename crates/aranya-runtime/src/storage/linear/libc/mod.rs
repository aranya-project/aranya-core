//! I/O provider for linear storage using `libc`.

#![cfg(feature = "libc")]
#![cfg_attr(docsrs, doc(cfg(feature = "libc")))]
#![warn(clippy::alloc_instead_of_core)]
#![warn(clippy::expect_used)]
#![warn(clippy::implicit_saturating_sub)]
#![warn(clippy::indexing_slicing)]
#![warn(clippy::missing_panics_doc)]
#![warn(clippy::string_slice)]
#![warn(clippy::undocumented_unsafe_blocks)]
#![warn(clippy::unimplemented)]
#![warn(missing_docs)]

// TODO(mmap): decide how we want to expose the two backends.

mod error;
pub mod mmap;
mod path;
pub mod rw;

pub use error::Error;
pub use path::IdPath;
pub use rw::{FileManager, Handle, Reader, Writer};
