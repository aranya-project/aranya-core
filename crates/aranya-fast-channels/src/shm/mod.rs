//! A shared memory implementation of `State`.
//!
//! It uses either POSIX shared memory or VxWorks' sdLib.

#![cfg(any(feature = "sdlib", feature = "posix"))]

mod align;
mod error;
mod le;
mod path;
mod posix;
mod read;
mod sdlib;
mod shared;
mod tests;
mod write;

pub use error::*;
pub use path::*;
pub use read::*;
pub use write::*;
