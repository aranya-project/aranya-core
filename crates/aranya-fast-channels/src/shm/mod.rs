//! A shared memory implementation of `State`.
//!
//! It uses POSIX shared memory.

#![cfg(feature = "posix")]

mod align;
mod error;
mod le;
mod path;
mod posix;
mod read;
mod shared;
mod tests;
mod write;

pub use error::*;
pub use path::*;
pub use read::*;
pub use write::*;
