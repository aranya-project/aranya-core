//! Base58 encoding.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod arith;
mod base58;

pub use crate::base58::*;
