//! Base58 encoding.

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![deny(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod arith;
mod base58;

pub use crate::base58::*;
