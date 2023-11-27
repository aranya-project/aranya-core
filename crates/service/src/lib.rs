#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(clippy::arithmetic_side_effects)]

pub fn version() -> &'static str {
    "42"
}
