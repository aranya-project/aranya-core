#![cfg_attr(not(any(test, feature = "std")), no_std)]

pub fn version() -> &'static str {
    "42"
}
