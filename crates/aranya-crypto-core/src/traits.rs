//! Commonly used traits.

#![allow(missing_docs)]

pub trait KeyInit {
    fn new(key: &[u8]) -> Self;
}
