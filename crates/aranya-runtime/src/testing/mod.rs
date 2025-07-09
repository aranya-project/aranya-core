//! Runtime testing support.

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

pub mod dsl;
pub mod protocol;
pub mod vm;

use core::fmt;

use crate::CommandId;

/// Derives a [`CommandId`] from some data.
pub fn hash_cmd_for_testing_only(data: &[u8]) -> CommandId {
    use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash, rust::Sha256};
    Sha256::hash(data).into_array().into_array().into()
}

pub struct ShortB58(pub CommandId);
impl fmt::Display for ShortB58 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #![allow(clippy::arithmetic_side_effects)]
        use spideroak_base58::ToBase58;
        let b58 = self.0.to_base58();
        let trimmed = b58.trim_start_matches('1');
        let len = trimmed.len();
        if len == 0 {
            write!(f, "1")
        } else if len > 8 {
            write!(f, "..{}", &trimmed[len - 6..])
        } else {
            write!(f, "{}", trimmed)
        }
    }
}
