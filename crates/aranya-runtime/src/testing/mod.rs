//! Runtime testing support.

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

pub mod dsl;
pub mod protocol;
pub mod vm;

use alloc::{
    format,
    string::{String, ToString as _},
};

use crate::CmdId;

/// Derives a [`CmdId`] from some data.
pub fn hash_for_testing_only(data: &[u8]) -> CmdId {
    use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash as _, rust::Sha256};
    Sha256::hash(data).into_array().into_array().into()
}

pub fn short_b58(id: CmdId) -> String {
    #![allow(clippy::arithmetic_side_effects)]
    let b58 = id.to_string();
    let trimmed = b58.trim_start_matches('1');
    let len = trimmed.len();
    if len == 0 {
        "1".into()
    } else if len > 8 {
        format!("..{}", &trimmed[len - 6..])
    } else {
        trimmed.into()
    }
}
