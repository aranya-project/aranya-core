//! Provides a convenient macro for constructing [`Hir`] in
//! tests.

#![cfg(test)]

use slotmap::KeyData;

/// Creates an ID from an index and version using slotmap's KeyData.
///
/// # Panics
/// - If idx is 0
/// - If version is 0
pub(crate) fn make_id<T: From<KeyData>>(idx: u32, version: u32) -> T {
    assert!(idx > 0, "idx must be greater than 0");
    assert!(version > 0, "version must be greater than 0");
    let v = (idx as u64) | ((version as u64) << 32);
    KeyData::from_ffi(v).into()
}
