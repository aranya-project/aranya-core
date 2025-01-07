#![forbid(unsafe_code)]

use core::cmp;

/// Copy from `src` to `dst`.
pub fn copy<T: Copy>(dst: &mut [T], src: &[T]) -> usize {
    let n = cmp::min(src.len(), dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

/// Like [`assert!`], but forces a compile-time error.
macro_rules! const_assert {
    ($($tt:tt)*) => {
        const _: () = assert!($($tt)*);
    }
}
pub(crate) use const_assert;
