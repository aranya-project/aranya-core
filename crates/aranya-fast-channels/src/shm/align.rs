use core::{
    alloc::Layout,
    mem::{align_of, size_of},
    ops::Deref,
    ptr::NonNull,
};

use derive_where::derive_where;

use super::shared::assert_ffi_safe;

/// A cache-aligned `T`.
// Copied from https://github.com/crossbeam-rs/crossbeam/blob/099d0469efcfacb32527bd9451a4fb62586ae537/crossbeam-utils/src/cache_padded.rs
// Follow that link for sources on each size.
#[cfg_attr(
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec",
        target_arch = "powerpc64",
    ),
    repr(align(128))
)]
#[cfg_attr(
    any(
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "hexagon",
    ),
    repr(align(32))
)]
#[cfg_attr(target_arch = "m68k", repr(align(16)))]
#[cfg_attr(target_arch = "s390x", repr(align(256)))]
#[cfg_attr(
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec",
        target_arch = "powerpc64",
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "hexagon",
        target_arch = "m68k",
        target_arch = "s390x",
    )),
    repr(align(64))
)]
#[repr(C)]
#[derive(Debug)]
pub(super) struct CacheAligned<T>(T);
assert_ffi_safe!(CacheAligned<()>);

impl<T> CacheAligned<T> {
    pub fn new(v: T) -> Self {
        Self(v)
    }
}

impl<T> Deref for CacheAligned<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// A non-null pointer aligned to `T`.
#[repr(transparent)]
#[derive_where(Copy, Clone, Debug)]
pub(super) struct Aligned<T: Sized> {
    ptr: NonNull<T>,
}

impl<T: Sized> Aligned<T> {
    /// Creates an [`Aligned`] from a pointer with the
    /// provided memory layout.
    ///
    /// If `layout` isn't large enough to handle an aligned `T`,
    /// it returns `None`.
    pub fn new(ptr: *mut T, layout: Layout) -> Option<Self> {
        // Fast path: ptr is suitably aligned.
        if ptr.is_aligned() {
            return Some(Self {
                ptr: NonNull::new(ptr)?,
            });
        }

        let off = ptr.align_offset(align_of::<T>());

        // Is the layout large enough for `T`?
        match layout.size().checked_sub(off) {
            None => return None,
            Some(x) if x < size_of::<T>() => return None,
            _ => (),
        }

        // SAFETY: `ptr` is non-null and can be aligned.
        let ptr = unsafe { ptr.add(ptr.align_offset(align_of::<T>())) };
        Some(Self {
            ptr: NonNull::new(ptr)?,
        })
    }
}

impl<T> Aligned<T> {
    /// Returns a shared reference to the pointer.
    ///
    /// # Safety
    ///
    /// - The data must be initialized.
    /// - You must respect Rust's aliasing rules.
    pub unsafe fn as_ref<'a>(&self) -> &'a T {
        // SAFETY: Caller mut ensure safety.
        unsafe { self.ptr.as_ref() }
    }

    /// Acquires the underlying `*mut` pointer.
    pub fn as_ptr(&self) -> *mut T {
        self.ptr.as_ptr()
    }
}
