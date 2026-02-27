use core::{
    alloc::{Layout, LayoutError},
    mem::{align_of, size_of},
    ops::Deref,
    ptr::NonNull,
};

use derive_where::derive_where;

use super::shared::assert_ffi_safe;

/// A cache-aligned `T`.
#[cfg_attr(
    any(target_arch = "aarch64", target_arch = "powerpc64"),
    repr(C, align(128))
)]
#[cfg_attr(any(target_arch = "x86_64"), repr(C, align(64)))]
#[cfg_attr(
    any(
        target_arch = "arm",
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "riscv64",
        target_arch = "powerpc",
    ),
    repr(C, align(32))
)]
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

const fn layout_error() -> LayoutError {
    match Layout::from_size_align(usize::MAX, 1) {
        Err(err) => err,
        _ => core::unreachable!(),
    }
}

// See https://doc.rust-lang.org/core/alloc/struct.Layout.html#method.repeat
pub(super) fn layout_repeat(layout: Layout, n: usize) -> Result<Layout, LayoutError> {
    let padded_size = layout.pad_to_align().size();
    let alloc_size = padded_size.checked_mul(n).ok_or(layout_error())?;

    Layout::from_size_align(alloc_size, layout.align())
}
