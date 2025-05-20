use core::{
    alloc::{Layout, LayoutError},
    mem::{align_of, size_of},
    ops::Deref,
    ptr::NonNull,
};

use super::shared::assert_ffi_safe;

/// Reports whether `v` is aligned to `align`.
pub(super) fn is_aligned_to(v: usize, align: usize) -> bool {
    assert!(align.is_power_of_two());
    v % align == 0
}

/// Reports whether `ptr` is aligned to `align`.
fn is_aligned<T>(ptr: *const T) -> bool {
    (ptr as usize) % align_of::<T>() == 0
}

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
#[derive(Debug)]
pub(super) struct Aligned<T: Sized> {
    ptr: NonNull<T>,
}

impl<T: Sized> Clone for Aligned<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: Sized> Copy for Aligned<T> {}

impl<T: Sized> Aligned<T> {
    /// Creates an [`Aligned`] from a pointer with the
    /// provided memory layout.
    ///
    /// If `layout` isn't large enough to handle an aligned `T`,
    /// it returns `None`.
    pub fn new(ptr: *mut T, layout: Layout) -> Option<Self> {
        // Fast path: ptr is suitably aligned.
        if is_aligned(ptr) {
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
    // This cannot overflow. Quoting from the invariant of Layout:
    // > `size`, when rounded up to the nearest multiple of `align`,
    // > must not overflow isize (i.e., the rounded value must be
    // > less than or equal to `isize::MAX`)
    let padded_size = layout.size() + padding_needed_for(layout.size(), layout.align());
    let alloc_size = padded_size.checked_mul(n).ok_or(layout_error())?;

    Layout::from_size_align(alloc_size, layout.align())
}

/// Returns the padding needed to align `layout` up to `align`.
///
/// Taken from `std::alloc::Layout`.
const fn padding_needed_for(size: usize, align: usize) -> usize {
    let len = size;

    // Rounded up value is:
    //   len_rounded_up = (len + align - 1) & !(align - 1);
    // and then we return the padding difference: `len_rounded_up -
    // len`.
    //
    // We use modular arithmetic throughout:
    //
    // 1. align is guaranteed to be > 0, so align - 1 is always
    //    valid.
    //
    // 2. `len + align - 1` can overflow by at most `align - 1`, so
    //    the &-mask with `!(align - 1)` will ensure that in the case
    //    of overflow, `len_rounded_up` will itself be 0. Thus the
    //    returned padding, when added to `len`, yields 0, which
    //    trivially satisfies the alignment `align`.
    //
    // (Of course, attempts to allocate blocks of memory whose
    // size and padding overflow in the above manner should cause
    // the allocator to yield an error anyway.)

    let len_rounded_up = len.wrapping_add(align).wrapping_sub(1) & !align.wrapping_sub(1);
    len_rounded_up.wrapping_sub(len)
}
