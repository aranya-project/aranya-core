pub use core::str::Utf8Error;
use core::{mem::MaybeUninit, ptr, slice, str};

use crate::safe::{TypeId, Typed, Valid};

// TODO
// unsafe impl AllowedAsConstPtr for Utf8Str {}
// unsafe impl AllowedAsMutPtr for Utf8Str {}

/// UTF-8 text slice.
#[derive(Copy, Clone, Debug)]
pub struct Utf8Str {
    ptr: Valid<u8>,
    len: usize,
}

impl Utf8Str {
    /// Creates a `Utf8Str` from `&str`.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetimes.
    pub const unsafe fn new(s: &str) -> Self {
        Self {
            // SAFETY: `str::as_ptr` always returns a non-null,
            // suitably aligned pointer.
            ptr: unsafe { Valid::new_unchecked(s.as_ptr().cast_mut()) },
            len: s.len(),
        }
    }

    /// Initializes `out` with `data`.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetimes.
    pub unsafe fn init_str(out: &mut MaybeUninit<Self>, data: &str) {
        out.write(Self {
            // SAFETY: `data` is a ref, so its pointer is always
            // non-null and aligned.
            ptr: unsafe { Valid::new_unchecked(data.as_ptr().cast_mut()) },
            len: data.len(),
        });
    }

    /// Initializes `out` with `data`.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetimes.
    pub unsafe fn init_bytes(out: &mut MaybeUninit<Self>, data: &[u8]) -> Result<(), Utf8Error> {
        // SAFETY: See the method's safety docs.
        unsafe { Self::init_str(out, str::from_utf8(data)?) };
        Ok(())
    }

    /// Returns the underlying `&str`.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetimes.
    pub const unsafe fn as_str(&self) -> &str {
        // SAFETY: `ptr` and `len` can always be combined into
        // a `&[u8]` or `&str`.
        let data = unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
        // SAFETY: `ptr` always points to valid UTF-8.
        unsafe { str::from_utf8_unchecked(data) }
    }

    /// Returns a pointer to the string's data.
    pub const fn data(&self) -> *const u8 {
        if self.len == 0 {
            // Don't expose a dangling pointer to C.
            ptr::null()
        } else {
            self.ptr.as_ptr()
        }
    }

    /// Returns the length of the string.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Reports whether the string is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// impl Eq for Utf8Str {}
// impl PartialEq for Utf8Str {
//     fn eq(&self, other: &Self) -> bool {
//         PartialEq::eq(self.as_str(), other.as_str())
//     }
// }
// impl<T: AsRef<str>> PartialEq<T> for Utf8Str {
//     fn eq(&self, other: &T) -> bool {
//         PartialEq::eq(self.as_str(), other.as_ref())
//     }
// }

// impl Ord for Utf8Str {
//     fn cmp(&self, other: &Self) -> Ordering {
//         Ord::cmp(self.as_str(), other.as_str())
//     }
// }
// impl PartialOrd for Utf8Str {
//     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
//         Some(self.cmp(other))
//     }
// }
// impl<T: AsRef<str>> PartialOrd<T> for Utf8Str {
//     fn partial_cmp(&self, other: &T) -> Option<Ordering> {
//         PartialOrd::partial_cmp(self.as_str(), other.as_ref())
//     }
// }

impl Default for Utf8Str {
    fn default() -> Self {
        // SAFETY: The lifetime is `'static`.
        unsafe { Self::new("") }
    }
}

impl Typed for Utf8Str {
    const TYPE_ID: TypeId = TypeId::new(0x0FCF564A);
}
