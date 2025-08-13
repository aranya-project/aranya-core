use core::slice;

// TODO(jdygert): Better repr to fit in 16 bytes.
#[derive(Clone)]
pub enum Repr {
    Static(&'static str),
    Inline { bytes: [u8; MAX_INLINE], len: u8 },
    Heap(arc::ArcStr),
}

/// The max number of bytes that can fit in the inline variant without increasing `Repr`'s size.
const MAX_INLINE: usize = 3 * size_of::<usize>() - 2;

impl Repr {
    pub const fn empty() -> Self {
        Self::Static("")
    }

    pub const fn from_static(s: &'static str) -> Self {
        Self::Static(s)
    }

    pub fn from_str(s: &str) -> Self {
        let len = s.len();
        if len <= MAX_INLINE {
            let mut bytes = [0u8; MAX_INLINE];
            bytes[..len].copy_from_slice(s.as_bytes());
            Self::Inline {
                bytes,
                len: len as u8,
            }
        } else {
            Self::Heap(arc::ArcStr::new(s))
        }
    }

    pub const fn as_str(&self) -> &str {
        match self {
            Repr::Static(s) => s,
            Repr::Inline { bytes, len } => {
                debug_assert!((*len as usize) <= MAX_INLINE);
                // SAFETY: We always ensure that `&bytes[..len]` is a valid string.
                let s = unsafe { slice::from_raw_parts(bytes.as_ptr(), *len as usize) };
                // SAFETY: We always ensure that `&bytes[..len]` is a valid string.
                unsafe { core::str::from_utf8_unchecked(s) }
            }
            Repr::Heap(s) => s.as_ref(),
        }
    }
}

impl Default for Repr {
    fn default() -> Self {
        Self::Static("")
    }
}

impl core::fmt::Debug for Repr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_str().fmt(f)
    }
}

impl PartialEq for Repr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str().eq(other.as_str())
    }
}

impl Eq for Repr {}

impl PartialOrd for Repr {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Repr {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl core::hash::Hash for Repr {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl<'de> serde::Deserialize<'de> for Repr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // No arc pooling for serde :(
        // We use `Cow` so we can often avoid allocating when the string
        // is directly present in the source bytes.
        let s = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Ok(Self::from_str(&s))
    }
}

impl serde::Serialize for Repr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

mod arc {
    //! Based on `std::sync::Arc`.

    use core::{
        alloc::Layout,
        ptr::{self, NonNull},
        sync::atomic,
    };

    pub struct ArcStr {
        ptr: NonNull<ArcStrInner>,
    }

    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Send for ArcStr {}
    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Sync for ArcStr {}

    #[repr(C)]
    struct ArcStrInner {
        strong: atomic::AtomicUsize,
        data: str,
    }

    const MAX_REFCOUNT: usize = isize::MAX as usize;

    impl ArcStr {
        pub fn new(v: &str) -> Self {
            let ptr = ArcStrInner::allocate(v.len());

            // SAFETY: `ptr` is valid, we are initializing the fields now.
            unsafe {
                ptr::addr_of_mut!((*ptr.as_ptr()).strong).write(atomic::AtomicUsize::new(1));
                ptr::copy_nonoverlapping(
                    v.as_ptr(),
                    ptr::addr_of_mut!((*ptr.as_ptr()).data).cast::<u8>(),
                    v.len(),
                );
            }

            Self { ptr }
        }

        pub const fn as_ref(&self) -> &str {
            &self.inner().data
        }

        #[inline]
        const fn inner(&self) -> &ArcStrInner {
            // SAFETY: While this arc is alive we're guaranteed that the inner pointer is valid.
            unsafe { self.ptr.as_ref() }
        }
    }

    impl ArcStrInner {
        /// Allocate an uninitialized `ArcStrInner`.
        fn allocate(len: usize) -> NonNull<ArcStrInner> {
            let layout = Self::layout(len);

            // SAFETY: layout is nonzero.
            let ptr = unsafe { alloc::alloc::alloc(layout) };
            let ptr = ptr::slice_from_raw_parts_mut(ptr, len) as *mut ArcStrInner;
            let Some(ptr) = NonNull::new(ptr) else {
                alloc::alloc::handle_alloc_error(layout);
            };

            ptr
        }

        fn layout(len: usize) -> Layout {
            Layout::new::<atomic::AtomicUsize>()
                .extend(Layout::array::<u8>(len).expect("fits isize"))
                .expect("fits isize")
                .0
                .pad_to_align()
        }
    }

    impl Clone for ArcStr {
        fn clone(&self) -> Self {
            let old = self.inner().strong.fetch_add(1, atomic::Ordering::Relaxed);

            // This will only fail if someone does `loop { mem::forget(x.clone()) }`.
            // See `std::sync::Arc` for details.
            assert!(old <= MAX_REFCOUNT);

            ArcStr { ptr: self.ptr }
        }
    }

    impl Drop for ArcStr {
        fn drop(&mut self) {
            if self.inner().strong.fetch_sub(1, atomic::Ordering::Release) != 1 {
                return;
            }

            atomic::fence(atomic::Ordering::Acquire);

            let layout = Layout::for_value(self.inner());

            // SAFETY: We have ensured we are the only owner of this arc
            // and can now drop the value and allocation.
            unsafe {
                ptr::drop_in_place(self.ptr.as_ptr());
                alloc::alloc::dealloc(self.ptr.as_ptr().cast(), layout);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn proptest_repr(s in ".{1,25}") {
            let repr = Repr::from_str(&s);
            assert_eq!(repr.as_str(), s.as_str());
        }
    }

    #[test]
    fn test_empty() {
        let empty1 = Repr::empty();
        let empty2 = Repr::from_str("");
        assert_eq!(empty1.as_str(), "");
        assert_eq!(empty2.as_str(), "");
        assert_eq!(empty1, empty2);
    }
}
