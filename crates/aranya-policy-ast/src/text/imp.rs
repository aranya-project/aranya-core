use core::{
    fmt,
    marker::PhantomData,
    mem,
    num::{NonZeroU8, NonZeroUsize},
    ptr::{self, NonNull},
    slice, str,
};

use arc::ArcStr;

/// # Layout
///
/// `Repr` is a fat pointer. Logically, it looks like this:
///
/// ```ignore
/// #[repr(C)]
/// struct FatPtr {
///     ptr: NonNull<()>,
///     len: usize,
/// }
/// ```
///
/// Where `len` is the length of the data pointed to by `ptr`.
/// We use the `len` field to disambiguate the three different
/// variants.
///
/// If the top bit in `len` is zero, then `Repr` is `&'static
/// str`. This is because `&'static str` has a length of at most
/// [`isize::MAX`].
///
/// Otherwise TODO
#[repr(transparent)]
pub struct Repr {
    ptr: NonNull<[()]>,
    _marker: PhantomData<(&'static str, InlineStr, ArcStr)>,
}
const _: () = assert!(size_of::<Repr>() == size_of::<*const [()]>());
const _: () = assert!(size_of::<Repr>() == size_of::<ArcStr>());

impl Repr {
    pub const fn empty() -> Self {
        Self::from_static("")
    }

    pub const fn from_static(s: &'static str) -> Self {
        Self::new_static_str(s)
    }

    pub fn from_str(s: &str) -> Self {
        if s.is_empty() {
            Self::empty()
        } else if let Some(s) = InlineStr::try_from_str(s) {
            Self::new_inline_str(s)
        } else {
            Self::new_arc_str(ArcStr::new(s))
        }
    }

    const fn new_static_str(s: &'static str) -> Self {
        // SAFETY: `s` is a reference, so it is non-null.
        let ptr = unsafe { NonNull::new_unchecked(s as *const str as *mut _) };
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    const fn new_inline_str(s: InlineStr) -> Self {
        let (lhs, rhs) = s.into_parts();
        let data = ptr::without_provenance::<[(); 0]>(lhs.get()) as *const ();
        let len = rhs.get();
        // SAFETY:
        // - `data` is non-null because `addr` is `NonZeroUsize`.
        // - `data` is valid for reads of `len * size_of::<()>()`
        //    bytes because here `len * size_of::<()>()` is
        //    always zero.
        // - `data` is aligned to `align_of::<()>()` because it
        //    is non-zero and `align_of::<()>` is 1.
        // - `data` points to `len` consecutive `()` values.
        // - `slice` is never mutated.
        // - The total size of `len * size_of::<()>` is less than
        //   `isize::MAX` because `len * size_of::<()>` is zero.
        let slice = unsafe { slice::from_raw_parts(data, len) };
        // SAFETY: `slice` is a reference, so it is non-null.
        let ptr = unsafe { NonNull::new_unchecked(slice as *const [()] as *mut _) };
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    fn new_arc_str(s: ArcStr) -> Self {
        Self {
            ptr: s.as_ptr(),
            _marker: PhantomData,
        }
    }

    pub const fn as_str(&self) -> &str {
        const TAG_NOT_STATIC: usize = 1 << (usize::BITS - 1);

        // SAFETY: TODO
        let FatPtr { lo, hi } = unsafe { &*(self as *const Self as *const FatPtr) };
        if *hi & TAG_NOT_STATIC == 0 {
            // SAFETY: `self.ptr` is `NonNull`, so the pointer is
            // always non-null.
            let s = unsafe { *(self as *const Self as *const &'static str) };
            return s;
        }
        if (*lo & 3) == 0 {
            // SAFETY: `self` is a reference, so it is always
            // non-null.
            let s = unsafe { &*(self as *const Self as *const ArcStr) };
            return s.as_ref();
        }
        // SAFETY: `self` is a reference, so it is always
        // non-null.
        let s = unsafe { &*(self as *const Self as *const InlineStr) };
        return s.as_str();
    }
}

impl Clone for Repr {
    fn clone(&self) -> Self {
        todo!()
    }
}

impl Default for Repr {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
        self.as_str().hash(state)
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

/// The max number of bytes that can fit in the inline variant
/// without increasing `Repr`'s size.
const MAX_INLINE: usize = (2 * size_of::<usize>()) - 2;

#[derive(Copy, Clone, Debug)]
#[repr(C, align(1))]
struct InlineStr {
    len: NonZeroU8,
    data: [u8; MAX_INLINE],
    _pad: AlwaysTrue,
}
const _: () = assert!(size_of::<InlineStr>() == size_of::<FatPtr>());

impl InlineStr {
    fn try_from_str(s: &str) -> Option<Self> {
        let len = s.len();
        if len == 0 || len > MAX_INLINE {
            return None;
        }
        let mut data = [0u8; MAX_INLINE];
        data[..len].copy_from_slice(s.as_bytes());
        let s = Self {
            len: NonZeroU8::new(len as u8).unwrap(),
            data,
            _pad: AlwaysTrue::True,
        };
        #[cfg(test)]
        {
            let (a, b) = s.into_parts();
            println!("A = {a:064b}");
            println!("B = {b:064b}");
            let v: u128 = unsafe { mem::transmute(s) };
            println!("C = {v:0128b}");
        }
        Some(s)
    }

    const fn as_str(&self) -> &str {
        // SAFETY: TODO
        let slice = unsafe { slice::from_raw_parts(self.data.as_ptr(), self.len.get() as usize) };
        // SAFETY: TODO
        unsafe { str::from_utf8_unchecked(slice) }
    }

    const fn into_parts(self) -> (NonZeroUsize, NonZeroUsize) {
        // TODO(eric): use `zerocopy`.
        // SAFETY:
        // - `self` has the same size as `(usize, usize)`.
        // - `NonZeroUsize` has the same layout as `usize`
        // - `self.len` is `NonZeroU8`, so the `NonZeroUsize` is
        //   also never zero.
        unsafe { mem::transmute(self) }
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum AlwaysTrue {
    True = 1 << 7,
}

#[repr(C)]
struct FatPtr {
    lo: usize,
    hi: usize,
}

mod arc {
    //! Based on `std::sync::Arc`.

    use core::{
        alloc::Layout,
        ptr::{self, NonNull},
        sync::atomic::{self, AtomicUsize, Ordering},
    };

    const _: () = assert!(size_of::<NonNull<()>>() == size_of::<*const ()>());
    const _: () = assert!(size_of::<NonNull<ArcStrInner>>() == size_of::<*const ArcStrInner>());

    #[repr(transparent)]
    pub struct ArcStr {
        ptr: NonNull<ArcStrInner>,
    }
    const _: () = assert!(size_of::<ArcStr>() == size_of::<*const ArcStrInner>());

    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Send for ArcStr {}
    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Sync for ArcStr {}

    #[repr(C, align(4))]
    struct ArcStrInner {
        strong: AtomicUsize,
        data: str,
    }

    const MAX_REFCOUNT: usize = isize::MAX as usize;

    impl ArcStr {
        pub fn new(v: &str) -> Self {
            let ptr = ArcStrInner::allocate(v.len());

            // SAFETY: `ptr` is valid, we are initializing the fields now.
            unsafe {
                ptr::addr_of_mut!((*ptr.as_ptr()).strong).write(AtomicUsize::new(1));
                ptr::copy_nonoverlapping(
                    v.as_ptr(),
                    ptr::addr_of_mut!((*ptr.as_ptr()).data).cast::<u8>(),
                    v.len(),
                )
            }

            Self { ptr }
        }

        pub const fn as_ptr(&self) -> NonNull<[()]> {
            // SAFETY: TODO
            unsafe { NonNull::new_unchecked(self.ptr.as_ptr() as *mut [()]) }
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
            Layout::new::<AtomicUsize>()
                .extend(Layout::array::<u8>(len).expect("fits isize"))
                .expect("fits isize")
                .0
                .pad_to_align()
        }
    }

    impl Clone for ArcStr {
        fn clone(&self) -> Self {
            let old = self.inner().strong.fetch_add(1, Ordering::Relaxed);

            // This will only fail if someone does `loop { mem::forget(x.clone()) }`.
            // See `std::sync::Arc` for details.
            assert!(old <= MAX_REFCOUNT);

            ArcStr { ptr: self.ptr }
        }
    }

    impl Drop for ArcStr {
        fn drop(&mut self) {
            if self.inner().strong.fetch_sub(1, Ordering::Release) != 1 {
                return;
            }

            atomic::fence(Ordering::Acquire);

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
mod tests {
    use super::*;

    #[test]
    fn test_repr() {
        let want = "hello, world!!";

        let got = Repr::from_static(want);
        assert_eq!(got.as_str(), want);

        println!("XXX");

        let got = Repr::from_str(want);
        assert_eq!(got.as_str(), want);

        println!("XXX");

        let want = "hello, world!!!";
        let got = Repr::from_str(want);
        assert_eq!(got.as_str(), want);
    }
}
