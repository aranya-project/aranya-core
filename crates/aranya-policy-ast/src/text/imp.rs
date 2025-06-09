use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    hint,
    marker::PhantomData,
    mem::{self, ManuallyDrop},
    num::{NonZeroU8, NonZeroUsize},
    ops::Deref,
    ptr::{self, NonNull},
    slice, str,
};

use arc::ArcStr;

/// The pointer metadata bits used to disambiguate the different
/// `Repr` variants
const TAG_BITS: usize = 0xc0 << (usize::BITS - 8);
/// `Repr` is `&'static str`.
const TAG_STATIC: usize = 0x00;
/// `Repr` is [`InlineStr`]
const TAG_INLINE: usize = TAG_BITS;
/// `Repr` is [`ArcStr`]
const TAG_ARC: usize = 0x80 << (usize::BITS - 8);

/// A fat pointer representation of a string.
///
/// # Layout
///
/// `Repr` is a fat pointer. Logically, it looks like this:
///
/// ```ignore
/// #[repr(C)]
/// struct FatPtr<T> {
///     ptr: NonNull<T>,
///     len: usize,
/// }
/// ```
///
/// Where `len` is the length of the data pointed to by `ptr`.
/// We use the `len` field to disambiguate the three different
/// variants.
///
/// `&'static str` has a maximum length of `isize::MAX`, which
/// means the top bit of `len` is always zero. We use this bit to
/// differentiate between `&'static str` and the other two
/// variants.
///
/// The last two bits of `len` are used to differentiate between
/// `InlineStr` and `ArcStr`. If the top two bits of `len` are
/// both one, then the `Repr` is an `InlineStr`. Otherwise, it is
/// `ArcStr`.
#[repr(transparent)]
pub struct Repr {
    ptr: NonNull<[()]>,
    _marker: PhantomData<(&'static str, InlineStr, ArcStr)>,
}
const _: () = assert!(size_of::<Repr>() == size_of::<*const [()]>());
const _: () = assert!(size_of::<Repr>() == size_of::<&'static str>());
const _: () = assert!(size_of::<Repr>() == size_of::<ArcStr>());
const _: () = assert!(size_of::<Repr>() == size_of::<InlineStr>());
const _: () = assert!(size_of::<Option<Repr>>() == size_of::<Option<&'static str>>());

impl Repr {
    /// Returns an empty string.
    pub const fn empty() -> Self {
        Self::from_static("")
    }

    /// Creates a `Repr` from a static string.
    pub const fn from_static(s: &'static str) -> Self {
        Self::from_static_str(s)
    }

    /// Creates a `Repr` from a runtime string.
    pub fn from_str(s: &str) -> Self {
        if s.is_empty() {
            Self::empty()
        } else if s == "\0" {
            // The first byte of `InlineStr` must be non-zero.
            Self::from_static("\0")
        } else if let Some(s) = InlineStr::try_from_str(s) {
            Self::from_inline_str(s)
        } else {
            Self::from_arc_str(ArcStr::new(s))
        }
    }

    const fn from_static_str(s: &'static str) -> Self {
        let ptr = s as *const str as *const [()];
        Self {
            // SAFETY: `ptr` came from `s` (a ref), so it is
            // non-null.
            ptr: unsafe { NonNull::new_unchecked(ptr.cast_mut()) },
            _marker: PhantomData,
        }
    }

    fn from_inline_str(s: InlineStr) -> Self {
        let ptr = {
            let (lhs, rhs) = s.into_parts();
            let data = ptr::without_provenance::<[(); 0]>(lhs.get()) as *const ();
            let len = rhs.get();
            ptr::slice_from_raw_parts(data, len)
        };
        Self {
            // SAFETY: `data` comes from `NonZeroUsize`, so `ptr`
            // is non-null.
            ptr: unsafe { NonNull::new_unchecked(ptr.cast_mut()) },
            _marker: PhantomData,
        }
    }

    fn from_arc_str(s: ArcStr) -> Self {
        Self {
            // SAFETY: `ArcStr` is `NonNull`, so
            // `ArcStr::into_raw` always returns a non-null
            // pointer.
            ptr: unsafe { NonNull::new_unchecked(s.into_raw().cast_mut()) },
            _marker: PhantomData,
        }
    }

    /// Returns the string as a `&str`.
    pub const fn as_str(&self) -> &str {
        self.as_data().as_str()
    }

    const fn as_data(&self) -> Data<'_> {
        match self.ptr_metadata() & TAG_BITS {
            TAG_STATIC => {
                // SAFETY: `self` is a reference, so the pointer
                // is always non-null.
                let s = unsafe { *(self as *const Self as *const &'static str) };
                Data::Static(s)
            }
            TAG_INLINE => {
                // SAFETY: `self` is a reference, so the pointer
                // is always non-null.
                let s = unsafe { &*(self as *const Self as *const InlineStr) };
                Data::Inline(s)
            }
            TAG_ARC => {
                // SAFETY: `self` is a reference, so the pointer
                // is always non-null.
                let s = unsafe { &*(self as *const Self as *const ArcStr) };
                Data::Arc(s)
            }
            // SAFETY: We masked the top two bits and covered all
            // the combinations that *we* set.
            _ => unsafe { hint::unreachable_unchecked() },
        }
    }

    const fn to_arc(&mut self) -> Option<ManuallyDrop<ArcStr>> {
        if self.ptr_metadata() & TAG_BITS != TAG_ARC {
            return None;
        }
        // SAFETY: `self.ptr` came from `ArcStr::into_raw`.
        let s = unsafe { ArcStr::from_raw(self.ptr.as_ptr() as *const [()]) };
        Some(ManuallyDrop::new(s))
    }

    const fn ptr_metadata(&self) -> usize {
        ptr_metadata(self.ptr.as_ptr())
    }
}

impl Clone for Repr {
    fn clone(&self) -> Self {
        match self.as_data() {
            Data::Static(_) | Data::Inline(_) => Self {
                ptr: self.ptr,
                _marker: PhantomData,
            },
            Data::Arc(s) => Self::from_arc_str(s.clone()),
        }
    }
}

impl Default for Repr {
    fn default() -> Self {
        Self::empty()
    }
}

impl Drop for Repr {
    fn drop(&mut self) {
        if let Some(mut s) = self.to_arc() {
            // SAFETY: `s` (and `self`) is no longer used after
            // this method returns.
            unsafe { ManuallyDrop::drop(&mut s) }
        }
    }
}

impl fmt::Debug for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Deref for Repr {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<T> AsRef<T> for Repr
where
    T: ?Sized,
    <Repr as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl Eq for Repr {}
impl PartialEq for Repr {
    fn eq(&self, other: &Self) -> bool {
        self.as_str().eq(other.as_str())
    }
}

impl Ord for Repr {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl PartialOrd for Repr {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for Repr {
    fn hash<H: Hasher>(&self, state: &mut H) {
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

/// The 'safe' representation of [`Repr`].
#[derive(Clone, Debug)]
enum Data<'a> {
    Static(&'static str),
    Inline(&'a InlineStr),
    Arc(&'a ArcStr),
}

impl<'a> Data<'a> {
    const fn as_str(&self) -> &'a str {
        match self {
            Data::Static(s) => s,
            Data::Inline(s) => s.as_str(),
            Data::Arc(s) => s.as_str(),
        }
    }
}

/// Turns a thin pointer plus its metadata into a fat pointer.
const fn fatten(ptr: *const (), len: usize) -> *const [()] {
    ptr::slice_from_raw_parts(ptr as *const (), len)
}

/// Updates the metadata of a fat pointer.
const fn update_ptr_metadata(ptr: *const [()], new_len: usize) -> *const [()] {
    fatten(ptr as *const (), new_len)
}

/// Returns the metadata of a fat pointer.
const fn ptr_metadata(ptr: *const [()]) -> usize {
    ptr.len()
}

/// The max number of bytes that can fit in [`InlineStr`].
const MAX_INLINE: usize = (2 * size_of::<usize>()) - 1;

// We have to update `InlineStr` if `usize` is ever larger than
// 64 bits.
const _: () = assert!(MAX_INLINE <= 15);

/// The length of the tail of the inline string.
const TAIL_LEN: usize = MAX_INLINE - 1;

/// A string stored inline inside of `Repr`.
///
/// It must be [1, N) bytes long, where N is the size of two
/// pointers, and the first byte cannot be zero.
#[repr(C, align(1))]
#[derive(Copy, Clone, Debug)]
struct InlineStr {
    /// `head` must be non-zero so that our "pointer" is always
    /// non-null.
    head: NonZeroU8,
    tail: [u8; TAIL_LEN],
    len: InlineStrLen,
}
const _: () = assert!(size_of::<InlineStr>() == size_of::<[usize; 2]>());

impl InlineStr {
    /// Attempts to create an `InlineStr` from a string.
    fn try_from_str(s: &str) -> Option<Self> {
        let s = s.as_bytes();
        let Some(len) = InlineStrLen::try_from_usize(s.len()) else {
            // Too long or too short.
            return None;
        };
        let Some((&first, rest)) = s.split_first() else {
            // This case is already covered by `try_from_usize`,
            // but it doesn't hurt to avoid string indexing.
            return None;
        };
        if rest.len() > TAIL_LEN {
            return None;
        }
        let Some(head) = NonZeroU8::new(first) else {
            // The first byte must be non-zero.
            return None;
        };
        let mut tail = [0u8; TAIL_LEN];
        tail[..rest.len()].copy_from_slice(rest);
        Some(Self { head, tail, len })
    }

    /// Returns the string data.
    const fn as_str(&self) -> &str {
        let data = self as *const Self as *const [u8; MAX_INLINE] as *const u8;
        let len = self.len.to_usize();
        // SAFETY:
        // - `data` comes from `&self`, so it is non-null.
        // - `data` is a pointer to `u8`, so it is always
        //   aligned.
        // - `data` does point to `len` consecutive initialized
        //   `u8`s.
        // - The memory is not mutated.
        // - The total length is less than `isize::MAX` because
        //   `self.len` can only represent values less than
        //   `isize::MAX`.
        let slice = unsafe { slice::from_raw_parts(data, len) };
        // SAFETY: `InlineStr` can only be created from `&str`,
        // so the data is always valid UTF-8.
        unsafe { str::from_utf8_unchecked(slice) }
    }

    /// Converts the `InlineStr` into its two consituent words.
    const fn into_parts(self) -> (NonZeroUsize, NonZeroUsize) {
        // TODO(eric): use `zerocopy`.
        // SAFETY:
        // - `self` has the same size as `(usize, usize)`.
        // - `NonZeroUsize` has the same layout as `usize`.
        // - `self.head` and `self.len` are both guaranteed to be
        //   non-zero.
        unsafe { mem::transmute(self) }
    }
}

/// Basically a `NonZeroU8`, but with [`TAG_INLINE`] applied.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum InlineStrLen {
    _1 = inline_str_len(1),
    _2 = inline_str_len(2),
    _3 = inline_str_len(3),
    _4 = inline_str_len(4),
    _5 = inline_str_len(5),
    _6 = inline_str_len(6),
    _7 = inline_str_len(7),

    #[cfg(target_pointer_width = "64")]
    _8 = inline_str_len(8),
    #[cfg(target_pointer_width = "64")]
    _9 = inline_str_len(9),
    #[cfg(target_pointer_width = "64")]
    _10 = inline_str_len(10),
    #[cfg(target_pointer_width = "64")]
    _11 = inline_str_len(11),
    #[cfg(target_pointer_width = "64")]
    _12 = inline_str_len(12),
    #[cfg(target_pointer_width = "64")]
    _13 = inline_str_len(13),
    #[cfg(target_pointer_width = "64")]
    _14 = inline_str_len(14),
    #[cfg(target_pointer_width = "64")]
    _15 = inline_str_len(15),
}

impl InlineStrLen {
    const fn try_from_usize(n: usize) -> Option<Self> {
        match n {
            1..=MAX_INLINE => {
                // SAFETY: `n` is in the range 1..=MAX_INLINE, so
                // it can be transmuted to `InlineStrLen`.
                let len = unsafe { mem::transmute::<u8, Self>(inline_str_len(n as u8)) };
                Some(len)
            }
            _ => None,
        }
    }

    const fn to_u8(self) -> u8 {
        (self as u8) & 0x3f
    }

    const fn to_usize(self) -> usize {
        self.to_u8() as usize
    }
}

const fn inline_str_len(n: u8) -> u8 {
    n | 0xc0
}

mod arc {
    //! Based on `std::sync::Arc`.

    use alloc::alloc;
    use core::{
        alloc::Layout,
        mem::ManuallyDrop,
        ptr::{self, NonNull},
        sync::atomic::{self, AtomicUsize, Ordering},
    };

    const _: () = assert!(size_of::<NonNull<()>>() == size_of::<*const ()>());
    const _: () = assert!(size_of::<NonNull<ArcStrInner>>() == size_of::<*const ArcStrInner>());

    #[derive(Debug)]
    #[repr(transparent)]
    pub struct ArcStr {
        ptr: NonNull<ArcStrInner>,
    }
    const _: () = assert!(size_of::<ArcStr>() == size_of::<*const ArcStrInner>());

    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Send for ArcStr {}
    // SAFETY: `ArcStr` is thread safe.
    unsafe impl Sync for ArcStr {}

    impl ArcStr {
        pub fn new(v: &str) -> Self {
            assert!(v.len() & super::TAG_ARC == 0);

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

            // Update the metadata with the tag.
            let len = super::ptr_metadata(ptr.as_ptr() as *const [()]);
            let ptr = super::update_ptr_metadata(ptr.as_ptr() as *const [()], len | super::TAG_ARC)
                as *const ArcStrInner;

            Self {
                // SAFETY: `ptr` came from `NonNull`.
                ptr: unsafe { NonNull::new_unchecked(ptr.cast_mut()) },
            }
        }

        /// Converts the `ArcStr` into a raw pointer.
        pub fn into_raw(self) -> *const [()] {
            let s = ManuallyDrop::new(self);
            s.ptr.as_ptr() as *const [()]
        }

        /// # Safety
        ///
        /// - `ptr` must be the same pointer returned by
        ///   [`into_raw`][Self::into_raw].
        pub const unsafe fn from_raw(ptr: *const [()]) -> Self {
            // SAFETY: See the function's safety docs.
            let ptr = unsafe { NonNull::new_unchecked((ptr as *const ArcStrInner).cast_mut()) };
            Self { ptr }
        }

        /// Returns the string data.
        pub const fn as_str(&self) -> &str {
            &self.inner().data
        }

        const fn inner(&self) -> &ArcStrInner {
            // SAFETY:
            // - `as_ptr` always returns a non-null pointer.
            // - While this arc is alive we're guaranteed that
            //   the inner pointer is valid.
            unsafe { &*self.as_ptr() }
        }

        /// Returns the inner pointer with the tag removed.
        const fn as_ptr(&self) -> *const ArcStrInner {
            let len = super::ptr_metadata(self.ptr.as_ptr() as *const [()]);
            super::update_ptr_metadata(self.ptr.as_ptr() as *const [()], len & !super::TAG_ARC)
                as *const ArcStrInner
        }

        /// Returns the inner pointer with the tag removed.
        const fn as_mut_ptr(&mut self) -> *mut ArcStrInner {
            let len = super::ptr_metadata(self.ptr.as_ptr() as *mut [()]);
            super::update_ptr_metadata(self.ptr.as_ptr() as *mut [()], len & !super::TAG_ARC)
                as *mut ArcStrInner
        }
    }

    impl Clone for ArcStr {
        fn clone(&self) -> Self {
            const MAX_REFCOUNT: usize = isize::MAX as usize;

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
                ptr::drop_in_place(self.as_mut_ptr());
                alloc::dealloc(self.as_mut_ptr().cast(), layout);
            }
        }
    }

    #[repr(C)]
    struct ArcStrInner {
        strong: AtomicUsize,
        data: str,
    }

    impl ArcStrInner {
        /// Allocate an uninitialized `ArcStrInner`.
        fn allocate(len: usize) -> NonNull<ArcStrInner> {
            let layout = Self::layout(len);

            // SAFETY: layout is nonzero.
            let ptr = unsafe { alloc::alloc(layout) };
            let ptr = ptr::slice_from_raw_parts_mut(ptr, len) as *mut ArcStrInner;
            let Some(ptr) = NonNull::new(ptr) else {
                alloc::handle_alloc_error(layout);
            };

            ptr
        }

        fn layout(len: usize) -> Layout {
            #[repr(C)]
            struct Header {
                strong: AtomicUsize,
            }
            Layout::new::<Header>()
                .extend(Layout::array::<u8>(len).expect("fits isize"))
                .expect("fits isize")
                .0
                .pad_to_align()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_repr_static() {
        let want = "hello, world!!";
        let got = Repr::from_static(want);
        assert_eq!(got.as_str(), want);
    }

    #[test]
    fn test_repr_inline() {
        let want = "hello, world!!";
        let got = Repr::from_str(want);
        assert_eq!(got.as_str(), want);
    }

    #[test]
    fn test_repr_arc() {
        let want = "hello, world!!!!!";
        let got = Repr::from_str(want);
        assert_eq!(got.as_str(), want);
    }
}
