//! String representation adapted from `compact_str`.

use core::{
    mem::{transmute, MaybeUninit},
    ptr,
};

use cfg_if::cfg_if;

/// Smart string representation.
///
/// Three variants:
/// - Inline (like [u8; N], 16 bytes on 64-bit and 12 bytes on 32-bit)
/// - Static (like &'static str)
/// - Shared (like Arc<str>)
///
/// We tag the last byte of repr.
/// - [0, 192) means a full inline string
///   - the last byte of valid utf8 must fall in this range
/// - [192, 208) gives the length of an inline string
/// - 208 is a shared arc str
/// - 209 is a static str
///
/// On 64-bit we can limit the length to 2^56 so we have a free byte to tag.
///
/// On 32-bit we throw in an extra word since 2^24 = 16MB is a bit small for a
/// max length. This also gives us 12 bytes inline instead of 8.
#[repr(C)]
pub struct Repr {
    ptr: MaybeUninit<*const u8>,
    len: MaybeUninit<Length>,
}

/// SAFETY: Repr is thread safe.
unsafe impl Send for Repr {}
/// SAFETY: Repr is thread safe.
unsafe impl Sync for Repr {}

// TODO(jdygert): I can't find a guarantee that pointers contain no padding.
// If they do, then copying an inline `Repr` might not copy those padding bytes.
const _: () = assert!(
    size_of::<*const u8>() + size_of::<Length>() == size_of::<Repr>(),
    "There must be no padding in `Repr`",
);

/// The max size of a string we can fit inline
const MAX_INLINE: usize = size_of::<Repr>();

const TAG_ARC: u8 = 208;
const TAG_STATIC: u8 = 209;

/// When our string is stored inline, we represent the length of the string in the last byte, offset
/// by `LENGTH_MASK`
const LENGTH_MASK: u8 = 0b11000000;

#[derive(Copy, Clone)]
#[repr(C)]
struct Length(usize, #[cfg(target_pointer_width = "32")] usize);

impl Length {
    const fn tag(len: usize, t: u8) -> Self {
        Self::assert_fits(len);
        cfg_if! {
            if #[cfg(target_pointer_width = "32")] {
                Self(len, usize::from_le_bytes([0, 0, 0, t]))
            } else if #[cfg(target_endian = "big")] {
                Self((len << 8) | t as usize)
            } else {
                Self(len | ((t as usize) << 56))
            }
        }
    }

    const fn untag(self) -> usize {
        cfg_if! {
            if #[cfg(target_pointer_width = "32")] {
                self.0
            } else if #[cfg(target_endian = "big")] {
                self.0 >> 8
            } else {
                (self.0 << 8) >> 8
            }
        }
    }

    const fn assert_fits(len: usize) {
        cfg_if! {
            if #[cfg(not(target_pointer_width = "32"))] {
                const SHIFT: usize = (size_of::<usize>() - 1) * 8;
                assert!(len >> SHIFT == 0);
            }
        }
    }
}

impl Repr {
    pub const fn empty() -> Self {
        Self::from_static("")
    }

    pub const fn from_static(s: &'static str) -> Self {
        Self {
            ptr: MaybeUninit::new(s.as_bytes().as_ptr()),
            len: MaybeUninit::new(Length::tag(s.len(), TAG_STATIC)),
        }
    }

    pub fn from_str(s: &str) -> Self {
        let len = s.len();
        if len <= MAX_INLINE {
            let mut bytes = [MaybeUninit::<u8>::uninit(); MAX_INLINE];
            // Note: this length will get overwritten if `len == MAX_INLINE`.
            bytes[MAX_INLINE - 1].write(len as u8 | LENGTH_MASK);
            // SAFETY: `s.len() <= bytes.len()` and valid pointers.
            unsafe {
                ptr::copy_nonoverlapping(s.as_ptr(), bytes.as_mut_ptr().cast::<u8>(), len);
            }
            // SAFETY: Same size and `Repr` is all `MaybeUninit`.
            unsafe { transmute::<[MaybeUninit<u8>; MAX_INLINE], Repr>(bytes) }
        } else {
            Self {
                ptr: MaybeUninit::new(arc::create(s)),
                len: MaybeUninit::new(Length::tag(s.len(), TAG_ARC)),
            }
        }
    }

    pub const fn as_str(&self) -> &str {
        // SAFETY: We always ensure valid utf8.
        unsafe { core::str::from_utf8_unchecked(self.as_bytes()) }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        // initially has the value of the stack pointer, conditionally becomes the heap pointer
        let mut pointer = ptr::from_ref(self).cast::<u8>();
        if self.last_byte() >= TAG_ARC {
            // SAFETY: ptr is initialized when tagged as arc or shared.
            pointer = unsafe { self.ptr.assume_init() };
        }

        // initially has the value of the stack length, conditionally becomes the heap length
        let mut length = self.last_byte().wrapping_sub(LENGTH_MASK) as usize;
        if length > MAX_INLINE {
            length = MAX_INLINE;
        }
        if self.last_byte() >= TAG_ARC {
            // SAFETY: len is initialized when tagged as arc or shared.
            length = unsafe { self.len.assume_init() }.untag();
        }

        // SAFETY: We know the data is valid, aligned, and part of the same contiguous allocated
        // chunk. It's also valid for the lifetime of self
        unsafe { core::slice::from_raw_parts(pointer, length) }
    }

    const fn last_byte(&self) -> u8 {
        // SAFETY: The last byte is always initialized.
        unsafe { ptr::from_ref(self).cast::<u8>().add(MAX_INLINE - 1).read() }
    }
}

impl Clone for Repr {
    fn clone(&self) -> Self {
        // increment counter if shared
        if self.last_byte() == TAG_ARC {
            // SAFETY: ptr is initialized and valid arc pointer when tagged as arc
            unsafe {
                arc::increment(self.ptr.assume_init());
            }
        }
        // SAFETY: inline/static are fine to bytewise copy.
        // arc is fine to bytewise copy once we have incremented.
        unsafe { ptr::read(self) }
    }
}

impl Drop for Repr {
    fn drop(&mut self) {
        if self.last_byte() == TAG_ARC {
            // SAFETY: ptr is initialized and valid arc pointer when tagged as arc
            unsafe {
                arc::decrement(self.ptr.assume_init(), self.len.assume_init());
            }
        }
    }
}

impl Default for Repr {
    fn default() -> Self {
        Self::empty()
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

mod arc {
    //! Based on `std::sync::Arc`.

    use core::{
        alloc::Layout,
        ptr::{self, NonNull},
        sync::atomic::{self, AtomicUsize},
    };

    use super::Length;

    const MAX_REFCOUNT: usize = isize::MAX as usize;

    pub(super) fn create(v: &str) -> *const u8 {
        let ptr = allocate(v.len());

        // SAFETY: `ptr` is valid, we are initializing the fields now.
        unsafe {
            let strong = ptr.cast::<AtomicUsize>();
            strong.write(AtomicUsize::new(1));

            let data = ptr.byte_add(size_of::<AtomicUsize>()).cast::<u8>();
            ptr::copy_nonoverlapping(v.as_ptr(), data, v.len());
            data
        }
    }

    fn allocate(len: usize) -> *mut () {
        let layout = make_layout(len);

        // SAFETY: layout is nonzero.
        let ptr = unsafe { alloc::alloc::alloc(layout) };
        let ptr = ptr::slice_from_raw_parts_mut(ptr, len);
        let Some(ptr) = NonNull::new(ptr) else {
            alloc::alloc::handle_alloc_error(layout);
        };

        ptr.as_ptr().cast()
    }

    fn make_layout(len: usize) -> Layout {
        Layout::new::<AtomicUsize>()
            .extend(Layout::array::<u8>(len).expect("fits isize"))
            .expect("fits isize")
            .0
            .pad_to_align()
    }

    unsafe fn strong_from_data(ptr: *const u8) -> *const AtomicUsize {
        // SAFETY: Given pointer must be valid.
        unsafe { ptr.sub(size_of::<AtomicUsize>()).cast::<AtomicUsize>() }
    }

    /// SAFETY: Must be a live pointer originating from `create`.
    pub(super) unsafe fn increment(ptr: *const u8) {
        // SAFETY: See function requirements.
        unsafe {
            let strong = strong_from_data(ptr);
            let old = (*strong).fetch_add(1, atomic::Ordering::Relaxed);
            // This will only fail if someone does `loop { mem::forget(x.clone()) }`.
            // See `std::sync::Arc` for details.
            assert!(old <= MAX_REFCOUNT);
        }
    }

    /// SAFETY: Must be a live pointer originating from `create`.
    /// The pointer must not be used afterward.
    /// The length must be the length which the arc was created with.
    pub(super) unsafe fn decrement(ptr: *const u8, len: Length) {
        // SAFETY: See function requirements.
        unsafe {
            let strong = strong_from_data(ptr);
            if (*strong).fetch_sub(1, atomic::Ordering::Release) != 1 {
                return;
            }

            atomic::fence(atomic::Ordering::Acquire);

            let layout = make_layout(len.untag());

            // SAFETY: We have ensured we are the only owner of this arc
            // and can now drop the allocation.
            alloc::alloc::dealloc(strong.cast_mut().cast(), layout);
        }
    }
}

#[cfg(test)]
mod test {
    use proptest::prelude::*;

    use super::*;

    fn check(s: &str) {
        let repr = Repr::from_str(s);
        assert_eq!(repr.as_str(), s);
        let repr2 = repr.clone();
        assert_eq!(repr, repr2);
        drop(repr);
        assert_eq!(repr2.as_str(), s);
        drop(repr2)
    }

    proptest! {
        #[test]
        fn proptest_repr(s: String) {
            check(&s);
        }
    }

    #[test]
    fn test_edge_cases() {
        check("");
        check(&str::repeat("\0", MAX_INLINE));
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
