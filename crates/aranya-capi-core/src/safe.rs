//! Types that make FFI a little bit safer.

use core::{
    cmp::Ordering,
    ffi::c_char,
    fmt,
    hash::{Hash, Hasher},
    marker::{PhantomData, PhantomPinned},
    mem::{self, size_of, ManuallyDrop, MaybeUninit},
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Deref, DerefMut, Not},
    ptr::{self, NonNull},
    slice, str,
};

use aranya_libc::Path;
use tracing::{error, instrument, warn};

use crate::{
    internal::conv::{
        alias::Alias,
        newtype::NewType,
        slice::{try_from_raw_parts, try_from_raw_parts_mut},
    },
    traits::InitDefault,
    InvalidSlice,
};

/// Errors returned by [`Safe`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    /// The address of a [`Safe`] changed.
    #[error("address changed")]
    AddrChanged,
    /// A [`Safe`] is already initialized.
    #[error("already initialized")]
    AlreadyInitialized,
    /// The pointer is invalid.
    #[error(transparent)]
    InvalidPtr(#[from] InvalidPtr),
    /// The slice is invalid.
    #[error(transparent)]
    InvalidSlice(#[from] InvalidSlice),
    /// The type identifier is invalid for `T`.
    #[error("invalid type")]
    InvalidType,
    /// The type is uninitialized.
    #[error("uninitialized")]
    Uninitialized,
}

/// A wrapper around `T` that attemps to limit the scope of
/// certain types of undefined behavior.
///
/// # Undefined Behavior Mitigations
///
/// It is important to note that `Safe` does not (and cannot)
/// _prevent_ undefined behavior. The following mitigations only
/// help limit the scope of the UB. For example, it is still
/// undefined behavior to use an uninitialized `Safe`. However,
/// the "Uninitialized Memory" mitigation limits the UB to
/// reading `Safe`'s uninitialized flags instead of reading from
/// (or writing to) the uninitialized inner `T`.
///
/// ## Type Confusion
///
/// `Safe` contains a unique type identifier for each type `T`
/// (see [`Typed`]). An error is returned if the type identifier
/// does not match the expected type identifier for `T`.
///
/// ## Uninitialized Memory
///
/// Type identifiers are random, so it's unlikely that
/// uninitialized memory will have the same bit pattern.
///
/// `Safe` also has an `INIT` flag that is set to true after the
/// inner `T` is initialized. An error is returned if the flag is
/// false.
///
/// ## Use After Cleanup (Free)
///
/// [`Safe`]'s `Drop` impl zeros out the type identifier and
/// flags, ensuring that it cannot be used after the inner `T`
/// has been dropped.
#[repr(C)]
#[non_exhaustive]
pub struct Safe<T: Typed> {
    // Should be `T::TYPE_ID`.
    id: TypeId,
    flags: Flags,
    addr: usize,
    inner: MaybeUninit<T>,
    _unpin: PhantomPinned,
}

impl<T: Typed> Safe<T> {
    /// Writes an initialized `Safe` to `out`.
    pub fn init(out: &mut MaybeUninit<Self>, v: T) {
        let addr = out as *mut MaybeUninit<Self> as usize;
        out.write(Self {
            id: T::TYPE_ID,
            flags: Flags::INIT,
            addr,
            inner: MaybeUninit::new(v),
            _unpin: PhantomPinned,
        });
    }

    /// Is the type ID correct?
    fn is_valid(&self) -> bool {
        self.id == T::TYPE_ID
    }

    /// Is the type initialized?
    fn is_init(&self) -> bool {
        self.flags & Flags::INIT != 0
    }

    /// Did the address change?
    fn addr_changed(&self) -> bool {
        self.addr != self as *const Self as usize
    }

    #[cfg(not(debug_assertions))]
    fn name(&self) -> tracing::field::Empty {
        tracing::field::Empty
    }

    #[cfg(debug_assertions)]
    fn name(&self) -> &'static str {
        core::any::type_name::<Self>()
    }

    /// Checks that `self` is valid, has been initialized, and
    /// has not been moved.
    ///
    /// This should only be called when receiving a pointer from
    /// external code, like C.
    fn check(&self) -> Result<(), Error> {
        if !self.is_valid() {
            error!(
                got = %self.id,
                want = %T::TYPE_ID,
                name = self.name(),
                "invalid type ID",
            );
            Err(Error::InvalidType)
        } else if !self.is_init() {
            error!(flags = %self.flags, name = self.name(), "not initialized");
            Err(Error::Uninitialized)
        } else if self.addr_changed() {
            error!(
                old = %Hex(self.addr),
                new = %Hex(self as *const Self as usize),
                id = %self.id,
                name = self.name(),
                "address changed"
            );
            Err(Error::AddrChanged)
        } else {
            Ok(())
        }
    }

    /// Like [`check`][Self::check], but does not check for
    /// a changed address.
    fn sanity_check(&self) {
        #[allow(clippy::panic, reason = "panicking only under debug_assertions")]
        if cfg!(debug_assertions) {
            if !self.is_valid() {
                error!(
                    got = %self.id,
                    want = %T::TYPE_ID,
                    name = self.name(),
                    "invalid type ID",
                );
                panic!("invalid type ID")
            } else if !self.is_init() {
                error!(flags = %self.flags, name = self.name(), "not initialized");
                panic!("not initialized")
            } else if self.addr_changed() {
                warn!(
                    old = %Hex(self.addr),
                    new = %Hex(self as *const Self as usize),
                    id = %self.id,
                    name = self.name(),
                    "address changed"
                );
            }
        }
        // NB: We skip the address change because it's okay for
        // Rust to move this type around, but not external code.
    }

    /// Returns a shared reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - The pointer must be initialized.
    /// - You must uphold Rust's aliasing rules.
    #[instrument]
    pub unsafe fn try_from_ptr<'a>(ptr: *const Self) -> Result<&'a Self, Error> {
        let v = Valid::<Self>::new(ptr.cast_mut()).map_err(Error::from)?;
        // SAFETY: See the function's safety docs.
        unsafe { v.as_ref() }.check()?;
        // SAFETY: See the function's safety docs.
        Ok(unsafe { v.as_ref() })
    }

    /// Returns an exclusive reference from `ptr`.
    ///
    /// # Safety
    ///
    /// - The pointer must be initialized.
    /// - You must uphold Rust's aliasing rules.
    #[instrument]
    pub unsafe fn try_from_mut_ptr<'a>(ptr: *mut Self) -> Result<&'a mut Self, Error> {
        let mut v = Valid::<Self>::new(ptr).map_err(Error::from)?;
        // SAFETY: See the function's safety docs.
        unsafe { v.as_ref() }.check()?;
        // SAFETY: See the function's safety docs.
        Ok(unsafe { v.as_mut() })
    }

    /// Returns a possibly uninitialized exclusive reference from
    /// `ptr`.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's aliasing rules.
    #[instrument]
    pub unsafe fn try_from_uninit_mut_ptr<'a>(
        ptr: *mut MaybeUninit<Self>,
    ) -> Result<&'a mut MaybeUninit<Self>, Error> {
        let mut v = Valid::<MaybeUninit<Self>>::new(ptr).map_err(Error::from)?;
        // SAFETY: See the function's safety docs.
        Ok(unsafe { v.as_mut() })
    }

    /// Returns an [`OwnedPtr`] from `ptr`.
    ///
    /// # Safety
    ///
    /// - The pointer must be initialized.
    /// - You must uphold Rust's aliasing rules.
    #[instrument]
    pub unsafe fn try_from_owned_ptr(ptr: *mut Self) -> Result<OwnedPtr<Self>, Error> {
        // TODO(eric): `ptr.cast()` or make `ptr: *mut
        // ManuallyDrop<Self>`?
        let v = Valid::<ManuallyDrop<Self>>::new(ptr.cast()).map_err(Error::from)?;
        // SAFETY: See the function's safety docs.
        unsafe { v.as_ref() }.check()?;
        // SAFETY: All `Valid`s are non-null and suitably
        // aligned. See the function's safety docs for the rest.
        Ok(unsafe { OwnedPtr::from_valid(v) })
    }

    /// Consumes the `Safe`, returning its inner data.
    pub fn into_inner(mut self) -> T {
        self.sanity_check();

        let inner = mem::replace(&mut self.inner, MaybeUninit::uninit());

        self.flags &= !Flags::INIT;
        debug_assert_eq!(self.flags, Flags::NONE);

        // SAFETY: The header is correct, so we have to assume
        // that `inner` is indeed initialized.
        unsafe { inner.assume_init() }
    }

    fn as_ref(&self) -> &T {
        self.sanity_check();

        // SAFETY: The header is correct, so we have to assume
        // that `inner` is indeed initialized.
        unsafe { self.inner.assume_init_ref() }
    }

    fn as_mut(&mut self) -> &mut T {
        self.sanity_check();

        // SAFETY: The header is correct, so we have to assume
        // that `inner` is indeed initialized.
        unsafe { self.inner.assume_init_mut() }
    }
}

impl<T: Typed + Default> InitDefault for Safe<T> {
    fn init_default(out: &mut MaybeUninit<Self>) {
        Self::init(out, T::default())
    }
}

impl<T: Typed> Drop for Safe<T> {
    fn drop(&mut self) {
        tracing::debug!(addr = self as *mut Safe<T> as usize, "dropping");
        debug_assert_eq!(self.id, T::TYPE_ID);

        if !self.is_valid() {
            // We shouldn't ever hit this code path. But `Drop`
            // isn't fallible, so there isn't anything we can
            // really do here.
            return;
        }
        if !self.is_init() {
            // This might happen if we call `Safe::into_inner`.
            return;
        }

        self.id = TypeId::UNSET;

        // SAFETY: Although we have checked the header, we still
        // have to trust that `inner` is valid to be dropped.
        unsafe { self.inner.assume_init_drop() }

        self.flags &= !Flags::INIT;

        debug_assert_eq!(self.id, TypeId::UNSET);
        debug_assert_eq!(self.flags, Flags::NONE);
    }
}

impl<T: Typed + Eq> Eq for Safe<T> {}
impl<T: Typed + PartialEq> PartialEq for Safe<T> {
    fn eq(&self, other: &Self) -> bool {
        // Ignore `addr` since it could be different for two
        // different objects.
        self.id == other.id && self.flags == other.flags && self.as_ref() == other.as_ref()
    }
}

impl<T: Typed> Deref for Safe<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T: Typed> DerefMut for Safe<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T: Typed + fmt::Debug> fmt::Debug for Safe<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Safe<T>")
            .field("id", &self.id)
            .field("flags", &self.flags)
            .field("addr", &self.addr)
            .field("inner", self.as_ref())
            .finish()
    }
}

impl<T: Typed> Typed for Safe<T> {
    const TYPE_ID: TypeId = T::TYPE_ID;
}

/// Implemented by types that can be used with [`Safe`].
pub trait Typed {
    /// Uniquely identifies the type.
    const TYPE_ID: TypeId;
}

/// Uniquely identifies types.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct TypeId(u32);

impl TypeId {
    /// The default value of `TypeId`.
    pub const UNSET: Self = Self(0);

    /// Creates a new type ID.
    ///
    /// It must not be [`UNSET`][Self::UNSET].
    pub const fn new(id: u32) -> Self {
        Self(id)
    }
}

impl fmt::Display for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Flags used by [`Safe`].
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
#[repr(transparent)]
struct Flags(u32);

impl Flags {
    /// No flags are set.
    pub const NONE: Self = Self(0);
    /// Enabled only after [`Safe`]'s inner `T` has been
    /// initialized.
    pub const INIT: Self = Self(1 << 0);
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Binary::fmt(&self.0, f)
    }
}

impl PartialEq<u32> for Flags {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl BitAnd for Flags {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}
impl BitAndAssign for Flags {
    fn bitand_assign(&mut self, other: Self) {
        *self = *self & other;
    }
}

impl BitOr for Flags {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl BitOrAssign for Flags {
    fn bitor_assign(&mut self, other: Self) {
        *self = *self | other;
    }
}

impl Not for Flags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Essentially the same thing as [`Valid`], but indicates
/// ownership of the pointed-to data.
///
/// NB: `OwnedPtr` does not implement `Drop`. You must either
/// call [`read`][Self::read] or
/// [`drop_in_place`][Self::drop_in_place].
#[repr(transparent)]
pub struct OwnedPtr<T> {
    ptr: Valid<ManuallyDrop<T>>,
    _marker: PhantomData<T>,
}

// Check that we take advantage of `NonNull`'s niche
// optimizations.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    const WANT: usize = size_of::<OwnedPtr<()>>();
    const GOT: usize = size_of::<Option<OwnedPtr<()>>>();
    assert!(GOT == WANT);
};

impl<T> OwnedPtr<T> {
    /// Creates a new `Owned`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must uphold Rust's lifetime rules. Specifically,
    ///   `OwnedPtr` now owns `ptr`.
    pub unsafe fn new(ptr: *mut ManuallyDrop<T>) -> Result<Self, InvalidPtr> {
        // SAFETY: See this method's safety docs.
        Ok(unsafe { Self::from_valid(Valid::new(ptr)?) })
    }

    /// Creates a new `Owned`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be initialized.
    /// - You must uphold Rust's lifetime rules. Specifically,
    ///   `OwnedPtr` now owns `ptr`.
    pub const unsafe fn from_valid(ptr: Valid<ManuallyDrop<T>>) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Consumes the owned pointer and returns the inner data.
    ///
    /// # Safety
    ///
    /// - The pointer must be live.
    #[must_use]
    pub unsafe fn read(self) -> T {
        // SAFETY: `Valid` is always non-null and suitably
        // aligned.
        let xref = unsafe { &mut *(self.ptr.as_mut_ptr()) };
        // SAFETY: `read` consumes `self`, so the `ManuallyDrop`
        // cannot be used again.
        unsafe { ManuallyDrop::take(xref) }
    }

    /// Executes the destructor, if any, for `T`.
    ///
    /// # Safety
    ///
    /// - The pointer must be live.
    pub unsafe fn drop_in_place(self) {
        // SAFETY: `Valid` is always non-null and suitably
        // aligned.
        let xref = unsafe { &mut *(self.ptr.as_mut_ptr()) };
        // SAFETY: `drop_in_place` consumes `self`, so the
        // `ManuallyDrop` cannot be used again.
        unsafe { ManuallyDrop::drop(xref) }
    }

    /// Returns the address of the owned pointer.
    ///
    /// This is used by `capi-macro`.
    #[doc(hidden)]
    pub fn addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }
}

impl<T> fmt::Debug for OwnedPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.ptr, f)
    }
}

impl<T> fmt::Pointer for OwnedPtr<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.ptr, f)
    }
}

// SAFETY: `T` is `NewType`.
unsafe impl<T: NewType> NewType for OwnedPtr<T> {
    type Inner = OwnedPtr<T::Inner>;
}

// SAFETY: `T: Alias<U>`, so the alias is sound.
unsafe impl<T, U> Alias<U> for OwnedPtr<T>
where
    T: Alias<U>,
    U: Sized,
{
}

/// Like `&[u8]`, but with a pointer from C.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CBytes {
    ptr: Valid<u8>,
    len: usize,
}

impl CBytes {
    /// Creates a `CBytes`.
    ///
    /// - If `ptr` is non-null, `len` must be non-zero.
    /// - If `ptr` is null, `len` must be zero.
    ///
    /// # Safety
    ///
    /// - If non-null, `ptr` must be valid for reads up to `len`
    ///   bytes.
    pub unsafe fn new(ptr: *const u8, len: usize) -> Result<Self, Error> {
        // SAFETY: See the method's safety docs. We uphold the
        // other aliasing and lifetime requirements.
        let s = unsafe { try_from_raw_parts(ptr, len)? };
        Ok(Self::from_slice(s))
    }

    /// Creates `CBytes` from a slice.
    pub const fn from_slice(s: &[u8]) -> Self {
        Self {
            // SAFETY: The pointer is coming from a ref, so it is
            // valid and aligned.
            ptr: unsafe { Valid::new_unchecked(s.as_ptr().cast_mut()) },
            len: s.len(),
        }
    }

    /// Returns the `CBytes` as a slice.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetimes.
    pub unsafe fn as_bytes(&self) -> &[u8] {
        // SAFETY:
        //
        // - `self.ptr` is always non-null and suitably aligned.
        // - `self.len` is always valid for `self.ptr`.
        // - See the method's safety docs.
        unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

/// A non-null, suitably aligned C string.
///
/// It has the same size and alignment as [`*const
/// c_char`][c_char].
///
/// Unlike [`core::ffi::CStr`], it is FFI safe.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct CStr {
    ptr: Valid<c_char>,
}

impl CStr {
    /// Unsafely creates a `CStr` from `&[u8]`.
    ///
    /// # Safety
    ///
    /// - The null terminator must be within [`isize::MAX`] bytes
    ///   from `ptr`.
    pub const unsafe fn new_unchecked(bytes: &[u8]) -> Self {
        Self {
            // SAFETY: See the method's docs.
            ptr: unsafe { Valid::new_unchecked(bytes.as_ptr().cast::<c_char>().cast_mut()) },
        }
    }

    /// Returns a `CStr` from `ptr`.
    ///
    /// # Safety
    ///
    /// - The pointer must be initialized.
    /// - You must uphold Rust's aliasing rules.
    /// - The null terminator must be within [`isize::MAX`] bytes
    ///   from `ptr`.
    pub unsafe fn try_from_ptr(ptr: *const c_char) -> Result<Self, Error> {
        let ptr = Valid::new(ptr.cast_mut()).map_err(Error::from)?;
        Ok(Self { ptr })
    }

    /// Converts the `CStr` into a [`Path`].
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's aliasing rules.
    pub unsafe fn into_path<'a>(self) -> &'a Path {
        // SAFETY: The pointer is valid because of `Valid`, but
        // we have to assume everything else.
        unsafe { Path::from_ptr(self.ptr.as_ptr()) }
    }

    /// Converts the `CStr` into a raw `*const c_char`.
    pub const fn as_ptr(self) -> *const c_char {
        self.ptr.as_ptr()
    }
}

/// A thin wrapper around `(*mut T, *mut usize)`.
///
/// `*mut usize` contains the number of elements in the buffer
/// `*mut T`. After calling [`copy_to`][Writer::copy_to], `*mut
/// usize` is updated with the number of elements written to the
/// buffer `*mut T`. If the buffer is too small to fit all the
/// elements, `*mut usize` is updated with the required number of
/// elements and [`copy_to`][Writer::copy_to] returns
/// [`OutOfSpace`].
///
/// # Example
///
/// ```rust
/// use core::ptr;
///
/// use aranya_capi_core::safe::Writer;
///
/// /// Writes `hello, world!` to `ptr`, which has a length of
/// /// `*len`.
/// ///
/// /// Reports whether there was enough space to write the
/// /// entire message to `ptr` and updates `len` with `"hello,
/// /// world!".len()`.
/// unsafe extern "C" fn write_hello_world(ptr: *mut u8, len: *mut usize) -> bool {
///     let mut w = unsafe {
///         // NB: A real function would return an error instead
///         // of unwrapping.
///         Writer::try_from_raw_parts(ptr, len).unwrap()
///     };
///     w.copy_to(|buf| {
///         // NB: You can write as many times as necessary.
///         buf.write_all(b"hello,");
///         buf.write_all(b" world");
///         buf.write_all(b"!");
///         Ok::<(), ()>(())
///     }).is_ok()
/// }
///
/// // Retrieve the number of elements we want to write.
/// let mut len = 0;
/// let mut buf = vec![0u8; len];
///
/// let wrote_all = {
///     // (ptr, len) must be either
///     // - (non-null, >0)
///     // - (null, 0)
///     let ptr = if len == 0 {
///         ptr::null_mut()
///     } else {
///         buf.as_mut_ptr()
///     };
///     unsafe { write_hello_world(ptr, &mut len) }
/// };
/// if !wrote_all {
///     buf.resize(len, 0);
///     unsafe {
///         write_hello_world(buf.as_mut_ptr(), &mut len);
///     }
/// }
/// assert_eq!(len, b"hello, world!".len());
/// assert_eq!(&buf[..len], b"hello, world!");
/// ```
// TODO(eric): Give this a more descriptive name?
pub struct Writer<T> {
    ptr: Valid<T>,    // slice pointer
    len: usize,       // slice length
    nw: Valid<usize>, // total bytes attempted to write
}

impl<T> Writer<T> {
    /// Creates a `Writer`.
    ///
    /// # Safety
    ///
    /// - The memory pointed to by `len` must be initialized.
    /// - If non-null, `ptr` must be valid for reads up to `*len`
    ///   bytes.
    /// - You must uphold Rust's lifetimes.
    /// - You must uphold Rust's aliasing guarantees.
    pub unsafe fn try_from_raw_parts(ptr: *mut T, len: *mut usize) -> Result<Self, Error> {
        let len = Valid::new(len)?;

        // Check that (ptr, len) is valid. We don't save the
        // resulting slice to simplify the API (no lifetimes,
        // etc.).
        let slice = {
            // SAFETY: See the method's safety docs.
            let len = unsafe { len.read() };
            // SAFETY: See the method's safety docs.
            unsafe { try_from_raw_parts_mut(ptr, len)? }
        };

        // We haven't written anything yet.
        unsafe {
            len.write(0);
        }

        Ok(Self {
            // SAFETY: `slice` is a ref, so its pointer is always
            // non-null and suitably aligned.
            ptr: unsafe { Valid::new_unchecked(slice.as_mut_ptr()) },
            len: slice.len(),
            nw: len,
        })
    }
}

impl<T: Copy> Writer<T> {
    /// Invokes `f` until it returns `Ok(0)` or `Err(E)`.
    ///
    /// # Safety
    ///
    /// - The writer's pointer must be live.
    pub unsafe fn copy_to<F, R>(self, f: F) -> Result<R, OutOfSpace>
    where
        F: FnOnce(&mut Buffer<'_, T>) -> R,
    {
        // SAFETY: The constructor checks these safety
        // requirements.
        let dst = unsafe { slice::from_raw_parts_mut(self.ptr.as_mut_ptr(), self.len) };
        let mut buf = Buffer { dst, nw: 0 };
        let res = f(&mut buf);
        // Update `nw` even if we don't have enough space in
        // order to report to the caller the total amount of
        // space needed.
        unsafe {
            self.nw.write(buf.nw);
        }
        if buf.nw > dst.len() {
            Err(OutOfSpace(()))
        } else {
            Ok(res)
        }
    }
}

/// A buffer.
// TODO(eric): implement std::io::Write?
pub struct Buffer<'a, T> {
    dst: &'a mut [T],
    nw: usize,
}

impl<T: Copy> Buffer<'_, T> {
    /// Writes the entirety of `data` to `self`.
    pub fn write_all(&mut self, data: &[T]) {
        let start = self.nw;
        // Update `nw` even if we don't have enough space in
        // order to report to the caller the total amount of
        // space needed.
        self.nw = start.saturating_add(data.len());
        if let Some(dst) = self.dst.get_mut(start..self.nw) {
            dst.copy_from_slice(data);
        }
    }
}

#[cfg(feature = "ciborium")]
impl ciborium_io::Write for &mut Buffer<'_, u8> {
    type Error = ();

    fn write_all(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        Buffer::write_all(self, data);
        Ok(())
    }
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Not enough space to write data to [`Writer`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("buffer out of space")]
pub struct OutOfSpace(());

/// A non-null, suitably aligned pointer.
#[repr(transparent)]
pub struct Valid<T: ?Sized> {
    ptr: NonNull<T>,
}

// Check that we take advantage of `NonNull`'s niche
// optimizations.
#[allow(clippy::assertions_on_constants)]
const _: () = {
    const WANT: usize = size_of::<Valid<()>>();
    const GOT: usize = size_of::<Option<Valid<()>>>();
    assert!(GOT == WANT);
};

impl<T> Valid<T> {
    /// Creates a new `Valid`.
    ///
    /// It returns [`Err(InvalidPtr)`][InvalidPtr] if `ptr` is
    /// null or misaligned.
    #[inline(always)]
    pub fn new(ptr: *mut T) -> Result<Self, InvalidPtr> {
        let Some(ptr) = NonNull::new(ptr) else {
            return Err(InvalidPtr::Null);
        };
        if !ptr.is_aligned() {
            Err(InvalidPtr::Unaligned)
        } else {
            Ok(Self { ptr })
        }
    }
}

impl<T: ?Sized> Valid<T> {
    /// Creates a new `Valid`.
    pub const fn from_ref(v: &T) -> Self {
        Self {
            // SAFETY: `v` is a reference, so it is always
            // non-null and suitably aligned.
            ptr: unsafe { NonNull::new_unchecked((v as *const T).cast_mut()) },
        }
    }

    /// Creates a new `Valid`.
    pub fn from_mut(v: &mut T) -> Self {
        Self {
            // SAFETY: `v` is a reference, so it is always
            // non-null and suitably aligned.
            ptr: unsafe { NonNull::new_unchecked(v as *mut T) },
        }
    }

    /// Creates a new `Valid`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null.
    /// - `ptr` must be suitably aligned.
    pub const unsafe fn new_unchecked(ptr: *mut T) -> Self {
        Self {
            // SAFETY: See the associated function's safety docs.
            ptr: unsafe { NonNull::new_unchecked(ptr) },
        }
    }

    /// Acquires the underlying pointer.
    pub const fn as_ptr(self) -> *const T {
        self.ptr.as_ptr()
    }

    /// Acquires the underlying pointer.
    pub const fn as_mut_ptr(self) -> *mut T {
        self.ptr.as_ptr()
    }

    /// Reads the underlying pointer.
    ///
    /// # Safety
    ///
    /// - The pointed-to memory must be initialized.
    pub const unsafe fn read(self) -> T
    where
        T: Sized,
    {
        // SAFETY: `Valid` only contains non-null and suitably
        // aligned pointers. The caller has to uphold the
        // remaining safety conditions.
        unsafe { self.ptr.read() }
    }

    /// Writes to the underlying pointer.
    ///
    /// # Safety
    ///
    /// - The pointer must be live.
    pub unsafe fn write(self, val: T)
    where
        T: Sized,
    {
        // SAFETY: `Valid` only contains non-null and suitably
        // aligned pointers.
        unsafe { self.ptr.write(val) }
    }

    /// Returns a shared reference to the `Valid`.
    ///
    /// # Safety
    ///
    /// - The pointed-to memory must be initialized.
    /// - You must uphold Rust's aliasing rules.
    pub unsafe fn as_ref<'a>(&self) -> &'a T {
        // SAFETY: `Valid` only contains non-null and suitably
        // aligned pointers. The caller has to uphold the
        // remaining safety conditions.
        unsafe { self.ptr.as_ref() }
    }

    /// Returns an exclusive reference to the `Valid`.
    ///
    /// # Safety
    ///
    /// - The pointed-to memory must be initialized.
    /// - You must uphold Rust's aliasing rules.
    pub unsafe fn as_mut<'a>(&mut self) -> &'a mut T {
        // SAFETY: `Valid` only contains non-null and suitably
        // aligned pointers. The caller has to uphold the
        // remaining safety conditions.
        unsafe { self.ptr.as_mut() }
    }
}

impl<T: ?Sized> Copy for Valid<T> {}

impl<T: ?Sized> Clone for Valid<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized> Eq for Valid<T> {}

impl<T: ?Sized> PartialEq for Valid<T> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.as_ptr(), other.as_ptr())
    }
}

impl<T: ?Sized> Ord for Valid<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_ptr().cast::<()>().cmp(&other.as_ptr().cast::<()>())
    }
}

impl<T: ?Sized> PartialOrd for Valid<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: ?Sized> Hash for Valid<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ptr().hash(state)
    }
}

impl<T: ?Sized> fmt::Debug for Valid<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.as_ptr(), f)
    }
}

impl<T: ?Sized> fmt::Pointer for Valid<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.as_ptr(), f)
    }
}

/// Describes why a raw pointer is invalid.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidPtr {
    /// The pointer is null.
    #[error("null pointer")]
    Null,
    /// The pointer is unaligned.
    #[error("unaligned pointer")]
    Unaligned,
}

impl InvalidPtr {
    /// Returns `InvalidPtr` as a constant string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null pointer",
            Self::Unaligned => "unaligned pointer",
        }
    }
}

#[repr(transparent)]
struct Hex(usize);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#0x}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use core::{
        hint::black_box,
        mem::ManuallyDrop,
        sync::atomic::{AtomicBool, Ordering},
    };

    use super::*;

    #[derive(Copy, Clone)]
    struct Dummy {
        _pad: u32,
    }
    impl Dummy {
        const fn new(x: u32) -> Self {
            Self { _pad: x }
        }
    }
    impl Typed for Dummy {
        const TYPE_ID: TypeId = TypeId::new(42);
    }

    /// Tests that we detect when a `Safe` is copied.
    #[test]
    fn test_safe_copy_check() {
        let mut orig = MaybeUninit::uninit();
        Safe::init(&mut orig, Dummy::new(123));

        // SAFETY: `orig` was initialized by `Safe::init`.
        unsafe { orig.assume_init_ref() }.check().unwrap();

        // Pretend that C copied `orig`.
        {
            let mut copy = MaybeUninit::<Safe<Dummy>>::uninit();
            // SAFETY: FFI call, no invariants.
            unsafe {
                black_box(libc::memmove(
                    black_box(ptr::addr_of_mut!(copy).cast()),
                    black_box(ptr::addr_of!(orig).cast()),
                    size_of_val(&orig),
                ))
            };
            assert_eq!(
                // SAFETY: `orig` was initialized by
                // `Safe::init`.
                unsafe { black_box(copy).assume_init_ref() }.check(),
                Err(Error::AddrChanged)
            );
        }

        assert_eq!(
            // SAFETY: `orig` was initialized by `Safe::init`.
            unsafe { black_box(orig).assume_init() }.check(),
            Err(Error::AddrChanged)
        );
    }

    #[test]
    fn test_owned_ptr_read() {
        struct T<'a>(&'a AtomicBool);
        impl Drop for T<'_> {
            fn drop(&mut self) {
                assert!(!self.0.load(Ordering::SeqCst));
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let dropped = AtomicBool::new(false);
        let mut val = ManuallyDrop::new(T(&dropped));
        // SAFETY: `ptr::addr_of_mut` always returns a non-null,
        // suitably aligned pointer.
        let ptr = unsafe { OwnedPtr::new(ptr::addr_of_mut!(val)) }.unwrap();

        let t = unsafe { ptr.read() };
        // `read` should not drop the inner value.
        assert!(!dropped.load(Ordering::SeqCst));
        drop(t);
        // Dropping `t` should flip the flag.
        assert!(dropped.load(Ordering::SeqCst));
    }
}
