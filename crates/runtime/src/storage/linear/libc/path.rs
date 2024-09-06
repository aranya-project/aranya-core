//! Null-terminated path handling.

#[cfg(any(test, feature = "std"))]
extern crate std;

extern crate alloc;

use alloc::vec::Vec;
use core::{
    cmp::Ordering,
    ffi::{c_char, CStr},
    fmt,
    mem::MaybeUninit,
    ops::Deref,
    slice, str,
};

use buggy::{Bug, BugExt};
use crypto::id::{String64, ToBase58};

use crate::GraphId;

/// The input to `Path` is missing a null byte.
#[derive(Debug, Eq, PartialEq)]
pub struct MissingNullByte(());

impl core::error::Error for MissingNullByte {}

impl fmt::Display for MissingNullByte {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        "missing null byte".fmt(f)
    }
}

/// A borrowed file path.
#[repr(transparent)]
pub struct Path(
    /// Even though all of the public APIs require inputs to be
    /// null terminated, this slice is NOT necessarily null
    /// termianted. This is because we want to interop with
    /// `std::path::Path` and `std::path::PathBuf` which only
    /// expose `std::ffi::OsStr` and `std::ffi::OsString` which
    /// do not contain a null byte.
    ///
    /// NB: if the slice contains a null byte it will always be
    /// the *very last* byte.
    [u8],
);

impl Path {
    fn new<S: AsRef<[u8]> + ?Sized>(path: &S) -> &Self {
        Self::try_new(path.as_ref()).into()
    }

    /// Returns `Ok` if `path` has a null byte, `Err` if it does
    /// not or if the null byte is not within `isize::MAX` bytes.
    ///
    /// `path` is truncated at the first null byte, if any.
    fn try_new<S: AsRef<[u8]> + ?Sized>(path: &S) -> Result<&Self, &Self> {
        let path = path.as_ref();
        memchr::memchr(0, path)
            .and_then(|idx| {
                let end = isize::try_from(idx).ok()?.checked_add(1)?.try_into().ok()?;
                path.get(..end)
            })
            .map(Self::from_raw_bytes)
            .ok_or(Self::from_raw_bytes(path))
    }

    /// Creates a `Path` from the bytes as-is.
    fn from_raw_bytes(path: &[u8]) -> &Self {
        // SAFETY: `&[u8]` and `&Self` have the same
        // memory layout.
        unsafe { &*(path as *const [u8] as *const Self) }
    }

    /// Create a `Path` from bytes that end with a null
    /// terminator.
    ///
    /// In debug mode this panics if `path` does not with with
    /// a null terminator.
    fn from_null_terminated_bytes(path: &[u8]) -> &Self {
        debug_assert!(path.ends_with(&[0]) || path.is_empty());

        Self::from_raw_bytes(path)
    }

    /// Create a [`Path`] from a raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must not be null.
    /// - `ptr` must be null terminated.
    /// - `ptr` must be valid for reads up to the null
    ///   terminator.
    /// - `ptr` must not be mutated for the duration of `'a`.
    /// - The null terminator must be within `isize::MAX` bytes
    ///   from `ptr`.
    pub unsafe fn from_ptr<'a>(ptr: *const c_char) -> &'a Self {
        debug_assert!(!ptr.is_null());

        // SAFETY: See the function's safety docs.
        let len = unsafe { libc::strlen(ptr) };
        debug_assert!(len < (isize::MAX - 1) as usize);

        // SAFETY: See the function's safety docs.
        let path = unsafe {
            // `len+1` does not overflow since the null
            // terminator must be within `isize::MAX` bytes from
            // `ptr`.
            #[allow(clippy::arithmetic_side_effects)]
            slice::from_raw_parts(ptr.cast(), len + 1)
        };
        Self::from_null_terminated_bytes(path)
    }

    /// Create a [`Path`] from null-terminated bytes.
    ///
    /// # Errors
    ///
    /// `path` must contain at least one null byte.
    pub fn from_bytes_until_null(path: &[u8]) -> Result<&Self, MissingNullByte> {
        Self::try_new(path).map_err(|_| MissingNullByte(()))
    }

    /// Create a [`Path`] from a [`CStr`].
    pub fn from_cstr(path: &CStr) -> &Self {
        Self::from_null_terminated_bytes(path.to_bytes_with_nul())
    }

    /// Returns the path as `&[u8]`.
    const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the path as `MaybeUtf8`.
    fn display(&self) -> MaybeUtf8<'_> {
        MaybeUtf8(self.as_bytes_without_null())
    }

    /// Returns the path as `&[u8]` *without* the trailing null
    /// byte, if any.
    fn as_bytes_without_null(&self) -> &[u8] {
        self.as_bytes()
            .strip_suffix(&[0])
            .unwrap_or(self.as_bytes())
    }

    /// Reports whether the path is absolute.
    pub fn is_abs(&self) -> bool {
        self.as_bytes().starts_with(b"/")
    }

    /// Creates an owned [`PathBuf`] with `path` joined to
    /// `self`.
    pub fn join<P: AsRef<Path>>(&self, path: P) -> PathBuf {
        PathBuf::from_iter([self, path.as_ref()])
    }

    /// Converts the `Path` into a [`PathBuf`].
    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(self)
    }

    /// Invokes `f` with `Path` converted to a null-terminated
    /// C-style string.
    pub fn with_cstr<R>(&self, f: &dyn Fn(*const c_char) -> R) -> R {
        // See https://github.com/rust-lang/rust/blob/7a5867425959b4b5d69334fa6f02150dc2a5d128/library/std/src/sys/pal/common/small_c_string.rs
        let path = self.as_bytes();
        if path.ends_with(&[0]) {
            f(path.as_ptr().cast())
        } else {
            self.with_cstr_no_null(f)
        }
    }

    #[cold]
    #[inline(never)]
    fn with_cstr_no_null<R>(&self, f: &dyn Fn(*const c_char) -> R) -> R {
        let path = self.as_bytes();

        // This size is taken from the stdlib's implementation,
        // which was chosen in order to avoid a probe frame.
        const MAX_STACK: usize = 384;
        if path.len() < MAX_STACK {
            let mut buf = MaybeUninit::<[u8; MAX_STACK]>::uninit();
            // SAFETY: `buf` is obviously a valid pointer and
            // we've checked that `path.len() < buf.len()`.
            unsafe {
                buf.as_mut_ptr()
                    .cast::<u8>()
                    .copy_from_nonoverlapping(path.as_ptr(), path.len());
                // Add the null terminator.
                buf.as_mut_ptr().cast::<u8>().add(path.len()).write(0);
            }
            f(buf.as_ptr().cast())
        } else {
            let path = self.to_path_buf();
            f(path.as_ptr())
        }
    }
}

impl Eq for Path {}
impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes_without_null() == other.as_bytes_without_null()
    }
}
impl Ord for Path {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(self.as_bytes_without_null(), other.as_bytes_without_null())
    }
}
impl PartialOrd for Path {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

// From stdlib v1.77.
macro_rules! impl_cmp {
    (<$($life:lifetime),*> $lhs:ty, $rhs: ty) => {
        impl<$($life),*> PartialEq<$rhs> for $lhs {
            fn eq(&self, other: &$rhs) -> bool {
                <Path as PartialEq>::eq(self, other)
            }
        }

        impl<$($life),*> PartialEq<$lhs> for $rhs {
            fn eq(&self, other: &$lhs) -> bool {
                <Path as PartialEq>::eq(self, other)
            }
        }

        impl<$($life),*> PartialOrd<$rhs> for $lhs {
            fn partial_cmp(&self, other: &$rhs) -> Option<Ordering> {
                <Path as PartialOrd>::partial_cmp(self, other)
            }
        }

        impl<$($life),*> PartialOrd<$lhs> for $rhs {
            fn partial_cmp(&self, other: &$lhs) -> Option<Ordering> {
                <Path as PartialOrd>::partial_cmp(self, other)
            }
        }
    };
}
impl_cmp!(<> PathBuf, Path);
impl_cmp!(<'a> PathBuf, &'a Path);

// From stdlib v1.77.
macro_rules! impl_cmp_raw{
    (<$($life:lifetime),*> $lhs:ty, $rhs: ty) => {
        impl<$($life),*> PartialEq<$rhs> for $lhs {
            fn eq(&self, other: &$rhs) -> bool {
                <Path as PartialEq>::eq(self, Path::new(other))
            }
        }

        impl<$($life),*> PartialEq<$lhs> for $rhs {
            fn eq(&self, other: &$lhs) -> bool {
                <Path as PartialEq>::eq(Path::new(self), other)
            }
        }

        impl<$($life),*> PartialOrd<$rhs> for $lhs {
            fn partial_cmp(&self, other: &$rhs) -> Option<Ordering> {
                <Path as PartialOrd>::partial_cmp(self, Path::new(other))
            }
        }

        impl<$($life),*> PartialOrd<$lhs> for $rhs {
            fn partial_cmp(&self, other: &$lhs) -> Option<Ordering> {
                <Path as PartialOrd>::partial_cmp(Path::new(self), other)
            }
        }
    };
}
impl_cmp_raw!(<> PathBuf, str);
impl_cmp_raw!(<'a> PathBuf, &'a str);
impl_cmp_raw!(<> Path, str);
impl_cmp_raw!(<'a> Path, &'a str);
impl_cmp_raw!(<'a> &'a Path, str);
impl_cmp_raw!(<> PathBuf, [u8]);
impl_cmp_raw!(<'a> PathBuf, &'a [u8]);
impl_cmp_raw!(<> Path, [u8]);
impl_cmp_raw!(<'a> Path, &'a [u8]);
impl_cmp_raw!(<'a> &'a Path, [u8]);

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

#[cfg(any(test, feature = "std"))]
impl AsRef<Path> for std::path::PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path().as_ref()
    }
}

#[cfg(any(test, feature = "std"))]
impl AsRef<Path> for std::path::Path {
    fn as_ref(&self) -> &Path {
        // NB: as of Rust 1.77, `OsStr::as_encoded_bytes` returns
        // the raw bytes for Unixy platforms.
        Path::new(self.as_os_str().as_encoded_bytes())
    }
}

impl<'a> From<&'a CStr> for &'a Path {
    fn from(path: &'a CStr) -> Self {
        Path::from_cstr(path)
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Path {
    type Error = MissingNullByte;

    fn try_from(path: &'a [u8]) -> Result<Self, Self::Error> {
        Path::from_bytes_until_null(path)
    }
}

impl<'a> From<Result<&'a Path, &'a Path>> for &'a Path {
    fn from(res: Result<&'a Path, &'a Path>) -> &'a Path {
        match res {
            Ok(v) | Err(v) => v,
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.display().fmt(f)
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Path").field(&self.display()).finish()
    }
}

/// For formatting a slice that might be UTF-8.
struct MaybeUtf8<'a>(&'a [u8]);

impl MaybeUtf8<'_> {
    /// Returns the path as `&[u8]`.
    fn try_as_str(&self) -> Result<&str, &[u8]> {
        str::from_utf8(self.0).map_err(|_| self.0)
    }
}

impl fmt::Display for MaybeUtf8<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_as_str() {
            Ok(s) => s.fmt(f),
            Err(v) => write!(f, "{v:?}"),
        }
    }
}

impl fmt::Debug for MaybeUtf8<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_as_str() {
            Ok(s) => s.fmt(f),
            Err(v) => write!(f, "{v:?}"),
        }
    }
}

/// An owned [`Path`].
#[derive(Eq, PartialEq)]
pub struct PathBuf {
    /// NB: unlike `Path`, this is *always* has a null
    /// terminator.
    buf: Vec<u8>,
}

impl PathBuf {
    const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// This is a method on `PathBuf` instead of `Path` because
    /// `PathBuf` always has a null terminator.
    fn as_ptr(&self) -> *const c_char {
        self.buf.as_ptr().cast()
    }

    fn as_path(&self) -> &Path {
        Path::from_null_terminated_bytes(self.buf.as_slice())
    }

    /// See `std::path::PathBuf::join`.
    fn push<P: AsRef<Path>>(&mut self, path: P) {
        // Get rid of the trailing null byte to simplify the code
        // below.
        if let Some(v) = self.buf.pop() {
            debug_assert_eq!(v, 0);
        }

        let path = path.as_ref();
        if path.is_abs() {
            self.buf = path.as_bytes().to_vec();
        } else {
            if !self.buf.is_empty() && !self.buf.ends_with(b"/") {
                self.buf.push(b'/');
            }
            self.buf.extend_from_slice(path.as_bytes());
        }
        if !self.buf.ends_with(&[0]) {
            self.buf.push(0);
        }
        debug_assert!(self.buf.ends_with(&[0]));
    }
}

impl AsRef<Path> for PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl Deref for PathBuf {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.as_path()
    }
}

impl<'a> From<&'a Path> for PathBuf {
    fn from(path: &'a Path) -> Self {
        let mut buf = Self::new();
        buf.push(path);
        buf
    }
}

impl<P> FromIterator<P> for PathBuf
where
    P: AsRef<Path>,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = P>,
    {
        let mut buf = Self::new();
        buf.extend(iter);
        buf
    }
}

impl<P> Extend<P> for PathBuf
where
    P: AsRef<Path>,
{
    fn extend<I: IntoIterator<Item = P>>(&mut self, iter: I) {
        for elem in iter {
            self.push(elem.as_ref())
        }
    }
}

impl fmt::Display for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for PathBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

/// A [`Path`] created from a [`GraphId`].
#[derive(Copy, Clone)]
pub struct IdPath {
    buf: [u8; String64::MAX_SIZE + 1],
}

impl IdPath {
    fn as_path(&self) -> &Path {
        Path::new(&self.buf)
    }
}

impl AsRef<Path> for IdPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl Deref for IdPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.as_path()
    }
}

impl fmt::Display for IdPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl fmt::Debug for IdPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

impl GraphId {
    pub(super) fn to_path(self) -> Result<IdPath, Bug> {
        let mut buf = [0u8; String64::MAX_SIZE + 1];
        let b58 = self.to_base58();
        let src = b58.as_bytes();
        let dst = buf
            .get_mut(..String64::MAX_SIZE)
            .assume("`buf.len()` >= `String64::MAX_SIZE`")?
            .get_mut(..src.len())
            .assume("`buf.len()` >= `src.len()`")?;
        dst.copy_from_slice(src);
        Ok(IdPath { buf })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    macro_rules! path {
        ($path:literal) => {{
            let path: &[u8] = $path.as_ref();
            // SAFETY: `&Path` has the same size as `&[u8]`.
            unsafe { &*(path as *const [u8] as *const Path) }
        }};
    }

    #[test]
    fn test_idpath() {
        let root = Path::new("/foo/bar");
        let id = GraphId::default();

        let got = root.join(id.to_path().unwrap());
        let want = format!("/foo/bar/{id}");

        assert_eq!(got, want.as_str());
    }

    /// Test [`Path::from_bytes_until_null`].
    #[test]
    fn test_path_from_bytes_until_null() {
        let cases: &[(&[u8], _)] = &[
            (b"/foo", Err(MissingNullByte(()))),
            (b"/foo\0", Ok(path!("/foo\0"))),
            (b"/foo\0\0", Ok(path!("/foo\0"))),
            (b"/foo\0\0bar\0", Ok(path!("/foo\0"))),
        ];
        for (i, (path, want)) in cases.iter().enumerate() {
            let got = Path::from_bytes_until_null(path);
            assert_eq!(got, *want, "#{i}");
        }
    }

    /// Test [`Path::from_ptr`].
    #[test]
    fn test_path_from_ptr() {
        let cases: &[(&[u8], _)] = &[
            (b"/foo\0", path!("/foo\0")),
            (b"/foo\0\0", path!("/foo\0")),
            (b"/foo\0\0bar\0", path!("/foo\0")),
        ];
        for (i, (path, want)) in cases.iter().enumerate() {
            // SAFETY: all inputs contain a null byte within
            // `isize::MAX`.
            let got = unsafe { Path::from_ptr(path.as_ptr().cast()) };
            assert_eq!(got, *want, "#{i}");
        }
    }

    /// Test [`Path::from_Cstr`].
    #[test]
    fn test_path_from_cstr() {
        let cases: &[(&[u8], _)] = &[
            (b"/foo\0", path!("/foo\0")),
            (b"/foo\0\0", path!("/foo\0")),
            (b"/foo\0\0bar\0", path!("/foo\0")),
        ];
        for (i, (path, want)) in cases.iter().enumerate() {
            let cstr = CStr::from_bytes_until_nul(path).unwrap();
            let got = Path::from_cstr(cstr);
            assert_eq!(got, *want, "#{i}");
        }
    }

    #[test]
    fn test_path_partial_eq() {
        let cases = [
            (path!("/foo"), "/foo"),
            (path!("/foo\0"), "/foo"),
            (path!("/foo\0"), "/foo\0"),
            (path!("/foo"), "/foo\0"),
        ];
        for (i, (a, b)) in cases.into_iter().enumerate() {
            assert_eq!(a, b, "#{i}: (a,b) str");
            assert_eq!(b, a, "#{i}: (b,a) str");
            assert_eq!(a, b.as_bytes(), "#{i}: (a,b) bytes");
            assert_eq!(b.as_bytes(), a, "#{i}: (b,a) bytes");
            assert_eq!(a.to_path_buf(), b, "#{i}: (a,b) PathBuf");
            assert_eq!(b, a.to_path_buf(), "#{i}: (b,a) PathBuf");
        }
    }

    /// Test [`Path::join`].
    #[test]
    fn test_path_join() {
        let cases: &[(&[&str], &Path)] = &[
            (&["foo"], path!("foo")),
            (&["foo", "bar"], path!("foo/bar")),
            (&["foo", "bar", "baz"], path!("foo/bar/baz")),
            (&["foo/", "bar/", "baz"], path!("foo/bar/baz")),
            (&["foo/", "bar/", "baz/"], path!("foo/bar/baz/")),
            (&["foo/", "bar/", "/baz/"], path!("/baz/")),
            (&["foo/", "/bar/", "/baz/"], path!("/baz/")),
            (&["/foo/", "/bar/", "/baz/"], path!("/baz/")),
            (&["/foo/", "/bar/", "baz//"], path!("/bar/baz//")),
            (&["foo/", "bar", "", "/", "", "baz//"], path!("/baz//")),
        ];
        for (i, (elems, want)) in cases.iter().enumerate() {
            let got: PathBuf = elems.iter().map(Path::new).collect();
            assert_eq!(got, *want, "#{i}");
        }
    }
}
