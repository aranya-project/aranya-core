use core::{
    ffi::{c_char, CStr},
    fmt, str,
};

use cfg_if::cfg_if;

use crate::errno::Errno;

/// The path is invalid.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidPathError(&'static str);

impl core::error::Error for InvalidPathError {}

impl fmt::Display for InvalidPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

const fn bad_path(msg: &'static str) -> Result<(), InvalidPathError> {
    Err(InvalidPathError(msg))
}

/// A borrowed shared memory path.
///
/// It's like `&str`, but syntactically valid.
#[derive(Debug)]
#[repr(transparent)]
pub struct Path([u8]);

impl Path {
    /// The maximum number of bytes allowed in a `Path`.
    pub const NAME_MAX: usize = if cfg!(target_os = "macos") { 32 } else { 255 };

    /// Checks whether `path` is valid.
    ///
    /// A path is valid if it:
    ///
    /// - is at most [`NAME_MAX`][Self::NAME_MAX] bytes
    /// - starts with "/"
    /// - has at most one "/"
    /// - has a trailing nul byte
    pub fn validate(path: &[u8]) -> Result<(), InvalidPathError> {
        if path.len() > Self::NAME_MAX {
            return bad_path("path too long");
        }
        let Some((first, rest)) = path.split_first() else {
            return bad_path("path is empty");
        };
        if first != &b'/' {
            return bad_path("path missing leading '/'");
        }
        if !rest.ends_with(b"\x00") {
            return bad_path("path missing trailing null byte");
        }
        if rest.contains(&b'/') {
            return bad_path("path has more than one '/'");
        }
        Ok(())
    }

    /// Create a [`Path`] from a C string.
    pub fn from_cstr(path: &CStr) -> Result<&Self, InvalidPathError> {
        Self::from_bytes(path.to_bytes_with_nul())
    }

    /// Create a [`Path`] from bytes.
    pub fn from_bytes(path: &[u8]) -> Result<&Self, InvalidPathError> {
        Self::validate(path)?;

        // SAFETY: Path and [u8] must have the same layout.
        Ok(unsafe { &*(path as *const [u8] as *const Self) })
    }

    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr().cast::<_>()
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Path {
    type Error = InvalidPathError;

    fn try_from(path: &'a [u8]) -> Result<Self, Self::Error> {
        Path::from_bytes(path)
    }
}

impl<'a> TryFrom<&'a CStr> for &'a Path {
    type Error = InvalidPathError;

    fn try_from(path: &'a CStr) -> Result<Self, Self::Error> {
        Path::from_cstr(path)
    }
}

impl<'a> TryFrom<&'a str> for &'a Path {
    type Error = InvalidPathError;

    fn try_from(path: &'a str) -> Result<Self, Self::Error> {
        Path::from_bytes(path.as_bytes())
    }
}

impl AsRef<Path> for Path {
    fn as_ref(&self) -> &Path {
        self
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Skip the null byte.
        let data = self.0.strip_suffix(&[0]).unwrap_or(&self.0);
        match str::from_utf8(data) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "invalid UTF-8: {:?}", &data),
        }
    }
}

/// Delete the shared data at `path`.
pub fn unlink<P>(path: P) -> Result<(), Errno>
where
    P: AsRef<Path>,
{
    cfg_if! {
        if #[cfg(feature = "sdlib")] {
            super::sdlib::unlink(path)
        } else {
            super::posix::shm_unlink(path)
        }
    }
}

/// Whether the shared memory should be created.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Flag {
    /// Do not try to create the shared memory if it does not
    /// exist.
    OpenOnly,
    /// Create the shared memory if it does not exist.
    Create,
}

/// Whether the shared memory should be opened only for reading
/// or for both reading and writing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Open the shared memory for reading only.
    #[deprecated = "The current implementation requires RW access"]
    ReadOnly,
    /// Open the shared memory for reading and writing.
    ReadWrite,
}

#[cfg(feature = "alloc")]
mod alloc_impls {
    use alloc::{boxed::Box, ffi::CString, string::String, vec::Vec};
    use core::ffi::CStr;

    use super::{InvalidPathError, Path};

    impl TryFrom<Box<[u8]>> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: Box<[u8]>) -> Result<Self, Self::Error> {
            Path::validate(&path)?;

            // SAFETY: Path and [u8] must have the same layout.
            Ok(unsafe { Box::from_raw(Box::into_raw(path) as *mut Path) })
        }
    }

    impl From<&Path> for Box<Path> {
        fn from(path: &Path) -> Self {
            let path = Box::<[u8]>::from(&path.0);

            // SAFETY: Path and [u8] must have the same layout.
            unsafe { Box::from_raw(Box::into_raw(path) as *mut Path) }
        }
    }

    impl Clone for Box<Path> {
        fn clone(&self) -> Self {
            self.as_ref().into()
        }
    }

    impl TryFrom<Vec<u8>> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: Vec<u8>) -> Result<Self, Self::Error> {
            path.into_boxed_slice().try_into()
        }
    }

    impl TryFrom<String> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: String) -> Result<Self, Self::Error> {
            path.into_bytes().into_boxed_slice().try_into()
        }
    }

    impl TryFrom<Box<str>> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: Box<str>) -> Result<Self, Self::Error> {
            path.into_boxed_bytes().try_into()
        }
    }

    impl TryFrom<CString> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: CString) -> Result<Self, Self::Error> {
            path.into_bytes_with_nul().into_boxed_slice().try_into()
        }
    }

    impl TryFrom<Box<CStr>> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: Box<CStr>) -> Result<Self, Self::Error> {
            path.into_c_string().try_into()
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_boxing() {
            let bytes = b"/asdf\0".as_slice();
            let path: Box<Path> = Path::from_bytes(bytes).unwrap().into();
            assert_eq!(&path.as_ref().0, bytes);

            let path: Box<Path> = (Box::<[u8]>::from(bytes)).try_into().unwrap();
            assert_eq!(&path.as_ref().0, bytes);

            let path: Box<Path> = path.clone();
            assert_eq!(&path.as_ref().0, bytes);
        }
    }
}
