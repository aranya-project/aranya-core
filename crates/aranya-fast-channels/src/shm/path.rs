use core::{
    ffi::{CStr, c_char},
    fmt, ptr, str,
};

use cfg_if::cfg_if;

use crate::errno::Errno;

/// The path is invalid.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidPathError(&'static str);

const fn bad_path(msg: &'static str) -> Result<(), InvalidPathError> {
    Err(InvalidPathError(msg))
}

/// A borrowed shared memory path.
///
/// It's like `&str`, but syntactically valid.
#[derive(Debug)]
#[repr(transparent)]
pub struct Path(CStr);

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
    pub fn validate(path: &CStr) -> Result<(), InvalidPathError> {
        let path = path.to_bytes();
        if path.len() > Self::NAME_MAX {
            return bad_path("path too long");
        }
        let Some((first, rest)) = path.split_first() else {
            return bad_path("path is empty");
        };
        if first != &b'/' {
            return bad_path("path missing leading '/'");
        }
        if rest.contains(&b'/') {
            return bad_path("path has more than one '/'");
        }
        Ok(())
    }

    /// Create a [`Path`] from a C string.
    pub fn from_cstr(path: &CStr) -> Result<&Self, InvalidPathError> {
        Self::validate(path)?;
        // SAFETY: Path and CStr have the same layout.
        Ok(unsafe { &*(ptr::from_ref(path) as *const Self) })
    }

    /// Create a [`Path`] from bytes.
    pub fn from_bytes(path: &[u8]) -> Result<&Self, InvalidPathError> {
        let cstr = CStr::from_bytes_with_nul(path)
            .map_err(|_| InvalidPathError("path is not nul terminated"))?;
        Self::from_cstr(cstr)
    }

    pub(crate) fn as_cstr(&self) -> &CStr {
        &self.0
    }

    pub(crate) fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
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
        let data = self.as_cstr().to_bytes();
        match str::from_utf8(data) {
            Ok(s) => write!(f, "{s}"),
            Err(_) => write!(f, "invalid UTF-8: {:?}", &data),
        }
    }
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for Path {}

impl serde::Serialize for Path {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let data = self.as_cstr().to_bytes();
        if serializer.is_human_readable() {
            match str::from_utf8(data) {
                Ok(s) => serializer.serialize_str(s),
                Err(_) => serializer.serialize_bytes(data),
            }
        } else {
            serializer.serialize_bytes(data)
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
    use core::{ffi::CStr, fmt};

    use super::{InvalidPathError, Path};

    impl TryFrom<Box<[u8]>> for Box<Path> {
        type Error = InvalidPathError;

        fn try_from(path: Box<[u8]>) -> Result<Self, Self::Error> {
            let path = CString::from_vec_with_nul(path.into_vec())
                .map_err(|_| InvalidPathError("path is not nul terminated"))?
                .into_boxed_c_str();

            Path::validate(&path)?;

            // SAFETY: Path and CStr have the same layout.
            Ok(unsafe { Box::from_raw(Box::into_raw(path) as *mut Path) })
        }
    }

    impl From<&Path> for Box<Path> {
        fn from(path: &Path) -> Self {
            let path = Box::<CStr>::from(&path.0);

            // SAFETY: Path and CStr have the same layout.
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

    impl<'de> serde::Deserialize<'de> for Box<Path> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            struct Visitor;
            impl de::Visitor<'_> for Visitor {
                type Value = Box<Path>;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f, "a valid shared memory path")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    self.visit_bytes(v.as_bytes())
                }
                fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                    self.visit_byte_buf(v.into_bytes())
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    #[allow(
                        clippy::arithmetic_side_effects,
                        reason = "isize::MAX + 1 < usize::MAX"
                    )]
                    let mut bytes: Vec<u8> = Vec::with_capacity(v.len() + 1);
                    bytes.extend_from_slice(v);
                    bytes.push(0);
                    bytes.try_into().map_err(E::custom)
                }
                fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                    let mut bytes = v;
                    bytes.reserve_exact(1);
                    bytes.push(0);
                    bytes.try_into().map_err(E::custom)
                }
            }

            if deserializer.is_human_readable() {
                deserializer.deserialize_string(Visitor)
            } else {
                deserializer.deserialize_byte_buf(Visitor)
            }
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        fn test_boxing() {
            let cstr = c"/asdf";
            let bytes = cstr.to_bytes_with_nul();
            let path: Box<Path> = Path::from_bytes(bytes).unwrap().into();
            assert_eq!(path.as_ref().0, *cstr);

            let path: Box<Path> = (Box::<[u8]>::from(bytes)).try_into().unwrap();
            assert_eq!(path.as_ref().0, *cstr);

            let path: Box<Path> = path.clone();
            assert_eq!(path.as_ref().0, *cstr);
        }

        #[test]
        fn test_boxed_path_serde_utf8() {
            use serde_test::{Configure, Token, assert_de_tokens, assert_tokens};

            let bytes = b"/asdf\0".as_slice();
            let path: Box<Path> = Path::from_bytes(bytes).unwrap().into();

            assert_tokens(&path.clone().readable(), &[Token::Str("/asdf")]);
            assert_tokens(&path.clone().compact(), &[Token::Bytes(b"/asdf")]);

            assert_de_tokens(&path.clone().readable(), &[Token::String("/asdf")]);
            assert_de_tokens(&path.clone().compact(), &[Token::ByteBuf(b"/asdf")]);
        }

        #[test]
        fn test_boxed_path_serde_non_utf8() {
            use serde_test::{Configure, Token, assert_tokens};

            let bytes = b"/\xFF\0".as_slice();
            let path: Box<Path> = Path::from_bytes(bytes).unwrap().into();

            assert_tokens(&path.clone().readable(), &[Token::Bytes(b"/\xFF")]);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_path_ser_utf8() {
        use serde_test::{Configure, Token, assert_ser_tokens};

        let bytes = b"/asdf\0".as_slice();
        let path: &Path = Path::from_bytes(bytes).unwrap();

        assert_ser_tokens(&path.readable(), &[Token::Str("/asdf")]);
        assert_ser_tokens(&path.compact(), &[Token::Bytes(b"/asdf")]);
    }

    #[test]
    fn test_path_ser_non_utf8() {
        use serde_test::{Configure, Token, assert_ser_tokens};

        let bytes = b"/\xFF\0".as_slice();
        let path: &Path = Path::from_bytes(bytes).unwrap();

        assert_ser_tokens(&path.readable(), &[Token::Bytes(b"/\xFF")]);
    }
}
