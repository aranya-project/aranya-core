//! Null-terminated path handling.

#[cfg(any(test, feature = "std"))]
extern crate std;

use core::{fmt, ops::Deref};

use aranya_buggy::{Bug, BugExt};
use aranya_crypto::id::{String64, ToBase58};
pub use aranya_libc::{MissingNullByte, Path, PathBuf};

use crate::GraphId;

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

    #[test]
    fn test_idpath() {
        let root = Path::new("/foo/bar");
        let id = GraphId::default();

        let got = root.join(id.to_path().unwrap());
        let want = format!("/foo/bar/{id}");

        assert_eq!(got, want.as_str());
    }
}
