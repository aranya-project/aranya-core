//! Null-terminated path handling.

use core::{fmt, ops::Deref};

use aranya_crypto::id::{String32, ToBase58};
use aranya_libc::Path;

use crate::GraphId;

/// A [`Path`] created from a [`GraphId`].
#[derive(Copy, Clone)]
pub struct IdPath(String32);

impl IdPath {
    fn as_path(&self) -> &Path {
        self.0.as_cstr().into()
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
        self.0.fmt(f)
    }
}

impl fmt::Debug for IdPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl GraphId {
    pub(super) fn to_path(self) -> IdPath {
        IdPath(self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idpath() {
        let root = Path::new("/foo/bar");
        let id = GraphId::default();

        let got = root.join(id.to_path());
        let want = format!("/foo/bar/{id}");

        assert_eq!(got, want.as_str());
    }
}
