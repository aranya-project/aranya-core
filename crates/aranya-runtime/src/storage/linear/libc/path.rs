//! Null-terminated path handling.

use core::{fmt, ops::Deref};

use aranya_libc::Path;
use spideroak_base58::{String32, ToBase58};

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

impl From<GraphId> for IdPath {
    fn from(id: GraphId) -> IdPath {
        IdPath(id.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idpath() {
        let root = Path::new("/foo/bar");
        let id = GraphId::default();

        let got = root.join(IdPath::from(id));
        let want = format!("/foo/bar/{id}");

        assert_eq!(got, want.as_str());
    }
}
