use serde::{Deserialize, Serialize};

/// Refer to immediately prior commands in a graph, usually via `Prior<CmdId>` or `Prior<Location>`.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
)]
pub enum Prior<T> {
    /// No parents (init command)
    None,
    /// One parent (basic command)
    Single(T),
    /// Two parents (merge command)
    Merge(T, T),
}

impl<T> Prior<T> {
    /// Converts from `&Prior<T>` to `Prior<&T>`.
    pub fn as_ref(&self) -> Prior<&T> {
        match self {
            Self::None => Prior::None,
            Self::Single(x) => Prior::Single(x),
            Self::Merge(x, y) => Prior::Merge(x, y),
        }
    }
}

impl<T: Clone> Prior<&T> {
    /// Maps an `Prior<&T>` to an `Prior<T>` by cloning the contents.
    pub fn cloned(self) -> Prior<T> {
        match self {
            Prior::None => Prior::None,
            Prior::Single(x) => Prior::Single(x.clone()),
            Prior::Merge(x, y) => Prior::Merge(x.clone(), y.clone()),
        }
    }
}

impl<T: Copy> Prior<&T> {
    /// Maps an `Prior<&T>` to an `Prior<T>` by copying the contents.
    pub fn copied(self) -> Prior<T> {
        match self {
            Prior::None => Prior::None,
            Prior::Single(x) => Prior::Single(*x),
            Prior::Merge(x, y) => Prior::Merge(*x, *y),
        }
    }
}

/// An iterator over the values in `Prior`.
///
/// Yields 0, 1, or 2 values.
pub struct IntoIter<T>(Prior<T>);

impl<T> IntoIterator for Prior<T> {
    type IntoIter = IntoIter<T>;
    type Item = T;
    fn into_iter(self) -> Self::IntoIter {
        IntoIter(self)
    }
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        match core::mem::replace(&mut self.0, Prior::None) {
            Prior::None => None,
            Prior::Single(x) => Some(x),
            Prior::Merge(x, y) => {
                self.0 = Prior::Single(y);
                Some(x)
            }
        }
    }
}
