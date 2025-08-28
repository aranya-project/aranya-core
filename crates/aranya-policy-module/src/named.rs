#![expect(missing_docs, reason = "TODO(jdygert): Document")]

use aranya_policy_ast::Identifier;

#[macro_export]
macro_rules! named {
    ($ty:ty) => {
        impl $crate::named::Named for $ty {
            fn name(&self) -> &Identifier {
                &self.name
            }
        }
    };
}

pub trait Named {
    fn name(&self) -> &Identifier;
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[serde(bound(
    serialize = "V: serde::Serialize + Named",
    deserialize = "V: serde::de::DeserializeOwned + Named"
))]
pub struct NamedMap<V> {
    map: indexmap::IndexSet<ByName<V>, fnv::FnvBuildHasher>,
}

impl<V> NamedMap<V> {
    pub const fn new() -> Self {
        Self {
            map: indexmap::IndexSet::with_hasher(core::hash::BuildHasherDefault::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &V> {
        self.map.iter().map(|x| &x.0)
    }
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[error("An entry with that name already exists")]
pub struct AlreadyExists;

impl<V: Named> NamedMap<V> {
    pub fn insert(&mut self, val: V) -> Result<(), AlreadyExists> {
        if self.map.insert(ByName(val)) {
            Ok(())
        } else {
            Err(AlreadyExists)
        }
    }

    pub fn get(&self, name: impl AsRef<str>) -> Option<&V> {
        self.map.get(name.as_ref()).map(|x| &x.0)
    }

    pub fn contains(&self, name: impl AsRef<str>) -> bool {
        self.map.contains(name.as_ref())
    }
}

impl<V> Default for NamedMap<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: Named + PartialEq> PartialEq for NamedMap<V> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .map
                .iter()
                .all(|x| other.map.get(x.0.name().as_str()).is_some_and(|y| x == y))
    }
}
impl<V: Named + Eq> Eq for NamedMap<V> {}

#[derive(Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
struct ByName<V>(V);

impl<V: Named> PartialEq for ByName<V> {
    fn eq(&self, other: &Self) -> bool {
        self.0.name() == other.0.name()
    }
}
impl<V: Named> Eq for ByName<V> {}

impl<V: Named> core::hash::Hash for ByName<V> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.name().hash(state);
    }
}

impl<V: Named> core::borrow::Borrow<str> for ByName<V> {
    fn borrow(&self) -> &str {
        self.0.name().as_str()
    }
}
