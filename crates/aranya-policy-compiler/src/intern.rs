use std::{
    cell::RefCell,
    collections::{hash_map::RandomState, HashMap},
    hash::{BuildHasher, Hash},
    ptr::NonNull,
};

use bumpalo::Bump;

use crate::arena::{Arena, Key};

/// Creates a typed interner with a custom key type.
///
/// Generates both the interner type alias and the key type.
macro_rules! typed_interner {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($ty:ty) => $id:ident;
    ) => {
        $(#[$meta])*
        $vis type $name = $crate::intern::Interner<$id, $ty>;
        $crate::arena::new_key_type! {
            $vis struct $id;
        }
    };
}
pub(crate) use typed_interner;

/// Interns values.
#[derive(Debug)]
pub(crate) struct Interner<K, V, S = RandomState> {
    alloc: Bump,
    index: RefCell<HashMap<u64, Vec<K>, S>>,
    arena: RefCell<Arena<K, NonNull<V>>>,
    hasher: S,
}

impl<K, V> Interner<K, V> {
    /// Creates a new interner with default hasher.
    pub fn new() -> Self {
        Self::with_hasher(RandomState::default())
    }
}

impl<K, V, S> Interner<K, V, S>
where
    S: BuildHasher + Clone,
{
    fn with_hasher(hasher: S) -> Self {
        Self {
            alloc: Bump::new(),
            index: RefCell::new(HashMap::with_hasher(hasher.clone())),
            arena: RefCell::new(Arena::new()),
            hasher,
        }
    }
}

impl<K, V, S> Interner<K, V, S>
where
    K: Key,
    V: Eq + Hash,
    S: BuildHasher,
{
    /// Interns `item`, returning a unique key.
    ///
    /// If `item` already exists, it returns the existing key.
    pub fn intern(&self, item: V) -> K {
        let hash = self.hash(&item);

        if let Some(keys) = self.index.borrow().get(&hash) {
            let arena = self.arena.borrow();
            if let Some(&key) = keys.iter().find(|&&key| {
                arena.get(key).is_some_and(|ptr| {
                    // SAFETY: `ptr` comes from `self.arena`
                    // which is alive until the `Interner` is
                    // dropped.
                    let cand = unsafe { ptr.as_ref() };
                    cand == &item
                })
            }) {
                return key;
            }
        }

        let item_ptr = self.alloc.alloc(item);
        let key = self.arena.borrow_mut().insert(NonNull::from(item_ptr));
        self.index.borrow_mut().entry(hash).or_default().push(key);
        key
    }

    fn hash(&self, item: &V) -> u64 {
        self.hasher.hash_one(item)
    }

    /// Returns a shared reference to the value associated with `key`.
    pub fn get(&self, key: K) -> Option<&V> {
        self.arena.borrow().get(key).map(|ptr| {
            // SAFETY: `ptr` comes from `self.arena`
            // which is alive until the `Interner` is
            // dropped.
            unsafe { ptr.as_ref() }
        })
    }

    /// Returns the number of unique interned values.
    pub fn len(&self) -> usize {
        self.arena.borrow().len()
    }

    /// Returns true if no values have been interned.
    pub fn is_empty(&self) -> bool {
        self.arena.borrow().is_empty()
    }
}

impl<K, V> Default for Interner<K, V, RandomState> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    typed_interner! {
        struct TestValueInterner(TestValue) => TestValueRef;
    }

    typed_interner! {
        struct StringInterner(String) => StringRef;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct TestValue {
        id: u32,
        data: String,
    }

    impl TestValue {
        fn new(id: u32, data: &str) -> Self {
            Self {
                id,
                data: data.to_string(),
            }
        }
    }

    #[test]
    fn test_interner_basic_functionality() {
        let interner = TestValueInterner::new();
        assert_eq!(interner.len(), 0);
        assert!(interner.is_empty());

        let value = TestValue::new(1, "test");
        let key1 = interner.intern(value.clone());
        let key2 = interner.intern(value.clone());

        // Should return the same key for the same value (deduplication)
        assert_eq!(key1, key2);
        assert_eq!(interner.len(), 1);

        // Should be able to retrieve the value
        assert_eq!(interner.get(key1), Some(&value));
    }

    #[test]
    fn test_interner_different_values() {
        let interner = TestValueInterner::new();
        let value1 = TestValue::new(1, "test1");
        let value2 = TestValue::new(2, "test2");

        let key1 = interner.intern(value1.clone());
        let key2 = interner.intern(value2.clone());

        // Should return different keys for different values
        assert_ne!(key1, key2);
        assert_eq!(interner.len(), 2);

        // Should be able to retrieve both values
        assert_eq!(interner.get(key1), Some(&value1));
        assert_eq!(interner.get(key2), Some(&value2));
    }

    #[test]
    fn test_interner_get_nonexistent() {
        let interner = TestValueInterner::new();
        let nonexistent_key = TestValueRef::from_usize(999);
        assert_eq!(interner.get(nonexistent_key), None);
    }

    #[test]
    fn test_interner_with_strings() {
        let interner = StringInterner::new();

        let s1 = "hello".to_string();
        let s2 = "world".to_string();
        let s3 = "hello".to_string(); // Same content as s1

        let key1 = interner.intern(s1.clone());
        let key2 = interner.intern(s2.clone());
        let key3 = interner.intern(s3.clone());

        // s1 and s3 should have the same key (deduplication)
        assert_eq!(key1, key3);
        assert_ne!(key1, key2);
        assert_eq!(interner.len(), 2);

        assert_eq!(interner.get(key1), Some(&s1));
        assert_eq!(interner.get(key2), Some(&s2));
    }

    #[test]
    fn test_typed_interner_macro() {
        let interner = TestValueInterner::new();
        let value = TestValue::new(42, "macro_test");
        let key = interner.intern(value.clone());

        // Verify we can retrieve the value
        assert_eq!(interner.get(key), Some(&value));
    }
}
