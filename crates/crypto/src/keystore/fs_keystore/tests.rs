#![cfg(test)]

use serde::{Deserialize, Serialize};
use tempfile::tempdir;

use super::Store;
use crate::{
    default::DefaultCipherSuite,
    engine::WrappedKey,
    id::{Id, Identified},
    KeyStore,
};

macro_rules! id {
    ($id:expr) => {{
        let data = ($id as u64).to_le_bytes();
        Id::new::<DefaultCipherSuite>(&data, b"TestKey")
    }};
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct TestKey64(u64);

impl WrappedKey for TestKey64 {}

impl Identified for TestKey64 {
    type Id = Id;

    fn id(&self) -> Self::Id {
        id!(self.0)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct TestKeyId(Id);

impl WrappedKey for TestKeyId {}

impl Identified for TestKeyId {
    type Id = Id;

    fn id(&self) -> Self::Id {
        self.0
    }
}

#[test]
fn test_get() {
    let dir = tempdir().expect("should be able to create tempdir");
    let mut store = Store::open(dir.path()).expect("should be able to create `Store`");

    let want = TestKey64(1);
    store
        .try_insert(id!(1), want)
        .expect("should be able to store key");
    let got = store
        .get::<TestKey64>(&id!(1))
        .expect("`get` should not fail")
        .expect("should be able to find key");
    assert_eq!(got, want);
}

#[test]
fn test_get_wrong_key_type() {
    let dir = tempdir().expect("should be able to create tempdir");
    let mut store = Store::open(dir.path()).expect("should be able to create `Store`");

    let want = TestKey64(1);
    store
        .try_insert(id!(1), want)
        .expect("should be able to store key");
    store
        .get::<TestKeyId>(&id!(1))
        .expect_err("should not be able to get key");
}

#[test]
fn test_remove() {
    let dir = tempdir().expect("should be able to create tempdir");
    let mut store = Store::open(dir.path()).expect("should be able to create `Store`");

    store
        .try_insert(id!(1), TestKey64(1))
        .expect("should be able to store key");
    store
        .try_insert(id!(2), TestKey64(2))
        .expect("should be able to store key");

    let got = store
        .remove::<TestKey64>(&id!(1))
        .expect("`remove` should not fail")
        .expect("should be able to find key");
    assert_eq!(got, TestKey64(1));

    // After removing key=1, key=2 should still exist.
    let got = store
        .get::<TestKey64>(&id!(2))
        .expect("`get` should not fail")
        .expect("should be able to find key");
    assert_eq!(got, TestKey64(2));

    // But key=1 should not.
    assert!(store
        .get::<TestKey64>(&id!(1))
        .expect("`get` should not fail")
        .is_none());
}

#[test]
fn test_get_cloned() {
    let dir = tempdir().expect("should be able to create tempdir");
    let mut store1 = Store::open(dir.path()).expect("should be able to create `Store`");

    let want = TestKey64(1);
    store1
        .try_insert(id!(1), want)
        .expect("should be able to store key");
    let got = store1
        .get::<TestKey64>(&id!(1))
        .expect("`get` should not fail")
        .expect("should be able to find key");
    assert_eq!(got, want);

    let store2 = store1.try_clone().expect("should be able to clone `Store`");
    let got = store2
        .get::<TestKey64>(&id!(1))
        .expect("`get` should not fail")
        .expect("should be able to find key");
    assert_eq!(got, want);
}
