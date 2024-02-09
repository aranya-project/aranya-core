#![cfg(test)]

use crypto::{default::DefaultEngine, keystore::memstore::MemStore, Rng};

use crate::testing::run_tests;

run_tests!(default_engine, || -> (DefaultEngine<_, _>, MemStore) {
    let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let store = MemStore::new();
    (eng, store)
});
