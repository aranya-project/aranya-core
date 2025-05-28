#![cfg(test)]

use aranya_crypto::{Rng, default::DefaultEngine, keystore::memstore::MemStore};

use crate::testing::run_tests;

run_tests!(default_engine, || -> (DefaultEngine<_, _>, MemStore) {
    let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
    let store = MemStore::new();
    (eng, store)
});
