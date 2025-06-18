#![cfg(test)]

use aranya_crypto::{
    Rng,
    default::{DefaultCipherSuite, DefaultEngine},
};

use crate::testing::{Device, MemStore, TestImpl, test_all};

struct DefaultImpl;

impl TestImpl for DefaultImpl {
    type Engine = DefaultEngine<Rng, DefaultCipherSuite>;
    type Store = MemStore;

    fn new() -> Device<Self> {
        let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
        let store = MemStore::new();
        Device::new(eng, store)
    }
}

test_all!(default_engine, DefaultImpl);
