#![cfg(test)]

use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Rng,
};

use crate::testing::{test_all, Device, MemStore, TestImpl};

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
