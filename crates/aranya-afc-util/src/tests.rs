#![cfg(test)]

use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Engine, Rng,
};
use aranya_fast_channels::memory::State;

use crate::testing::{test_all, MemStore, TestImpl, User};

struct DefaultImpl;

impl TestImpl for DefaultImpl {
    type Engine = DefaultEngine<Rng, DefaultCipherSuite>;
    type Afc = State<<Self::Engine as Engine>::CS>;
    type Aranya = State<<Self::Engine as Engine>::CS>;
    type Store = MemStore;

    fn new() -> User<Self> {
        let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
        let afc = State::new();
        let aranya = afc.clone();
        let store = MemStore::new();
        User::new(eng, afc, aranya, store)
    }
}

test_all!(default_engine, DefaultImpl);