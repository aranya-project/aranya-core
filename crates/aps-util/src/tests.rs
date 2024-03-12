#![cfg(test)]

use aps::memory::State;
use crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Engine, Rng,
};

use crate::testing::{test_all, MemStore, TestImpl, User};

struct DefaultImpl;

impl TestImpl for DefaultImpl {
    type Engine = DefaultEngine<Rng, DefaultCipherSuite>;
    type Aps = State<<Self::Engine as Engine>::CS>;
    type Aranya = State<<Self::Engine as Engine>::CS>;
    type Store = MemStore;

    fn new() -> User<Self> {
        let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
        let aps = State::new();
        let aranya = aps.clone();
        let store = MemStore::new();
        User::new(eng, aps, aranya, store)
    }
}

test_all!(default_engine, DefaultImpl);
