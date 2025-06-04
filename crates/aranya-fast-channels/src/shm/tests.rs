#![cfg(test)]
#![allow(clippy::indexing_slicing, clippy::missing_panics_doc, clippy::panic)]

use aranya_crypto::{
    afc::{BidiKeys, RawOpenKey, RawSealKey, UniOpenKey, UniSealKey},
    hash::Hash,
    rust::Sha256,
    CipherSuite, Engine, Random, Rng,
};
use serial_test::serial;

use super::{
    shared::{Index, ShmChan},
    Flag, Mode, Path, ReadState, WriteState,
};
use crate::{
    state::{AranyaState, Channel, ChannelId, Directed, Label, NodeId},
    testing::{
        test_impl,
        util::{self, DummyAead, States, TestEngine, TestImpl},
    },
};

fn make_path(name: &str, id: NodeId) -> Box<Path> {
    let id = format!("{name}-{id}");
    let hash = &Sha256::hash(id.as_bytes())[..8];
    let path = format!("/{}\x00", hex::encode(hash));
    path.try_into().expect("should fit `Path`'s constraints")
}

/// A [`TestImpl`] that uses [`ReadState`] and [`WriteState`].
pub struct SharedMemImpl;

impl TestImpl for SharedMemImpl {
    type Afc<CS: CipherSuite> = ReadState<CS>;
    type Aranya<CS: CipherSuite> = WriteState<CS, Rng>;
    type Rng = Rng;

    fn new_states<CS: CipherSuite>(
        name: &str,
        id: NodeId,
        max_chans: usize,
    ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
        let path = make_path(name, id);
        let _ = super::unlink(&path);
        let aranya = WriteState::open(&path, Flag::Create, Mode::ReadWrite, max_chans, Rng)
            .expect("unable to create Aranya state");
        let afc = ReadState::open(&path, Flag::OpenOnly, Mode::ReadWrite, max_chans)
            .expect("unable to create APS state");
        States { afc, aranya }
    }

    fn convert_bidi_keys<CS: CipherSuite>(
        keys: BidiKeys<CS>,
    ) -> (
        <Self::Aranya<CS> as AranyaState>::SealKey,
        <Self::Aranya<CS> as AranyaState>::OpenKey,
    ) {
        keys.into_raw_keys()
    }

    fn convert_uni_seal_key<CS: CipherSuite>(
        key: UniSealKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::SealKey {
        key.into_raw_key()
    }

    fn convert_uni_open_key<CS: CipherSuite>(
        key: UniOpenKey<CS>,
    ) -> <Self::Aranya<CS> as AranyaState>::OpenKey {
        key.into_raw_key()
    }
}

test_impl!(#[serial], shm, SharedMemImpl);

/// Test adding many nodes.
#[test]
fn test_many_nodes() {
    const MAX_CHANS: usize = 101;

    let labels = [Label::new(0), Label::new(42)];

    type E = TestEngine<DummyAead>;

    let path = Path::from_bytes(b"/test_exhaustive\x00").unwrap();
    let _ = super::unlink(path);
    let aranya = WriteState::<<E as Engine>::CS, Rng>::open(
        path,
        Flag::Create,
        Mode::ReadWrite,
        MAX_CHANS * labels.len(),
        Rng,
    )
    .expect("unable to created shared memory");
    let afc = ReadState::<<E as Engine>::CS>::open(
        path,
        Flag::OpenOnly,
        Mode::ReadWrite,
        MAX_CHANS * labels.len(),
    )
    .expect("unable to created shared memory");

    // All the channels we've stored in the shared memory.
    let mut chans = Vec::with_capacity(MAX_CHANS * labels.len());

    let rng = &mut Rng;

    // NB: this is O(((n^2 + n)/2) * m) where n=MAX_CHANS
    // and m=len(labels).
    for label in labels {
        for i in 0..MAX_CHANS {
            let chan = Channel {
                id: ChannelId::new(NodeId::new(u32::try_from(i).unwrap()), label),
                keys: match util::rand_intn(&mut Rng, 3) {
                    0 => Directed::SealOnly {
                        seal: RawSealKey::random(rng),
                    },
                    1 => Directed::OpenOnly {
                        open: RawOpenKey::random(rng),
                    },
                    2 => Directed::Bidirectional {
                        seal: RawSealKey::random(rng),
                        open: RawOpenKey::random(rng),
                    },
                    v => unreachable!("{v}"),
                },
            };
            aranya
                .add(chan.id, chan.keys.clone())
                .unwrap_or_else(|err| panic!("unable to add node {i}: {err}"));
            chans.push(chan);

            // Now check that all previously added nodes
            // exist and are correct.
            for (j, want) in chans.iter().enumerate().by_ref() {
                let idx = Index(j);

                // Check with and without a hint.
                for hint in [None, Some(idx)] {
                    let id = want.id;

                    let (got, got_idx) = afc
                        .inner
                        .find_chan(id, hint)
                        .unwrap_or_else(|err| panic!("find_chan({id}, {hint:?}): {err}"))
                        .unwrap_or_else(|| panic!("find_chan({id}, {hint:?}) returned `None`"));

                    assert_eq!(got_idx, idx, "{idx:?}");

                    assert_eq!(got.magic, ShmChan::<<E as Engine>::CS>::MAGIC, "{idx:?}");

                    let got_id = got.id().unwrap_or_else(|err| {
                        panic!("unable to get channel for chan {idx:?}: {err}")
                    });
                    assert_eq!(got_id, want.id, "{idx:?}");

                    let got_secret = got
                        .keys()
                        .unwrap_or_else(|err| panic!("unable to get keys: {err}"));
                    assert_eq!(got_secret, want.keys.as_ref(), "{idx:?}");
                }
            }
        }
    }
}
