#![cfg(test)]
#![allow(clippy::indexing_slicing, clippy::missing_panics_doc, clippy::panic)]

use aranya_crypto::{
    CipherSuite, DeviceId, Engine, Random as _, Rng,
    afc::{RawOpenKey, RawSealKey, UniOpenKey, UniSealKey},
    dangerous::spideroak_crypto::{hash::Hash as _, rust::Sha256},
    id::IdExt as _,
    policy::LabelId,
};
use serial_test::serial;

use super::{
    Flag, Mode, Path, ReadState, WriteState,
    shared::{Index, ShmChan},
};
use crate::{
    state::{AranyaState, Channel, Directed},
    testing::{
        test_impl,
        util::{self, DeviceIdx, DummyAead, States, TestEngine, TestImpl},
    },
};

fn make_path(name: &str, id: DeviceIdx) -> Box<Path> {
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
        id: DeviceIdx,
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

    let labels = [LabelId::random(&mut Rng), LabelId::random(&mut Rng)];

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
    let og_afc = ReadState::<<E as Engine>::CS>::open(
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
    for label_id in labels {
        for idx in 0..MAX_CHANS {
            let keys = match util::rand_intn(&mut Rng, 2) {
                0 => Directed::SealOnly {
                    seal: RawSealKey::random(rng),
                },
                1 => Directed::OpenOnly {
                    open: RawOpenKey::random(rng),
                },
                v => unreachable!("{v}"),
            };
            let id = aranya
                .add(keys.clone(), label_id, DeviceId::random(&mut Rng))
                .unwrap_or_else(|err| panic!("unable to add channel {idx}: {err}"));
            let chan = Channel { id, keys, label_id };
            chans.push((chan, og_afc.clone()));

            // Now check that all previously added nodes
            // exist and are correct.
            for (j, (want, afc)) in chans.iter().enumerate().by_ref() {
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
