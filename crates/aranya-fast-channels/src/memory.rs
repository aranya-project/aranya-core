//! Memory implementation of State for same process APS usage

#![cfg(any(test, feature = "memory"))]
#![cfg_attr(docsrs, doc(cfg(feature = "memory")))]

extern crate alloc;

use alloc::{
    collections::btree_map::{BTreeMap, Entry},
    sync::Arc,
};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey},
    policy::LabelId,
};
use buggy::BugExt as _;
use derive_where::derive_where;

use crate::{
    ChannelId,
    error::Error,
    mutex::StdMutex,
    state::{AfcState, AranyaState, Directed},
};

#[derive_where(Debug, Default)]
struct Inner<CS: CipherSuite> {
    next_chan_id: u64,
    #[allow(clippy::type_complexity)]
    chans: BTreeMap<ChannelId, (Directed<SealKey<CS>, OpenKey<CS>>, LabelId)>,
}

/// An im-memory implementation of [`AfcState`] and
/// [`AranyaState`].
#[derive_where(Clone, Debug, Default)]
pub struct State<CS: CipherSuite> {
    inner: Arc<StdMutex<Inner<CS>>>,
}

impl<CS: CipherSuite> State<CS> {
    /// Creates a new `State`.
    pub fn new() -> Self {
        Self::default()
    }
}

impl<CS> AfcState for State<CS>
where
    CS: CipherSuite,
{
    type CipherSuite = CS;

    fn seal<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        let mut inner = self.inner.lock().assume("poisoned")?;
        let (key, chan_label_id) = inner.chans.get_mut(&id).ok_or(Error::NotFound(id))?;

        let key = key.seal_mut().ok_or(Error::NotFound(id))?;
        Ok(f(key, *chan_label_id))
    }

    fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        let inner = self.inner.lock().assume("poisoned")?;
        let (key, chan_label_id) = inner.chans.get(&id).ok_or(Error::NotFound(id))?;
        let key = key.open().ok_or(Error::NotFound(id))?;

        Ok(f(key, *chan_label_id))
    }

    fn exists(&self, id: ChannelId) -> Result<bool, Error> {
        Ok(self
            .inner
            .lock()
            .assume("poisoned")?
            .chans
            .contains_key(&id))
    }
}

impl<CS> AranyaState for State<CS>
where
    CS: CipherSuite,
{
    type CipherSuite = CS;

    type SealKey = SealKey<CS>;
    type OpenKey = OpenKey<CS>;
    type Error = Error;

    fn add(
        &self,
        keys: Directed<Self::SealKey, Self::OpenKey>,
        label_id: LabelId,
    ) -> Result<ChannelId, Self::Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        let id = ChannelId::new(inner.next_chan_id);
        inner.next_chan_id = inner
            .next_chan_id
            .checked_add(1)
            .assume("should not overflow")?;
        inner.chans.insert(id, (keys, label_id));
        Ok(id)
    }

    fn update(
        &self,
        id: ChannelId,
        keys: Directed<Self::SealKey, Self::OpenKey>,
        label_id: LabelId,
    ) -> Result<(), Self::Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        match inner.chans.entry(id) {
            Entry::Vacant(_) => return Err(Error::NotFound(id)),
            Entry::Occupied(mut e) => e.insert((keys, label_id)),
        };
        Ok(())
    }

    fn remove(&self, id: ChannelId) -> Result<(), Self::Error> {
        self.inner.lock().assume("poisoned")?.chans.remove(&id);
        Ok(())
    }

    fn remove_all(&self) -> Result<(), Self::Error> {
        self.inner.lock().assume("poisoned")?.chans.clear();
        Ok(())
    }

    fn remove_if(&self, mut f: impl FnMut(ChannelId, LabelId) -> bool) -> Result<(), Self::Error> {
        self.inner
            .lock()
            .assume("poisoned")?
            .chans
            .retain(|&id, (_keys, label_id)| !f(id, *label_id));
        Ok(())
    }

    fn exists(&self, id: ChannelId) -> Result<bool, Self::Error> {
        Ok(self
            .inner
            .lock()
            .assume("poisoned")?
            .chans
            .contains_key(&id))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use aranya_crypto::{
        Rng,
        afc::{UniOpenKey, UniSealKey},
    };

    use super::*;
    use crate::testing::{
        test_impl,
        util::{DeviceIdx, States, TestImpl},
    };

    /// A [`TestImpl`] that uses the memory state.
    struct MemoryImpl;

    impl TestImpl for MemoryImpl {
        type Afc<CS: CipherSuite> = State<CS>;
        type Aranya<CS: CipherSuite> = State<CS>;
        type Rng = Rng;

        fn new_states<CS: CipherSuite>(
            _name: &str,
            _id: DeviceIdx,
            _max_chans: usize,
        ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
            let afc = State::<CS>::new();
            let aranya = afc.clone();
            States { afc, aranya }
        }

        fn convert_uni_seal_key<CS: CipherSuite>(
            key: UniSealKey<CS>,
        ) -> <Self::Aranya<CS> as AranyaState>::SealKey {
            key.into_key().expect("should be able to create `SealKey`")
        }

        fn convert_uni_open_key<CS: CipherSuite>(
            key: UniOpenKey<CS>,
        ) -> <Self::Aranya<CS> as AranyaState>::OpenKey {
            key.into_key().expect("should be able to create `OpenKey`")
        }
    }

    test_impl!(mem, MemoryImpl);
}
