//! Memory implementation of State for same process APS usage

#![cfg(any(test, feature = "memory"))]
#![cfg_attr(docsrs, doc(cfg(feature = "memory")))]

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};

use aranya_crypto::{
    afc::{OpenKey, SealKey},
    CipherSuite,
};
use buggy::{Bug, BugExt};

use crate::{
    error::Error,
    mutex::StdMutex,
    state::{AfcState, AranyaState, ChannelId, Directed},
};

/// An im-memory implementation of [`AfcState`] and
/// [`AranyaState`].
pub struct State<CS: CipherSuite> {
    #[allow(clippy::type_complexity)]
    chans: Arc<StdMutex<BTreeMap<ChannelId, Directed<SealKey<CS>, OpenKey<CS>>>>>,
}

impl<CS: CipherSuite> Clone for State<CS> {
    fn clone(&self) -> Self {
        State {
            chans: self.chans.clone(),
        }
    }
}

impl<CS: CipherSuite> Default for State<CS> {
    fn default() -> Self {
        Self {
            chans: Arc::default(),
        }
    }
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
        F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, Error>,
    {
        let mut chans = self.chans.lock().assume("poisoned")?;
        let key = chans
            .get_mut(&id)
            .ok_or(Error::NotFound(id))?
            .seal_mut()
            .ok_or(Error::NotFound(id))?;
        Ok(f(key))
    }

    fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>) -> Result<T, Error>,
    {
        let chans = self.chans.lock().assume("poisoned")?;
        let key = chans
            .get(&id)
            .ok_or(Error::NotFound(id))?
            .open()
            .ok_or(Error::NotFound(id))?;
        Ok(f(key))
    }

    fn exists(&self, id: ChannelId) -> Result<bool, Error> {
        Ok(self.chans.lock().assume("poisoned")?.contains_key(&id))
    }
}

impl<CS> AranyaState for State<CS>
where
    CS: CipherSuite,
{
    type CipherSuite = CS;

    type SealKey = SealKey<CS>;
    type OpenKey = OpenKey<CS>;
    type Error = Bug;

    fn add(
        &self,
        id: ChannelId,
        keys: Directed<Self::SealKey, Self::OpenKey>,
    ) -> Result<(), Self::Error> {
        self.chans.lock().assume("poisoned")?.insert(id, keys);
        Ok(())
    }

    fn remove(&self, id: ChannelId) -> Result<(), Self::Error> {
        self.chans.lock().assume("poisoned")?.remove(&id);
        Ok(())
    }

    fn remove_all(&self) -> Result<(), Self::Error> {
        self.chans.lock().assume("poisoned")?.clear();
        Ok(())
    }

    fn remove_if(&self, mut f: impl FnMut(ChannelId) -> bool) -> Result<(), Self::Error> {
        self.chans
            .lock()
            .assume("poisoned")?
            .retain(|&id, _| !f(id));
        Ok(())
    }

    fn exists(&self, id: ChannelId) -> Result<bool, Self::Error> {
        Ok(self.chans.lock().assume("poisoned")?.contains_key(&id))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use aranya_crypto::{
        afc::{BidiKeys, UniOpenKey, UniSealKey},
        Rng,
    };

    use super::*;
    use crate::{
        state::NodeId,
        testing::{
            test_impl,
            util::{States, TestImpl},
        },
    };

    /// A [`TestImpl`] that uses the memory state.
    struct MemoryImpl;

    impl TestImpl for MemoryImpl {
        type Afc<CS: CipherSuite> = State<CS>;
        type Aranya<CS: CipherSuite> = State<CS>;
        type Rng = Rng;

        fn new_states<CS: CipherSuite>(
            _name: &str,
            _id: NodeId,
            _max_chans: usize,
        ) -> States<Self::Afc<CS>, Self::Aranya<CS>> {
            let afc = State::<CS>::new();
            let aranya = afc.clone();
            States { afc, aranya }
        }

        fn convert_bidi_keys<CS: CipherSuite>(
            keys: BidiKeys<CS>,
        ) -> (
            <Self::Aranya<CS> as AranyaState>::SealKey,
            <Self::Aranya<CS> as AranyaState>::OpenKey,
        ) {
            let (seal, open) = keys
                .into_keys()
                .expect("should be able to create `SealKey` and `OpenKey`");
            (seal, open)
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
