//! Memory implementation of State for same process APS usage

#![cfg(any(test, feature = "memory"))]
#![cfg_attr(docsrs, doc(cfg(feature = "memory")))]

extern crate alloc;

mod lender;

use alloc::{collections::btree_map::BTreeMap, sync::Arc};

use aranya_crypto::{
    CipherSuite, DeviceId,
    afc::{OpenKey, SealKey},
    policy::LabelId,
};
use buggy::BugExt as _;
use derive_where::derive_where;

use crate::{
    ChannelDirection, LocalChannelId, RemoveIfParams,
    error::Error,
    mutex::StdMutex,
    state::{AfcState, AranyaState, Directed},
};

#[derive(Debug)]
struct SharedValue {
    direction: ChannelDirection,
    label_id: LabelId,
    peer_id: DeviceId,
}

#[derive_where(Debug)]
struct ExclusiveValue<CS: CipherSuite> {
    keys: Directed<SealKey<CS>, OpenKey<CS>>,
}

/// Seal channel context.
#[derive_where(Debug)]
pub struct SealCtx<CS: CipherSuite> {
    id: LocalChannelId,
    handle: lender::Lent<SharedValue, ExclusiveValue<CS>>,
}

/// Open channel context.
#[derive_where(Debug)]
pub struct OpenCtx<CS: CipherSuite> {
    id: LocalChannelId,
    handle: lender::Lent<SharedValue, ExclusiveValue<CS>>,
}

#[derive_where(Debug, Default)]
struct Inner<CS: CipherSuite> {
    next_chan_id: u64,
    chans: BTreeMap<LocalChannelId, lender::Owner<SharedValue, ExclusiveValue<CS>>>,
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

    type SealCtx = SealCtx<CS>;

    type OpenCtx = OpenCtx<CS>;

    fn setup_seal_ctx(&self, id: LocalChannelId) -> Result<Self::SealCtx, Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        let val = inner.chans.get_mut(&id).ok_or(Error::NotFound(id))?;
        if val.shared().direction != ChannelDirection::Seal {
            return Err(Error::NotFound(id));
        }
        let handle = val.lend().ok_or(Error::NotFound(id))?;
        Ok(SealCtx { id, handle })
    }

    fn setup_open_ctx(&self, id: LocalChannelId) -> Result<Self::OpenCtx, Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        let val = inner.chans.get_mut(&id).ok_or(Error::NotFound(id))?;
        if val.shared().direction != ChannelDirection::Open {
            return Err(Error::NotFound(id));
        }
        let handle = val.lend().ok_or(Error::NotFound(id))?;
        Ok(OpenCtx { id, handle })
    }

    fn seal<F, T>(&self, ctx: &mut Self::SealCtx, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        let (SharedValue { label_id, .. }, ExclusiveValue { keys, .. }) =
            ctx.handle.get_mut().ok_or(Error::NotFound(ctx.id))?;
        let key = keys.seal_mut().ok_or(Error::NotFound(ctx.id))?;
        Ok(f(key, *label_id))
    }

    fn open<F, T>(&self, ctx: &mut Self::OpenCtx, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        let (SharedValue { label_id, .. }, ExclusiveValue { keys, .. }) =
            ctx.handle.get_mut().ok_or(Error::NotFound(ctx.id))?;
        let key = keys.open().ok_or(Error::NotFound(ctx.id))?;
        Ok(f(key, *label_id))
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, Error> {
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
        peer_id: DeviceId,
    ) -> Result<LocalChannelId, Self::Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        let id = LocalChannelId::new(inner.next_chan_id);
        inner.next_chan_id = inner
            .next_chan_id
            .checked_add(1)
            .assume("should not overflow")?;
        inner.chans.insert(
            id,
            lender::Owner::new(
                SharedValue {
                    direction: keys.direction(),
                    label_id,
                    peer_id,
                },
                ExclusiveValue { keys },
            ),
        );
        Ok(id)
    }

    fn remove(&self, id: LocalChannelId) -> Result<(), Self::Error> {
        self.inner.lock().assume("poisoned")?.chans.remove(&id);
        Ok(())
    }

    fn remove_all(&self) -> Result<(), Self::Error> {
        self.inner.lock().assume("poisoned")?.chans.clear();
        Ok(())
    }

    fn remove_if(&self, mut f: impl FnMut(RemoveIfParams) -> bool) -> Result<(), Self::Error> {
        self.inner
            .lock()
            .assume("poisoned")?
            .chans
            .retain(|&id, value| {
                let &SharedValue {
                    direction,
                    label_id,
                    peer_id,
                } = value.shared();
                !f(RemoveIfParams::new(id, label_id, peer_id, direction))
            });
        Ok(())
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, Self::Error> {
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
