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

use self::lender::{Lender, Loan};
use crate::{
    ChannelDirection, LocalChannelId, RemoveIfParams,
    error::Error,
    mutex::StdMutex,
    state::{AfcState, AranyaState, Directed},
};

/// Shared channel data accessed by both sides of the state.
///
/// The aranya state needs all of these for `remove_if`, while the afc state
/// needs `label_id` for the seal/open operation.
#[derive(Debug)]
struct SharedChannelData {
    direction: ChannelDirection,
    label_id: LabelId,
    peer_id: DeviceId,
}

/// Exclusive state used for the seal/open operation.
///
/// We need mutable access to the seal key to update the sequence number.
#[derive_where(Debug)]
struct ExclusiveChannelData<CS: CipherSuite> {
    keys: Directed<SealKey<CS>, OpenKey<CS>>,
}

/// Seal channel context, passed in when sealing.
#[derive_where(Debug)]
pub struct SealCtx<CS: CipherSuite> {
    id: LocalChannelId,
    handle: Loan<SharedChannelData, ExclusiveChannelData<CS>>,
}

/// Open channel context, passed in when opening.
#[derive_where(Debug)]
pub struct OpenCtx<CS: CipherSuite> {
    id: LocalChannelId,
    handle: Loan<SharedChannelData, ExclusiveChannelData<CS>>,
}

#[derive_where(Debug, Default)]
struct Inner<CS: CipherSuite> {
    next_chan_id: u64,
    /// Map of data for each channel.
    ///
    /// We wrap the channel data in [`Lender`] so we can give out a [`Loan`]
    /// in the channel context, allowing the fast path direct access to the
    /// channel data after only an atomic load validity check.
    chans: BTreeMap<LocalChannelId, Lender<SharedChannelData, ExclusiveChannelData<CS>>>,
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
        // Find the channel for this ID.
        let val = inner.chans.get_mut(&id).ok_or(Error::NotFound(id))?;
        // Ensure this is a seal channel.
        if val.shared().direction != ChannelDirection::Seal {
            return Err(Error::NotFound(id));
        }
        // Loan out a handle to the channel data for fast access on later seal operations.
        // The caller is responsible to not call this twice, but we return an error here anyways.
        let handle = val.lend().ok_or(Error::NotFound(id))?;
        Ok(SealCtx { id, handle })
    }

    fn setup_open_ctx(&self, id: LocalChannelId) -> Result<Self::OpenCtx, Error> {
        let mut inner = self.inner.lock().assume("poisoned")?;
        // Find the channel for this ID.
        let val = inner.chans.get_mut(&id).ok_or(Error::NotFound(id))?;
        // Ensure this is an open channel.
        if val.shared().direction != ChannelDirection::Open {
            return Err(Error::NotFound(id));
        }
        // Loan out a handle to the channel data for fast access on later open operations.
        // The caller is responsible to not call this twice, but we return an error here anyways.
        let handle = val.lend().ok_or(Error::NotFound(id))?;
        Ok(OpenCtx { id, handle })
    }

    fn seal<F, T>(&self, ctx: &mut Self::SealCtx, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        // Load the channel data, failing if it was revoked.
        let (SharedChannelData { label_id, .. }, ExclusiveChannelData { keys, .. }) =
            ctx.handle.get_mut().ok_or(Error::NotFound(ctx.id))?;
        let key = keys.seal_mut().assume("seal context holds seal key")?;
        Ok(f(key, *label_id))
    }

    fn open<F, T>(&self, ctx: &mut Self::OpenCtx, f: F) -> Result<Result<T, Error>, Error>
    where
        F: FnOnce(&OpenKey<Self::CipherSuite>, LabelId) -> Result<T, Error>,
    {
        // Load the channel data, failing if it was revoked.
        let (SharedChannelData { label_id, .. }, ExclusiveChannelData { keys, .. }) =
            ctx.handle.get_mut().ok_or(Error::NotFound(ctx.id))?;
        let key = keys.open().assume("open context holds open key")?;
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
            Lender::new(
                SharedChannelData {
                    direction: keys.direction(),
                    label_id,
                    peer_id,
                },
                ExclusiveChannelData { keys },
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
                let &SharedChannelData {
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
