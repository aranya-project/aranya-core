use core::{cell::Cell, marker::PhantomData};

use aranya_crypto::{
    CipherSuite, Csprng, DeviceId,
    afc::{RawOpenKey, RawSealKey},
    policy::LabelId,
};

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::{ShmChan, State},
};
#[allow(unused_imports)]
use crate::features::*;
use crate::{
    RemoveIfParams,
    state::{AranyaState, Directed, LocalChannelId},
};

/// The writer's view of the shared memory state.
#[derive(Debug)]
pub struct WriteState<CS: CipherSuite, R> {
    inner: State<CS>,
    rng: R,

    /// Make `State` `!Sync` pending issues/95.
    _no_sync: PhantomData<Cell<()>>,
}

impl<CS, R> WriteState<CS, R>
where
    CS: CipherSuite,
    R: Csprng,
{
    /// Open the state at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, max_chans: u32, rng: R) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: State::open(path, flag, mode, max_chans)?,
            rng,
            _no_sync: PhantomData,
        })
    }
}

impl<CS, R> AranyaState for WriteState<CS, R>
where
    CS: CipherSuite,
    R: Csprng,
{
    type CipherSuite = CS;
    type SealKey = RawSealKey<CS>;
    type OpenKey = RawOpenKey<CS>;
    type Error = Error;

    fn add(
        &self,
        keys: Directed<Self::SealKey, Self::OpenKey>,
        label_id: LabelId,
        peer_id: DeviceId,
    ) -> Result<LocalChannelId, Error> {
        let idx = self
            .inner
            .shm()
            .arena()?
            .add(ShmChan::new(label_id, peer_id, &keys, &self.rng))
            .map_err(|_| Error::OutOfSpace)?; // TODO: More precise?

        Ok(idx.into())
    }

    fn remove(&self, id: LocalChannelId) -> Result<(), Error> {
        self.inner
            .shm()
            .arena()?
            .remove(id.into())
            .map_err(|_| Error::NotFound(id)) // TODO: More precise?
    }

    fn remove_all(&self) -> Result<(), Self::Error> {
        self.inner
            .shm()
            .arena()?
            .clear()
            .map_err(|_| -> Error { todo!() })?;
        Ok(())
    }

    fn remove_if(&self, mut f: impl FnMut(RemoveIfParams) -> bool) -> Result<(), Self::Error> {
        self.inner
            .shm()
            .arena()?
            .retain(|idx, chan| match chan.remove_if_params(idx) {
                Ok(params) => !f(params),
                Err(_corrupted) => true,
            })
            .map_err(|_| -> Error { todo!() })?;
        Ok(())
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, Self::Error> {
        Ok(self.inner.shm().arena()?.get(id.into()).is_some())
    }
}
