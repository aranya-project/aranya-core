use core::fmt::Debug;

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey},
    policy::LabelId,
};

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::State,
};
use crate::{
    shm::shared::index_from_id,
    state::{AfcState, LocalChannelId},
};

/// The reader's view of the shared memory state.
#[derive(Debug)]
pub struct ReadState<CS>
where
    CS: CipherSuite,
{
    // `pub(super)` for testing.
    pub(super) inner: State<CS>,
}

impl<CS> ReadState<CS>
where
    CS: CipherSuite,
{
    /// Open the state at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, max_chans: u32) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: State::open(path, flag, mode, max_chans)?,
        })
    }
}

impl<CS> AfcState for ReadState<CS>
where
    CS: CipherSuite + Sized,
{
    type CipherSuite = CS;

    fn seal<F, T>(&self, id: LocalChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, crate::Error>,
    {
        let mut chan = self
            .inner
            .shm()
            .arena()?
            .get(index_from_id(id))
            .ok_or(crate::Error::NotFound(id))?;

        let label_id = chan.label_id()?;
        let mut key = chan.seal_key()?;

        let result = f(&mut key, label_id);
        if likely!(result.is_ok()) {
            chan.set_seq(key.seq());
        }
        Ok(result)
    }

    fn open<F, T>(&self, id: LocalChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&OpenKey<CS>, LabelId) -> Result<T, crate::Error>,
    {
        let chan = self
            .inner
            .shm()
            .arena()?
            .get(index_from_id(id))
            .ok_or(crate::Error::NotFound(id))?;

        let label_id = chan.label_id()?;
        let key = chan.open_key()?;

        Ok(f(&key, label_id))
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, crate::Error> {
        Ok(self.inner.shm().arena()?.get(index_from_id(id)).is_some())
    }
}
