use core::{cell::Cell, fmt::Debug, marker::PhantomData, sync::atomic::Ordering};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey, Seq},
    policy::LabelId,
};
use buggy::BugExt as _;

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::{Op, State},
};
use crate::{
    ctx::{OpenChannelCtx, SealChannelCtx},
    state::{AfcState, LocalChannelId},
    util::debug,
};

/// The reader's view of the shared memory state.
#[derive(Debug)]
pub struct ReadState<CS>
where
    CS: CipherSuite,
{
    // `pub(super)` for testing.
    pub(super) inner: State<CS>,

    /// Make `State` `!Sync` pending issues/95.
    _no_sync: PhantomData<Cell<()>>,
}

impl<CS> ReadState<CS>
where
    CS: CipherSuite,
{
    /// Open the state at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, max_chans: usize) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: State::open(path, flag, mode, max_chans)?,
            _no_sync: PhantomData,
        })
    }
}

impl<CS> AfcState for ReadState<CS>
where
    CS: CipherSuite + Sized,
{
    type CipherSuite = CS;

    fn seal<F, T>(
        &self,
        id: LocalChannelId,
        ctx: &mut SealChannelCtx<Self::CipherSuite>,
        f: F,
    ) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        let mut list = mutex.lock().assume("poisoned")?;

        // The list is currently locked (precluding writes to
        // `list.generation`), so we don't *need* atomics here. But we
        // might as well since relaxed is ~free.
        //
        // NB: we load the generation before traversing the list
        // to avoid ownership conflicts with `chan`.
        let _generation = list.generation.load(Ordering::Relaxed);

        // TODO: Don't eagerly search list. Compare to generation
        let (chan, _idx) = match list.find_mut(id, None, Op::Seal)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };

        let label_id = *ctx.label_id();
        let maybe_key = ctx.seal_mut()?;
        let mut key = match maybe_key {
            None => maybe_key.insert(SealKey::from_raw(&chan.seal_key, Seq::ZERO)?),
            Some(key) => key,
        };

        debug!("chan = {chan:p}/{chan:?}");

        let result = f(&mut key, label_id);
        Ok(result)
    }

    fn open<F, T>(
        &self,
        id: LocalChannelId,
        ctx: &mut OpenChannelCtx<Self::CipherSuite>,
        f: F,
    ) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&OpenKey<CS>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        let list = mutex.lock().assume("poisoned")?;

        // TODO: Don't eagerly search list. Compare to generation
        let (chan, _idx) = match list.find(id, None, Op::Open)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };

        let label_id = *ctx.label_id();
        let maybe_key = ctx.open_mut()?;
        let key = match maybe_key {
            None => maybe_key.insert(OpenKey::from_raw(&chan.open_key)?),
            Some(key) => key,
        };

        let result = f(&key, label_id);
        Ok(result)
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let list = mutex.lock().assume("poisoned")?;
        Ok(list.exists(id, None, Op::Any)?)
    }
}
