use core::{cell::Cell, fmt::Debug, marker::PhantomData};

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
    OpenCtx as _, OpenCtxImpl, SealCtx, SealCtxImpl,
    state::{self, AfcState, ChannelId},
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
    type SealCtx = SealCtxImpl<Self::CipherSuite>;
    type OpenCtx = OpenCtxImpl<Self::CipherSuite>;

    fn seal<F, T>(
        &self,
        ctx: &mut Self::SealCtx,
        f: F,
    ) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        let label_id = ctx.label_id();
        let key = match ctx.seal_key() {
            Some(key) => key,
            None => {
                // We don't have a cached key, so we need to traverse the
                // list.
                let mut list = mutex.lock().assume("poisoned")?;

                let id = ctx.channel_id();

                let (chan, idx) = match list.find_mut(id, None, Op::Seal)? {
                    None => return Err(crate::Error::NotFound(id)),
                    Some((chan, idx)) => (chan, idx),
                };

                debug!("chan = {chan:p}/{chan:?}");

                // Assume the seq number starts at 0 if there isn't a key already cached
                let key = SealKey::from_raw(&chan.seal_key, Seq::ZERO)?;

                ctx.set_seal_key(key, state::private::Internal);

                // SAFETY: Assumes the implementation of `SealCtx`` sets the key to `Some`
                unsafe { ctx.seal_key().unwrap_unchecked() }
            }
        };

        let result = f(key, label_id);
        Ok(result)
    }

    fn open<F, T>(
        &self,
        ctx: &mut Self::OpenCtx,
        f: F,
    ) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&OpenKey<CS>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        // Check to see if the current `OpenKey` for this channel
        // is cached.
        let label_id = ctx.label_id();
        let key = match ctx.open_key() {
            Some(key) => key,
            None => {
                // We don't have a cached key, so we need to traverse the
                // list.
                let mut list = mutex.lock().assume("poisoned")?;

                let id = ctx.channel_id();

                let (chan, idx) = match list.find_mut(id, None, Op::Seal)? {
                    None => return Err(crate::Error::NotFound(id)),
                    Some((chan, idx)) => (chan, idx),
                };

                debug!("chan = {chan:p}/{chan:?}");

                // Assume the seq number starts at 0 if there isn't a key already cached
                let key = OpenKey::from_raw(&chan.open_key)?;

                ctx.set_open_key(key, state::private::Internal);

                // SAFETY: Assumes the implementation of `SealCtx`` sets the key to `Some`
                unsafe { ctx.open_key().unwrap_unchecked() }
            }
        };

        let result = f(&key, label_id);
        Ok(result)
    }

    fn exists(&self, id: ChannelId) -> Result<bool, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let list = mutex.lock().assume("poisoned")?;
        Ok(list.exists(id, None, Op::Any)?)
    }
}
