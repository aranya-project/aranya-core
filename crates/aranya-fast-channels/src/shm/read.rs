use core::{
    cell::Cell,
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey, Seq},
    policy::LabelId,
};
use buggy::BugExt as _;
use derive_where::derive_where;

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::{Index, KeyId, Op, State},
};
use crate::{
    OpenCtx as _, OpenCtxImpl, SealCtx, SealCtxImpl,
    mutex::StdMutex,
    state::{self, AfcState, ChannelId},
    util::debug,
};

/// The key used for the recent successful invocation of `seal`
/// or `open`.
#[derive(Clone)]
#[derive_where(Debug)]
struct Cache<K> {
    /// The channel the key is for.
    id: ChannelId,
    /// The label ID associated with the channel.
    label_id: LabelId,
    #[derive_where(skip)]
    /// The cached key.
    key: K,
    /// The `ChanList`'s generation when this key was cached.
    ///
    /// Used to quickly determine whether the cache is stale.
    generation: u32,
    /// Index of the channel in the `ChanList`.
    ///
    /// Used as a hint when retrieving the updated channel
    /// information after the `ChanList`'s generation has
    /// changed.
    idx: Index,
}

/// The reader's view of the shared memory state.
#[derive(Debug)]
pub struct ReadState<CS>
where
    CS: CipherSuite,
{
    // `pub(super)` for testing.
    pub(super) inner: State<CS>,

    // APS is typically used to seal/open many messages with the
    // same peer, so cache the most recent successful invocations
    // of seal/open.
    last_seal: StdMutex<Option<Cache<CachedSealKey<CS>>>>,
    last_open: StdMutex<Option<Cache<OpenKey<CS>>>>,

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
            last_seal: StdMutex::new(None),
            last_open: StdMutex::new(None),
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

struct CachedSealKey<CS: CipherSuite> {
    key: SealKey<CS>,
    id: KeyId,
}

impl<CS: CipherSuite> Deref for CachedSealKey<CS> {
    type Target = SealKey<CS>;
    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl<CS: CipherSuite> DerefMut for CachedSealKey<CS> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.key
    }
}
