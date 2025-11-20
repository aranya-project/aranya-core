use core::{cell::Cell, fmt::Debug, marker::PhantomData, sync::atomic::Ordering};

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
    shared::{Index, Op, State},
};
use crate::{
    mutex::StdMutex,
    state::{AfcState, LocalChannelId},
    util::debug,
};

/// The key used for the recent successful invocation of `seal`
/// or `open`.
#[derive(Clone)]
#[derive_where(Debug)]
struct Cache<K> {
    /// The channel the key is for.
    id: LocalChannelId,
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
            last_open: StdMutex::new(None),
            _no_sync: PhantomData,
        })
    }
}

/// Sealing channel context.
pub struct SealCtx<CS: CipherSuite>(Option<Cache<SealKey<CS>>>);

/// Opening channel context.
pub struct OpenCtx<CS: CipherSuite>(Option<Cache<OpenKey<CS>>>);

impl<CS> AfcState for ReadState<CS>
where
    CS: CipherSuite + Sized,
{
    type CipherSuite = CS;

    type SealCtx = SealCtx<CS>;

    type OpenCtx = OpenCtx<CS>;

    fn setup_seal_ctx(&self, id: LocalChannelId) -> Result<Self::SealCtx, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let mut list = mutex.lock().assume("poisoned")?;

        let generation = list.generation.load(Ordering::Relaxed);

        let (chan, idx) = match list.find_mut(id, None, Op::Seal)? {
            None => {
                return Err(crate::Error::NotFound(id));
            }
            Some((chan, idx)) => (chan, idx),
        };

        let key = SealKey::from_raw(&chan.seal_key, Seq::ZERO)?;
        Ok(SealCtx(Some(Cache {
            id,
            label_id: chan.label_id,
            key,
            generation,
            idx,
        })))
    }

    fn setup_open_ctx(&self, id: LocalChannelId) -> Result<Self::OpenCtx, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let mut list = mutex.lock().assume("poisoned")?;

        let generation = list.generation.load(Ordering::Relaxed);

        let (chan, idx) = match list.find_mut(id, None, Op::Open)? {
            None => {
                return Err(crate::Error::NotFound(id));
            }
            Some((chan, idx)) => (chan, idx),
        };

        let key = OpenKey::from_raw(&chan.open_key)?;
        Ok(OpenCtx(Some(Cache {
            id,
            label_id: chan.label_id,
            key,
            generation,
            idx,
        })))
    }

    fn seal<F, T>(
        &self,
        ctx: &mut Self::SealCtx,
        f: F,
    ) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, crate::Error>,
    {
        let cache = ctx.0.as_mut().ok_or(crate::Error::KeyExpired)?;

        let id = cache.id;

        let mutex = self.inner.load_read_list()?;

        let hint = {
            // SAFETY: we only access an atomic field.
            let generation = unsafe {
                mutex
                    .inner_unsynchronized()
                    .generation
                    .load(Ordering::Acquire)
            };
            if cache.generation == generation {
                // Same generation, so we can use the key.
                debug!(
                    "cache hit: id={id} generation={generation} seq={}",
                    cache.key.seq()
                );

                return Ok(f(&mut cache.key, cache.label_id));
            }
            // The generations are different, so
            // optimistically use `idx` to try and speed up
            // the list traversal.
            Some(cache.idx)
        };

        // We don't have a cached key, so we need to traverse the
        // list.
        let mut list = mutex.lock().assume("poisoned")?;

        // The list is currently locked (precluding writes to
        // `list.generation`), so we don't *need* atomics here. But we
        // might as well since relaxed is ~free.
        //
        // NB: we load the generation before traversing the list
        // to avoid ownership conflicts with `chan`.
        let generation = list.generation.load(Ordering::Relaxed);

        let (chan, idx) = match list.find_mut(id, hint, Op::Seal)? {
            None => {
                *ctx = SealCtx(None);
                return Err(crate::Error::NotFound(id));
            }
            Some((chan, idx)) => (chan, idx),
        };

        let mut key = SealKey::from_raw(&chan.seal_key, cache.key.seq())?;

        debug!("chan = {chan:p}/{chan:?}");

        let label_id = chan.label_id;

        let result = f(&mut key, label_id);
        if likely!(result.is_ok()) {
            // Encryption was successful (it usually is), so
            // update the cache.
            cache.idx = idx;
            cache.generation = generation;
            cache.key = key;
        }
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
        let cache = ctx.0.as_mut().ok_or(crate::Error::KeyExpired)?;

        let id = cache.id;

        let mutex = self.inner.load_read_list()?;

        let hint = {
            // SAFETY: we only access an atomic field.
            let generation = unsafe {
                mutex
                    .inner_unsynchronized()
                    .generation
                    .load(Ordering::Acquire)
            };
            if cache.generation == generation {
                // Same generation, so we can use the key.
                debug!("cache hit: id={id} generation={generation}");

                return Ok(f(&cache.key, cache.label_id));
            }
            // The generations are different, so
            // optimistically use `idx` to try and speed up
            // the list traversal.
            Some(cache.idx)
        };

        // We don't have a cached key, so we need to traverse the
        // list.
        let list = mutex.lock().assume("poisoned")?;

        let (chan, idx) = match list.find(id, hint, Op::Open)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };

        let key = OpenKey::from_raw(&chan.open_key)?;
        let label_id = chan.label_id;

        let result = f(&key, label_id);
        if result.is_ok() {
            // Decryption was successful, so update the cache.
            cache.idx = idx;
            cache.generation = list.generation.load(Ordering::Relaxed);
            cache.key = key;
        }
        Ok(result)
    }

    fn exists(&self, id: LocalChannelId) -> Result<bool, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let list = mutex.lock().assume("poisoned")?;
        Ok(list.exists(id, None, Op::Any)?)
    }
}
