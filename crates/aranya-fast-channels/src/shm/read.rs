use core::{cell::Cell, fmt::Debug, marker::PhantomData, sync::atomic::Ordering};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey},
    policy::LabelId,
};
use buggy::BugExt;
use derive_where::derive_where;

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::{Index, Op, State},
};
use crate::{
    mutex::StdMutex,
    state::{AfcState, ChannelId},
    util::debug,
};

/// The cache used for the recent successful invocation of `seal`
/// or `open`.
#[derive(Clone)]
#[derive_where(Debug)]
struct Cache<K> {
    /// The channel the key is for.
    id: ChannelId,
    /// The label ID associated with the channel.
    label_id: LabelId,
    #[derive_where(skip)]
    /// The type of key this cache is for.
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
///
/// # Notes
///
/// Dropping a `ReadState` instance and its clones will not unmap
/// the shared memory object.
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
    last_seal: StdMutex<Option<Cache<NotSealKey<CS>>>>,
    last_open: StdMutex<Option<Cache<OpenKey<CS>>>>,

    /// Make `State` `!Sync` pending issues/95.
    _no_sync: PhantomData<Cell<()>>,
}

impl<CS: CipherSuite> Clone for ReadState<CS> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            last_seal: StdMutex::default(),
            last_open: StdMutex::default(),
            _no_sync: PhantomData,
        }
    }
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

    fn seal<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        // Check to see if the current `SealKey` for this channel
        // is cached.
        let mut cache = self.last_seal.lock().assume("poisoned")?;
        let (hint, update_cache) = match cache.as_mut().filter(|c| c.id == id) {
            // There is a cache entry for this channel.
            Some(c) => {
                // SAFETY: we only access an atomic field.
                let generation = unsafe {
                    mutex
                        .inner_unsynchronized()
                        .generation
                        .load(Ordering::Acquire)
                };
                let replace = if c.generation == generation {
                    // Same generation, so we can use the index and not update the cache.
                    debug!("cache hit: id={id} generation={generation}");

                    false
                } else {
                    true
                };
                // If the generations are different, we
                // optimistically use `idx` to try and speed up
                // the list traversal.
                // If they're the same then looking up the channel with `idx` should be O(1).
                (Some(c.idx), replace)
            }
            _ => (None, true),
        };

        let mut list = mutex.lock().assume("poisoned")?;

        // The list is currently locked (precluding writes to
        // `list.generation`), so we don't *need* atomics here. But we
        // might as well since relaxed is ~free.
        //
        // NB: we load the generation before traversing the list
        // to avoid ownership conflicts with `chan`.
        let generation = list.generation.load(Ordering::Relaxed);

        let (chan, idx) = match list.find_mut(id, hint, Op::Seal)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };

        let mut key = SealKey::from_raw(&chan.seal_key, chan.seq())?;

        debug!("chan = {chan:p}/{chan:?}");

        let label_id = chan.label_id;

        let result = f(&mut key, label_id);
        if likely!(result.is_ok()) {
            debug!(
                "updating seq: chan = {chan:p}/{chan:?} old={} new={}",
                chan.seq(),
                key.seq()
            );
            // Update the channel with the new sequence number.
            chan.set_seq(key.seq());

            if update_cache {
                // Encryption was successful (it usually is) and `update_cache` is true, so
                // update the cache.
                let new = Cache {
                    id,
                    // TODO: Seal operations don't use the label ID from the cache. Consider adding a separate type without this field.
                    label_id,
                    key: PhantomData,
                    generation,
                    idx,
                };
                let _ = cache.replace(new);
            }
        }
        Ok(result)
    }

    fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&OpenKey<CS>, LabelId) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        // Check to see if the current `OpenKey` for this channel
        // is cached.
        let mut cache = self.last_open.lock().assume("poisoned")?;
        let hint = match cache.as_mut().filter(|c| c.id == id) {
            // There is a cache entry for this channel.
            Some(c) => {
                // SAFETY: we only access an atomic field.
                let generation = unsafe {
                    mutex
                        .inner_unsynchronized()
                        .generation
                        .load(Ordering::Acquire)
                };
                if c.generation == generation {
                    // Same generation, so we can use the key.
                    // so we can use it.
                    debug!("cache hit: id={id} generation={generation}");

                    return Ok(f(&c.key, c.label_id));
                }
                // The generations are different, so
                // optimistically use `idx` to try and speed up
                // the list traversal.
                Some(c.idx)
            }
            _ => None,
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
            *cache = Some(Cache {
                id,
                label_id,
                key,
                // The list is currently locked (precluding
                // writes to `list.generation`), so we don't *need*
                // atomics here. But we might as well since
                // relaxed is ~free.
                generation: list.generation.load(Ordering::Relaxed),
                idx,
            });
        }
        Ok(result)
    }

    fn exists(&self, id: ChannelId) -> Result<bool, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let list = mutex.lock().assume("poisoned")?;
        Ok(list.exists(id, None, Op::Any)?)
    }
}

type NotSealKey<CS> = PhantomData<SealKey<CS>>;
