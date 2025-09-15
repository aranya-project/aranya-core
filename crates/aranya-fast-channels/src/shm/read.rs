use core::{
    cell::Cell,
    fmt::Debug,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::atomic::Ordering,
};

use aranya_crypto::{
    CipherSuite,
    afc::{OpenKey, SealKey},
    policy::LabelId,
};
use buggy::{BugExt, bug};
use derive_where::derive_where;

use super::{
    error::Error,
    path::{Flag, Mode, Path},
    shared::{Index, KeyId, Op, State},
};
use crate::{
    mutex::StdMutex,
    state::{AfcState, ChannelId},
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
        let state = State::open(path, flag, mode, max_chans)?;
        if state.shm().increment_reader_count() > 0 {
            bug!("More than 1 reader shared memory handle open")
        }

        Ok(Self {
            inner: state,
            last_seal: StdMutex::new(None),
            last_open: StdMutex::new(None),
            _no_sync: PhantomData,
        })
    }
}

impl<CS: CipherSuite> Drop for ReadState<CS> {
    fn drop(&mut self) {
        let count = self.inner.shm().decrement_reader_count();
        if count <= 1 {
            self.inner.unmap();
        }
    }
}

impl<CS: CipherSuite> Clone for ReadState<CS> {
    fn clone(&self) -> Self {
        self.inner.shm().increment_reader_count();
        Self {
            inner: self.inner.clone(),
            last_seal: StdMutex::default(),
            last_open: StdMutex::default(),
            _no_sync: PhantomData,
        }
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
                    debug!(
                        "cache hit: id={id} generation={generation} seq={}",
                        c.key.seq()
                    );

                    return Ok(f(&mut c.key, c.label_id));
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
            // Encryption was successful (it usually is), so
            // update the cache.
            let new = Cache {
                id,
                label_id,
                key: CachedSealKey {
                    key,
                    id: chan.key_id,
                },
                generation,
                idx,
            };
            if let Some(old) = cache.replace(new) {
                // We've evicted an existing entry, so try to
                // write back the updated sequence number.
                if let Some((chan, _)) = list.find_mut(old.id, Some(old.idx), Op::Seal)? {
                    debug!(
                        "updating seq: chan = {chan:p}/{chan:?} old={} new={}",
                        chan.seq(),
                        old.key.seq()
                    );
                    if chan.key_id == old.key.id {
                        chan.set_seq(old.key.seq());
                    }
                }
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
