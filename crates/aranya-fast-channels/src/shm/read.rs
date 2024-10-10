use core::{cell::Cell, marker::PhantomData, sync::atomic::Ordering};

use aranya_buggy::BugExt;
use aranya_crypto::{
    afc::{OpenKey, SealKey},
    CipherSuite,
};

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

/// The key used for the recent successful invocation of `seal`
/// or `open`.
#[derive(Clone)]
struct Cache<K> {
    /// The channel the key is for.
    id: ChannelId,
    /// The cached key.
    key: K,
    /// The `ChanList`'s generation when this key was cached.
    ///
    /// Used to quickly determine whether the cache is stale.
    gen: u32,
    /// Index of the channel in the `ChanList`.
    ///
    /// Used as a hint when retrieving the updated channel
    /// information after the `ChanList`'s generation has
    /// changed.
    idx: Index,
}

/// The reader's view of the shared memory state.
pub struct ReadState<CS>
where
    CS: CipherSuite,
{
    // `pub(super)` for testing.
    pub(super) inner: State<CS>,

    // APS is typically used to seal/open many messages with the
    // same peer, so cache the most recent successful invocations
    // of seal/open.
    last_seal: StdMutex<Option<Cache<SealKey<CS>>>>,
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

    fn seal<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&mut SealKey<Self::CipherSuite>) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        // Check to see if the current `SealKey` for this channel
        // is cached.
        let mut cache = self.last_seal.lock().assume("poisoned")?;
        let hint = match cache.as_mut().filter(|c| c.id == id) {
            // There is a cache entry for this channel.
            Some(c) => {
                // SAFETY: we only access an atomic field.
                let gen = unsafe { mutex.inner_unsynchronized().gen.load(Ordering::Acquire) };
                if c.gen == gen {
                    // Same generation, so we can use the key.
                    debug!("cache hit: id={id} gen={gen}");

                    return Ok(f(&mut c.key));
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
        // `list.gen`), so we don't *need* atomics here. But we
        // might as well since relaxed is ~free.
        //
        // NB: we load the generation before traversing the list
        // to avoid ownership conflicts with `chan`.
        let gen = list.gen.load(Ordering::Relaxed);

        let (chan, idx) = match list.find_mut(id, hint, Op::Seal)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };
        let mut key = SealKey::from_raw(&chan.seal_key, chan.seq())?;

        let result = f(&mut key);
        if likely!(result.is_ok()) {
            // Encryption was successful (it usually is), so
            // update the cache.
            let new = Cache { id, key, gen, idx };
            if let Some(old) = cache.replace(new) {
                // We've evicted an existing entry, so write back
                // the updated sequence number.
                chan.set_seq(old.key.seq());
            }
        }
        Ok(result)
    }

    fn open<F, T>(&self, id: ChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
    where
        F: FnOnce(&OpenKey<CS>) -> Result<T, crate::Error>,
    {
        let mutex = self.inner.load_read_list()?;

        // Check to see if the current `OpenKey` for this channel
        // is cached.
        let mut cache = self.last_open.lock().assume("poisoned")?;
        let hint = match cache.as_mut().filter(|c| c.id == id) {
            // There is a cache entry for this channel.
            Some(c) => {
                // SAFETY: we only access an atomic field.
                let gen = unsafe { mutex.inner_unsynchronized().gen.load(Ordering::Acquire) };
                if c.gen == gen {
                    // Same generation, so we can use the key.
                    // so we can use it.
                    debug!("cache hit: id={id} gen={gen}");

                    return Ok(f(&c.key));
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

        let result = f(&key);
        if result.is_ok() {
            // Decryption was successful, so update the cache.
            *cache = Some(Cache {
                id,
                key,
                // The list is currently locked (precluding
                // writes to `list.gen`), so we don't *need*
                // atomics here. But we might as well since
                // relaxed is ~free.
                gen: list.gen.load(Ordering::Relaxed),
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