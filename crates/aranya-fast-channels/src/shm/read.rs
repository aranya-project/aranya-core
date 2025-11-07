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
    SealChannelCtx,
    mutex::StdMutex,
    state::{AfcState, LocalChannelId},
    util::debug,
};

/// The key used for the recent successful invocation of `open`.
#[derive_where(Debug)]
struct OpenCache<CS: CipherSuite> {
    /// The channel the key is for.
    id: LocalChannelId,
    /// The label ID associated with the channel.
    label_id: LabelId,
    #[derive_where(skip)]
    /// The cached key.
    key: OpenKey<CS>,
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

    // APS is typically used to open many messages with the
    // same peer, so cache the most recent successful invocations
    // of open.
    last_open: StdMutex<Option<OpenCache<CS>>>,

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

        let label_id = ctx.label_id();

        let hint = match ctx.key_gen_mut() {
            // There is a cache entry for this channel.
            Some((key, ctx_generation)) => {
                // SAFETY: we only access an atomic field.
                let generation = unsafe {
                    mutex
                        .inner_unsynchronized()
                        .generation
                        .load(Ordering::Acquire)
                };
                if *ctx_generation == generation {
                    // Same generation, so we can use the key.
                    // so we can use it.
                    debug!("cache hit: id={id} generation={generation}");

                    return Ok(f(key, label_id));
                }
                // TODO(Steve): Add `Index` to `SealChannelCtx`.
                // The generations are different, so
                // optimistically use `idx` to try and speed up
                // the list traversal.
                None
            }
            _ => None,
        };

        // The list is currently locked (precluding writes to
        // `list.generation`), so we don't *need* atomics here. But we
        // might as well since relaxed is ~free.
        //
        // NB: we load the generation before traversing the list
        // to avoid ownership conflicts with `chan`.
        let generation = list.generation.load(Ordering::Relaxed);

        let (chan, _idx) = match list.find_mut(id, hint, Op::Seal)? {
            None => return Err(crate::Error::NotFound(id)),
            Some((chan, idx)) => (chan, idx),
        };

        let maybe_key_gen = ctx.key_gen_mut();
        let key_gen = match maybe_key_gen {
            None => {
                maybe_key_gen.insert((SealKey::from_raw(&chan.seal_key, Seq::ZERO)?, generation))
            }
            Some(key) => key,
        };

        debug!("chan = {chan:p}/{chan:?}");

        let result = f(&mut key_gen.0, label_id);
        Ok(result)
    }

    fn open<F, T>(&self, id: LocalChannelId, f: F) -> Result<Result<T, crate::Error>, crate::Error>
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
            *cache = Some(OpenCache {
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

    fn exists(&self, id: LocalChannelId) -> Result<bool, crate::Error> {
        let mutex = self.inner.load_read_list()?;
        let list = mutex.lock().assume("poisoned")?;
        Ok(list.exists(id, None, Op::Any)?)
    }
}
