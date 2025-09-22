use core::{cell::Cell, marker::PhantomData, ops::DerefMut, sync::atomic::Ordering};

use aranya_crypto::{
    CipherSuite, Csprng,
    afc::{RawOpenKey, RawSealKey},
    policy::LabelId,
};
use buggy::BugExt;

use super::{
    error::{Corrupted, Error, corrupted},
    path::{Flag, Mode, Path},
    shared::{ShmChan, State},
};
#[allow(unused_imports)]
use crate::features::*;
use crate::{
    mutex::StdMutex,
    shm::shared::Op,
    state::{AranyaState, ChannelId, Directed},
    util::debug,
};

/// The writer's view of the shared memory state.
#[derive(Debug)]
pub struct WriteState<CS, R> {
    inner: State<CS>,
    rng: StdMutex<R>,

    /// Make `State` `!Sync` pending issues/95.
    _no_sync: PhantomData<Cell<()>>,
}

impl<CS, R> WriteState<CS, R>
where
    CS: CipherSuite,
    R: Csprng,
{
    /// Open the state at `path`.
    pub fn open<P>(path: P, flag: Flag, mode: Mode, max_chans: usize, rng: R) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            inner: State::open(path, flag, mode, max_chans)?,
            rng: StdMutex::new(rng),
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
    ) -> Result<ChannelId, Error> {
        let mut rng = self.rng.lock().assume("poisoned")?;

        let id = {
            // NB: This cannot reasonably overflow.
            let next = self.inner.shm().next_chan_id.fetch_add(1, Ordering::SeqCst);
            ChannelId::new(next)
        };

        let (write_off, idx) = {
            let off = self.inner.write_off(self.inner.shm())?;
            // Load state after loading the write offset because
            // of borrowing rules.
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;

            if side.len >= side.cap {
                // We're out of space.
                return Err(Error::OutOfSpace);
            }

            let idx = usize::try_from(side.len)
                .map_err(|_| corrupted("`side.len` larger than `usize::MAX`"))?;
            let chan = side.raw_at(idx)?;
            debug!("adding chan {id} at {idx}");

            ShmChan::<CS>::init(chan, id, label_id, &keys, rng.deref_mut());

            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("write side generation={}", generation + 1);

            // We've updated the generation and the channel, so
            // we're now free to grow the list.
            side.len += 1;
            assert!(side.len <= side.cap);
            debug!("write side len={}", side.len);

            (off, idx)
        };

        let read_off = {
            // Swap the pointers: the reader will now see the
            // updated list.
            let off = self.inner.swap_offsets(self.inner.shm(), write_off)?;
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;

            ShmChan::<CS>::init(side.raw_at(idx)?, id, label_id, &keys, rng.deref_mut());

            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("read side generation={}", generation + 1);

            // We've updated the generation and the channel, so
            // we're now free to grow the list.
            side.len += 1;
            assert!(side.len <= side.cap);
            debug!("read side len={}", side.len);

            off
        };

        self.inner
            .shm()
            .write_off
            .store(read_off.into(), Ordering::SeqCst);

        Ok(id)
    }

    fn update(
        &self,
        id: ChannelId,
        keys: Directed<Self::SealKey, Self::OpenKey>,
        label_id: LabelId,
    ) -> Result<(), Error> {
        let mut rng = self.rng.lock().assume("poisoned")?;

        let (write_off, idx) = {
            let off = self.inner.write_off(self.inner.shm())?;
            // Load state after loading the write offset because
            // of borrowing rules.
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;

            let (idx, chan) = match side
                .try_iter_mut()?
                .enumerate()
                .try_find(|(_, chan)| Ok::<bool, Corrupted>(chan.id()? == id))?
            {
                Some((i, chan)) => (i, chan.as_uninit_mut()),
                None => return Err(Error::NotFound(id)),
            };
            debug!("adding chan {id} at {idx}");

            ShmChan::<CS>::init(chan, id, label_id, &keys, rng.deref_mut());

            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("write side generation={}", generation + 1);

            (off, idx)
        };

        let read_off = {
            // Swap the pointers: the reader will now see the
            // updated list.
            let off = self.inner.swap_offsets(self.inner.shm(), write_off)?;
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;

            ShmChan::<CS>::init(side.raw_at(idx)?, id, label_id, &keys, rng.deref_mut());

            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("read side generation={}", generation + 1);

            off
        };

        self.inner
            .shm()
            .write_off
            .store(read_off.into(), Ordering::SeqCst);

        Ok(())
    }

    fn remove(&self, id: ChannelId) -> Result<(), Error> {
        let (write_off, idx) = {
            let off = self.inner.write_off(self.inner.shm())?;
            // Load state after loading the write offset because
            // borrowing rules.
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;
            if side.len == 0 {
                return Ok(());
            }

            let idx = match side
                .try_iter_mut()?
                .enumerate()
                .try_find(|(_, chan)| Ok::<bool, Corrupted>(chan.id()? == id))?
            {
                Some((i, _)) => i,
                // The channel wasn't found.
                None => return Ok(()),
            };
            debug!("removing chan at {idx}");

            // As a precaution, update the generation before we
            // do anything else.
            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("write side generation={}", generation + 1);

            // side[i] = side[side.len-1]
            side.swap_remove(idx)?;
            debug!("write side len={}", side.len);

            (off, idx)
        };

        let read_off = {
            // Swap the pointers: the reader will now see the
            // updated list.
            let off = self.inner.swap_offsets(self.inner.shm(), write_off)?;
            let mut side = self.inner.shm().side(off)?.lock().assume("poisoned")?;

            // As a precaution, update the generation before we
            // do anything else.
            let generation = side.generation.fetch_add(1, Ordering::AcqRel);
            debug!("read side generation={}", generation + 1);

            // side[i] = side[side.len-1]
            side.swap_remove(idx)?;
            debug!("read side len={}", side.len);

            off
        };

        self.inner
            .shm()
            .write_off
            .store(read_off.into(), Ordering::SeqCst);

        Ok(())
    }

    fn remove_all(&self) -> Result<(), Self::Error> {
        let shm = self.inner.shm();

        let write_off = {
            let off = self.inner.write_off(shm)?;
            shm.side(off)?.lock().assume("poisoned")?.clear();
            off
        };

        let read_off = {
            // Swap the pointers: the reader will now see the
            // updated list.
            let off = self.inner.swap_offsets(shm, write_off)?;
            shm.side(off)?.lock().assume("poisoned")?.clear();
            off
        };

        shm.write_off.store(read_off.into(), Ordering::SeqCst);

        Ok(())
    }

    fn remove_if(&self, mut f: impl FnMut(ChannelId) -> bool) -> Result<(), Self::Error> {
        let shm = self.inner.shm();

        let write_off = {
            let off = self.inner.write_off(shm)?;
            // Load state after loading the write offset because
            // borrowing rules.
            let mut side = shm.side(off)?.lock().assume("poisoned")?;
            if side.len == 0 {
                return Ok(());
            }
            side.remove_if(&mut f)?;
            off
        };

        let read_off = {
            // Swap the pointers: the reader will now see the
            // updated list.
            let off = self.inner.swap_offsets(shm, write_off)?;
            let mut side = shm.side(off)?.lock().assume("poisoned")?;

            // It's only possible to get here if `side.len > 0`.
            debug_assert!(side.len > 0);

            side.remove_if(&mut f)?;

            off
        };

        shm.write_off.store(read_off.into(), Ordering::SeqCst);

        Ok(())
    }

    fn exists(&self, id: ChannelId) -> Result<bool, Self::Error> {
        let mutex = self.inner.load_write_list()?;
        let list = mutex.lock().assume("poisoned")?;
        list.exists(id, None, Op::Any)
    }
}
