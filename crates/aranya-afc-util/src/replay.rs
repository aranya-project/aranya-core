//! Receiver-side replay protection for AFC control messages.

use core::fmt;

use aranya_crypto::{BaseId, DeviceId, policy::CmdId};

/// The default per-sender, per-epoch nonce cap.
pub const DEFAULT_NONCE_CAP: usize = 16_384;

/// Durable, receiver-side memory of accepted control messages.
///
/// Records are keyed by `(graph, sender)`. `graph` is the graph's
/// ID as a [`BaseId`].
///
/// Per `(graph, sender)` the store conceptually holds
/// `Record { epoch_max: u64, seen: Set<CmdId> }`, with an absent
/// record meaning `{ 0, ∅ }`.
pub trait ReplayStore {
    /// The error returned by the store.
    type Error: core::error::Error;

    /// Checks `(epoch, nonce)` for `(graph, sender)` and records
    /// it if fresh.
    ///
    /// A newer epoch resets the record; an unseen nonce at the
    /// current epoch is added, subject to the nonce cap. Anything
    /// else is rejected without mutating the store; see
    /// [`Verdict`] for the possible outcomes.
    ///
    /// The record MUST be durable before this returns
    /// `Ok(Verdict::Fresh)`.
    fn accept(
        &mut self,
        graph: BaseId,
        sender: DeviceId,
        epoch: u64,
        nonce: CmdId,
    ) -> Result<Verdict, Self::Error>;

    /// Raises the epoch floor for `(graph, sender)` to `epoch`,
    /// discarding recorded nonces from lower epochs.
    ///
    /// This is a no-op if the stored epoch is already
    /// `>= epoch`.
    fn raise_floor(
        &mut self,
        graph: BaseId,
        sender: DeviceId,
        epoch: u64,
    ) -> Result<(), Self::Error>;
}

impl<T: ReplayStore + ?Sized> ReplayStore for &mut T {
    type Error = T::Error;

    fn accept(
        &mut self,
        graph: BaseId,
        sender: DeviceId,
        epoch: u64,
        nonce: CmdId,
    ) -> Result<Verdict, Self::Error> {
        (**self).accept(graph, sender, epoch, nonce)
    }

    fn raise_floor(
        &mut self,
        graph: BaseId,
        sender: DeviceId,
        epoch: u64,
    ) -> Result<(), Self::Error> {
        (**self).raise_floor(graph, sender, epoch)
    }
}

/// The result of [`ReplayStore::accept`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Not seen before; now recorded.
    Fresh,
    /// `epoch` is below the stored high-water mark.
    StaleEpoch {
        /// The stored high-water mark.
        current: u64,
    },
    /// `epoch` equals the high-water mark and `nonce` was already
    /// recorded.
    Replay,
    /// The per-sender nonce cap for this epoch is exhausted. The
    /// sender must rotate its epoch before more channels are
    /// accepted.
    SenderMustRotate {
        /// The store's nonce cap.
        cap: usize,
    },
}

impl Verdict {
    /// Reports whether the verdict is [`Verdict::Fresh`].
    #[inline]
    pub const fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh)
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fresh => f.write_str("fresh"),
            Self::StaleEpoch { current } => write!(f, "stale epoch (current = {current})"),
            Self::Replay => f.write_str("replayed control message"),
            Self::SenderMustRotate { cap } => {
                write!(
                    f,
                    "nonce cap ({cap}) exhausted; sender must rotate its epoch"
                )
            }
        }
    }
}

#[cfg(any(test, feature = "testing"))]
mod memstore {
    extern crate alloc;

    use alloc::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };
    use core::convert::Infallible;

    use aranya_crypto::{BaseId, DeviceId, policy::CmdId};
    use spin::Mutex;

    use super::{DEFAULT_NONCE_CAP, ReplayStore, Verdict};

    /// A per-`(graph, sender)` record.
    #[derive(Clone, Debug, Default)]
    struct Record {
        epoch_max: u64,
        seen: BTreeSet<CmdId>,
    }

    #[derive(Debug)]
    struct Inner {
        cap: usize,
        records: BTreeMap<(BaseId, DeviceId), Record>,
    }

    /// An in-memory [`ReplayStore`].
    ///
    /// This is the fixture for the crate's tests and a template
    /// for a daemon's implementation. It is **not durable** and
    /// must not be used in production.
    ///
    /// Cloning a `MemStore` yields a handle to the same
    /// underlying state.
    #[derive(Clone, Debug)]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub struct MemStore {
        inner: Arc<Mutex<Inner>>,
    }

    impl Default for MemStore {
        fn default() -> Self {
            Self::new()
        }
    }

    impl MemStore {
        /// Creates a `MemStore` with [`DEFAULT_NONCE_CAP`].
        pub fn new() -> Self {
            Self::with_cap(DEFAULT_NONCE_CAP)
        }

        /// Creates a `MemStore` with a custom per-sender,
        /// per-epoch nonce cap.
        pub fn with_cap(cap: usize) -> Self {
            Self {
                inner: Arc::new(Mutex::new(Inner {
                    cap,
                    records: BTreeMap::new(),
                })),
            }
        }

        /// Returns the stored epoch high-water mark for `(graph,
        /// sender)`.
        pub fn epoch(&self, graph: BaseId, sender: DeviceId) -> u64 {
            self.inner
                .lock()
                .records
                .get(&(graph, sender))
                .map_or(0, |r| r.epoch_max)
        }

        /// Returns the number of nonces recorded for `(graph,
        /// sender)` in its current epoch.
        pub fn nonces(&self, graph: BaseId, sender: DeviceId) -> usize {
            self.inner
                .lock()
                .records
                .get(&(graph, sender))
                .map_or(0, |r| r.seen.len())
        }
    }

    impl ReplayStore for MemStore {
        type Error = Infallible;

        fn accept(
            &mut self,
            graph: BaseId,
            sender: DeviceId,
            epoch: u64,
            nonce: CmdId,
        ) -> Result<Verdict, Self::Error> {
            let mut inner = self.inner.lock();
            let cap = inner.cap;
            let rec = inner.records.entry((graph, sender)).or_default();

            if epoch > rec.epoch_max {
                rec.epoch_max = epoch;
                rec.seen.clear();
                rec.seen.insert(nonce);
                return Ok(Verdict::Fresh);
            }
            if epoch < rec.epoch_max {
                return Ok(Verdict::StaleEpoch {
                    current: rec.epoch_max,
                });
            }
            if rec.seen.contains(&nonce) {
                return Ok(Verdict::Replay);
            }
            if rec.seen.len() >= cap {
                return Ok(Verdict::SenderMustRotate { cap });
            }
            rec.seen.insert(nonce);
            Ok(Verdict::Fresh)
        }

        fn raise_floor(
            &mut self,
            graph: BaseId,
            sender: DeviceId,
            epoch: u64,
        ) -> Result<(), Self::Error> {
            let mut inner = self.inner.lock();
            let rec = inner.records.entry((graph, sender)).or_default();
            if epoch > rec.epoch_max {
                rec.epoch_max = epoch;
                rec.seen.clear();
            }
            Ok(())
        }
    }
}

#[cfg(any(test, feature = "testing"))]
#[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
pub use memstore::MemStore;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use aranya_crypto::{Rng, id::IdExt as _};

    use super::*;

    fn ids() -> (BaseId, DeviceId) {
        (BaseId::random(Rng), DeviceId::random(Rng))
    }

    #[test]
    fn test_accept_fresh_new_sender() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 0, n).unwrap(), Verdict::Fresh);
        assert_eq!(store.epoch(g, s), 0);
        assert_eq!(store.nonces(g, s), 1);
    }

    #[test]
    fn test_accept_higher_epoch_resets_seen() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n1 = CmdId::random(Rng);
        let n2 = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 1, n1).unwrap(), Verdict::Fresh);
        assert_eq!(store.accept(g, s, 1, n2).unwrap(), Verdict::Fresh);
        assert_eq!(store.nonces(g, s), 2);

        let n3 = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 5, n3).unwrap(), Verdict::Fresh);
        assert_eq!(store.epoch(g, s), 5);
        assert_eq!(store.nonces(g, s), 1);

        // Old nonces at the old epoch are now stale, not replays.
        assert_eq!(
            store.accept(g, s, 1, n1).unwrap(),
            Verdict::StaleEpoch { current: 5 }
        );
    }

    #[test]
    fn test_accept_same_epoch_new_nonce() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        for i in 0..10 {
            let n = CmdId::random(Rng);
            assert_eq!(store.accept(g, s, 3, n).unwrap(), Verdict::Fresh, "#{i}");
        }
        assert_eq!(store.nonces(g, s), 10);
    }

    #[test]
    fn test_accept_replay() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 3, n).unwrap(), Verdict::Fresh);
        assert_eq!(store.accept(g, s, 3, n).unwrap(), Verdict::Replay);
        assert_eq!(store.accept(g, s, 3, n).unwrap(), Verdict::Replay);
        assert_eq!(store.nonces(g, s), 1);
    }

    #[test]
    fn test_accept_cap_exhausted() {
        let (g, s) = ids();
        let mut store = MemStore::with_cap(2);
        let n1 = CmdId::random(Rng);
        let n2 = CmdId::random(Rng);
        let n3 = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 0, n1).unwrap(), Verdict::Fresh);
        assert_eq!(store.accept(g, s, 0, n2).unwrap(), Verdict::Fresh);
        assert_eq!(
            store.accept(g, s, 0, n3).unwrap(),
            Verdict::SenderMustRotate { cap: 2 }
        );
        // Replays of recorded nonces are still reported as such.
        assert_eq!(store.accept(g, s, 0, n1).unwrap(), Verdict::Replay);
        // Rotating clears the cap.
        assert_eq!(store.accept(g, s, 1, n3).unwrap(), Verdict::Fresh);
        assert_eq!(store.nonces(g, s), 1);
    }

    #[test]
    fn test_accept_stale_epoch() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 4, n).unwrap(), Verdict::Fresh);
        assert_eq!(
            store.accept(g, s, 3, CmdId::random(Rng)).unwrap(),
            Verdict::StaleEpoch { current: 4 }
        );
        assert_eq!(
            store.accept(g, s, 0, CmdId::random(Rng)).unwrap(),
            Verdict::StaleEpoch { current: 4 }
        );
        assert_eq!(store.nonces(g, s), 1);
    }

    #[test]
    fn test_raise_floor() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert_eq!(store.accept(g, s, 2, n).unwrap(), Verdict::Fresh);

        // Below: no-op.
        store.raise_floor(g, s, 1).unwrap();
        assert_eq!(store.epoch(g, s), 2);
        assert_eq!(store.nonces(g, s), 1);

        // Equal: no-op.
        store.raise_floor(g, s, 2).unwrap();
        assert_eq!(store.epoch(g, s), 2);
        assert_eq!(store.nonces(g, s), 1);

        // Above: raises and forgets.
        store.raise_floor(g, s, 3).unwrap();
        assert_eq!(store.epoch(g, s), 3);
        assert_eq!(store.nonces(g, s), 0);
        assert_eq!(
            store.accept(g, s, 2, n).unwrap(),
            Verdict::StaleEpoch { current: 3 }
        );
        assert_eq!(store.accept(g, s, 3, n).unwrap(), Verdict::Fresh);
    }

    #[test]
    fn test_records_are_independent() {
        let (g1, s1) = ids();
        let (g2, s2) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert_eq!(store.accept(g1, s1, 9, n).unwrap(), Verdict::Fresh);
        // Same nonce, different sender.
        assert_eq!(store.accept(g1, s2, 0, n).unwrap(), Verdict::Fresh);
        // Same nonce and sender, different graph.
        assert_eq!(store.accept(g2, s1, 0, n).unwrap(), Verdict::Fresh);
        assert_eq!(store.epoch(g1, s1), 9);
        assert_eq!(store.epoch(g1, s2), 0);
        assert_eq!(store.epoch(g2, s1), 0);
    }

    #[test]
    fn test_shared_handles() {
        let (g, s) = ids();
        let mut a = MemStore::new();
        let mut b = a.clone();
        let n = CmdId::random(Rng);
        assert_eq!(a.accept(g, s, 0, n).unwrap(), Verdict::Fresh);
        assert_eq!(b.accept(g, s, 0, n).unwrap(), Verdict::Replay);
    }
}
