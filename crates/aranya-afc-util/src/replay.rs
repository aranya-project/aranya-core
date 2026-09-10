//! Receiver-side memory of accepted AFC control-message nonces.
//!
//! A [`ReplayStore`] remembers which control messages a receiver
//! has already accepted so that a captured message cannot be
//! delivered twice.

use aranya_crypto::{BaseId, DeviceId, policy::CmdId};

/// Durable, receiver-side memory of accepted control-message
/// nonces.
///
/// Records are keyed by `(graph, sender, epoch)`. `graph` is the
/// graph's ID as a [`BaseId`].
pub trait ReplayStore {
    /// The error returned by the store.
    type Error: core::error::Error;

    /// Records `nonce` as accepted for `(graph, sender, epoch)`.
    ///
    /// Returns `Ok(true)` if the nonce was not already recorded
    /// and has now been stored, or `Ok(false)` if it was already
    /// present (a replay). Nothing is modified when this returns
    /// `Ok(false)`.
    ///
    /// The record MUST be durable before this returns `Ok(true)`.
    fn insert(
        &mut self,
        graph: BaseId,
        sender: DeviceId,
        epoch: u64,
        nonce: CmdId,
    ) -> Result<bool, Self::Error>;

    /// Forgets every nonce recorded for `(graph, sender)` at
    /// epochs strictly below `epoch`. Nonces at `epoch` or above
    /// are kept.
    ///
    /// This is a no-op if nothing is recorded below `epoch`.
    fn clear(&mut self, graph: BaseId, sender: DeviceId, epoch: u64) -> Result<(), Self::Error>;
}

#[cfg(any(test, feature = "testing"))]
mod memstore {
    extern crate alloc;

    use alloc::collections::{BTreeMap, BTreeSet};
    use core::convert::Infallible;

    use aranya_crypto::{BaseId, DeviceId, policy::CmdId};

    use super::ReplayStore;

    /// An in-memory [`ReplayStore`].
    ///
    /// This is the fixture for the crate's tests and a template
    /// for a daemon's implementation. It is **not durable** and
    /// must not be used in production.
    #[derive(Debug, Default)]
    #[cfg_attr(docsrs, doc(cfg(feature = "testing")))]
    pub struct MemStore {
        /// `(graph, sender)` → epoch → nonces.
        records: BTreeMap<(BaseId, DeviceId), BTreeMap<u64, BTreeSet<CmdId>>>,
    }

    impl MemStore {
        /// Creates an empty `MemStore`.
        pub const fn new() -> Self {
            Self {
                records: BTreeMap::new(),
            }
        }

        /// Returns the number of nonces recorded for `(graph,
        /// sender)` across all epochs.
        pub fn nonces(&self, graph: BaseId, sender: DeviceId) -> usize {
            self.records
                .get(&(graph, sender))
                .map_or(0, |by_epoch| by_epoch.values().map(BTreeSet::len).sum())
        }
    }

    impl ReplayStore for MemStore {
        type Error = Infallible;

        fn insert(
            &mut self,
            graph: BaseId,
            sender: DeviceId,
            epoch: u64,
            nonce: CmdId,
        ) -> Result<bool, Self::Error> {
            Ok(self
                .records
                .entry((graph, sender))
                .or_default()
                .entry(epoch)
                .or_default()
                .insert(nonce))
        }

        fn clear(
            &mut self,
            graph: BaseId,
            sender: DeviceId,
            epoch: u64,
        ) -> Result<(), Self::Error> {
            if let Some(by_epoch) = self.records.get_mut(&(graph, sender)) {
                // `split_off` keeps everything `>= epoch`.
                *by_epoch = by_epoch.split_off(&epoch);
                if by_epoch.is_empty() {
                    self.records.remove(&(graph, sender));
                }
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
    fn test_insert_fresh_then_replay() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert!(store.insert(g, s, 0, n).unwrap());
        assert!(!store.insert(g, s, 0, n).unwrap());
        assert!(!store.insert(g, s, 0, n).unwrap());
        assert_eq!(store.nonces(g, s), 1);
    }

    #[test]
    fn test_same_nonce_different_epochs_are_independent() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert!(store.insert(g, s, 1, n).unwrap());
        assert!(store.insert(g, s, 2, n).unwrap());
        assert!(!store.insert(g, s, 1, n).unwrap());
        assert!(!store.insert(g, s, 2, n).unwrap());
        assert_eq!(store.nonces(g, s), 2);
    }

    #[test]
    fn test_insert_does_not_order_epochs() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        assert!(store.insert(g, s, 5, CmdId::random(Rng)).unwrap());
        // An older epoch is still recorded; rejecting it is the
        // policy rule's job.
        assert!(store.insert(g, s, 1, CmdId::random(Rng)).unwrap());
        assert_eq!(store.nonces(g, s), 2);
    }

    #[test]
    fn test_clear_drops_lower_epochs_only() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n0 = CmdId::random(Rng);
        let n1 = CmdId::random(Rng);
        let n2 = CmdId::random(Rng);
        assert!(store.insert(g, s, 0, n0).unwrap());
        assert!(store.insert(g, s, 1, n1).unwrap());
        assert!(store.insert(g, s, 2, n2).unwrap());
        assert_eq!(store.nonces(g, s), 3);

        store.clear(g, s, 2).unwrap();
        assert_eq!(store.nonces(g, s), 1);
        // Epoch 2 survived...
        assert!(!store.insert(g, s, 2, n2).unwrap());
        // ...epochs 0 and 1 were forgotten.
        assert!(store.insert(g, s, 0, n0).unwrap());
        assert!(store.insert(g, s, 1, n1).unwrap());
        assert_eq!(store.nonces(g, s), 3);

        store.clear(g, s, 5).unwrap();
        assert_eq!(store.nonces(g, s), 0);
    }

    #[test]
    fn test_clear_equal_is_noop() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert!(store.insert(g, s, 3, n).unwrap());
        store.clear(g, s, 3).unwrap();
        assert_eq!(store.nonces(g, s), 1);
        assert!(!store.insert(g, s, 3, n).unwrap());
    }

    #[test]
    fn test_clear_unknown_sender() {
        let (g, s) = ids();
        let mut store = MemStore::new();
        store.clear(g, s, 7).unwrap();
        assert_eq!(store.nonces(g, s), 0);
    }

    #[test]
    fn test_records_are_independent() {
        let (g1, s1) = ids();
        let (g2, s2) = ids();
        let mut store = MemStore::new();
        let n = CmdId::random(Rng);
        assert!(store.insert(g1, s1, 0, n).unwrap());
        // Same nonce, different sender.
        assert!(store.insert(g1, s2, 0, n).unwrap());
        // Same nonce and sender, different graph.
        assert!(store.insert(g2, s1, 0, n).unwrap());
        // Clearing one record leaves the others alone.
        store.clear(g1, s1, 1).unwrap();
        assert_eq!(store.nonces(g1, s1), 0);
        assert_eq!(store.nonces(g1, s2), 1);
        assert_eq!(store.nonces(g2, s1), 1);
    }
}
