use alloc::{collections::BTreeMap, vec::Vec};

use buggy::BugExt as _;
use tracing::trace;

use crate::{ClientError, Location, Prior, Segment as _, Storage, TraversalBuffer};

/// Returns the last common ancestor of two Locations.
///
/// This walks the graph backwards until the two locations meet. This
/// ensures that you can jump to the last common ancestor from
/// the merge command created using left and right and know that you
/// won't be jumping into a branch.
pub(super) fn last_common_ancestor<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
) -> Result<Location, ClientError> {
    trace!(%left, %right, "finding least common ancestor");
    let mut left = left;
    let mut right = right;
    while left != right {
        let left_seg = storage.get_segment(left)?;
        let right_seg = storage.get_segment(right)?;
        // The command with the lower max cut could be our least common ancestor
        // so we keeping following the command with the higher max cut until
        // both sides converge.
        if left.max_cut > right.max_cut {
            left = if let Some(previous) = left_seg.previous(left) {
                previous
            } else {
                match left_seg.prior() {
                    Prior::None => left,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        if let Some(l) = left_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *l
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok(left);
                        }
                    }
                }
            };
        } else {
            right = if let Some(previous) = right_seg.previous(right) {
                previous
            } else {
                match right_seg.prior() {
                    Prior::None => right,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        if let Some(r) = right_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *r
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok(right);
                        }
                    }
                }
            };
        }
    }
    Ok(left)
}

/// BFS pre-pass that identifies convergence points between two merge parents.
///
/// Walks backwards from `left` and `right` toward `lca` using the
/// `TraversalQueue` with `push_duplicate`/`pop_duplicates`. When multiple
/// paths reach the same location, its count indicates convergence.
fn compute_convergence<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
    lca: Location,
    buffer: &mut TraversalBuffer,
) -> Result<BTreeMap<Location, usize>, ClientError> {
    let mut convergence = BTreeMap::new();
    let queue = buffer.get();

    queue.push_duplicate(left)?;
    queue.push_duplicate(right)?;

    while let Some((loc, count)) = queue.pop_duplicates() {
        if loc.max_cut <= lca.max_cut {
            continue;
        }

        if count >= 2 {
            convergence.insert(loc, count);
        }

        // Expand priors — once per location regardless of count.
        let segment = storage.get_segment(loc)?;
        if let Some(previous) = segment.previous(loc) {
            queue.push_duplicate(previous)?;
        } else {
            for prior in segment.prior() {
                queue.push_duplicate(prior)?;
            }
        }
    }

    Ok(convergence)
}

/// Produces a deterministic ordering for a set of [`Command`]s in a graph.
///
/// The `lca` parameter is the last common ancestor of `left` and `right`.
/// A BFS pre-pass (`compute_convergence`) walks backwards from both merge
/// parents to identify convergence points — locations reachable from
/// multiple paths. During braiding, each prior location is checked against
/// the convergence map for O(1) ancestor detection, replacing the previous
/// O(k) `is_ancestor` BFS per strand.
pub(super) fn braid<S: Storage>(
    storage: &mut S,
    left: Location,
    right: Location,
    lca: Location,
    buffer: &mut TraversalBuffer,
) -> Result<Vec<Location>, ClientError> {
    use strand_heap::{Strand, StrandHeap};

    let mut braid = Vec::new();
    let mut strands = StrandHeap::new();

    trace!(%left, %right, %lca, "braiding");

    let mut convergence = compute_convergence(storage, left, right, lca, buffer)?;

    for head in [left, right] {
        strands.push(Strand::new(storage, head, None)?)?;
    }

    // Get latest command
    while let Some(strand) = strands.pop() {
        // Consume another command off the strand
        let (prior, mut maybe_cached_segment) =
            if let Some(previous) = strand.segment.previous(strand.next) {
                (Prior::Single(previous), Some(strand.segment))
            } else {
                (strand.segment.prior(), None)
            };
        if matches!(prior, Prior::Merge(..)) {
            trace!("skipping merge command at {}", strand.next);
        } else {
            trace!("adding {}", strand.next);
            braid.push(strand.next);
        }

        // Continue processing prior if not accessible from other strands.
        'location: for location in prior {
            // O(1) LCA skip: any prior at or below the outermost LCA
            // is shared by both branches — no need for further checks.
            if location.max_cut <= lca.max_cut {
                trace!("prior {location} at/below LCA (max_cut <= {}) skipping", lca.max_cut);
                continue 'location;
            }

            // Same-segment check (O(1) per strand).
            for other in strands.iter() {
                if location.same_segment(other.next) && location.max_cut <= other.next.max_cut {
                    trace!("prior {location} same segment as {}", other.next);
                    continue 'location;
                }
            }

            // Convergence count check (O(1)).
            if let Some(remaining) = convergence.get_mut(&location) {
                *remaining = remaining
                    .checked_sub(1)
                    .assume("convergence count must not underflow")?;
                if *remaining > 0 {
                    trace!("prior {location} convergence remaining={remaining}");
                    continue 'location;
                }
            }

            trace!("strand at {location}");
            strands.push(Strand::new(
                storage,
                location,
                // Taking is OK here because `maybe_cached_segment` is `Some` when
                // the current strand has a single parent that is in the same segment
                Option::take(&mut maybe_cached_segment),
            )?)?;
        }
        if let Some(strand) = strands.lone() {
            // No concurrency left, done.
            let next = strand.next;
            trace!("adding {next}");
            braid.push(next);
            break;
        }
    }

    braid.reverse();

    Ok(braid)
}

mod strand_heap {
    use heapless::binary_heap::Max;

    use crate::{
        storage::QUEUE_CAPACITY, ClientError, CmdId, Command as _, Location, Priority, Segment,
        Storage, StorageError,
    };

    /// Maximum number of active strands. Equal to `QUEUE_CAPACITY` since
    /// strand count is bounded by graph width, the same bound as the
    /// traversal queue.
    pub const STRAND_CAPACITY: usize = QUEUE_CAPACITY;

    pub struct Strand<S> {
        key: (Priority, CmdId),
        pub next: Location,
        pub segment: S,
    }

    impl<S: Segment> Strand<S> {
        pub fn new(
            storage: &mut impl Storage<Segment = S>,
            location: Location,
            cached_segment: Option<S>,
        ) -> Result<Self, ClientError> {
            let segment = cached_segment.map_or_else(|| storage.get_segment(location), Ok)?;

            let key = {
                let cmd = segment
                    .get_command(location)
                    .ok_or(StorageError::CommandOutOfBounds(location))?;
                (cmd.priority(), cmd.id())
            };

            Ok(Self {
                key,
                next: location,
                segment,
            })
        }
    }

    impl<S> Eq for Strand<S> {}
    impl<S> PartialEq for Strand<S> {
        fn eq(&self, other: &Self) -> bool {
            self.key == other.key
        }
    }
    impl<S> Ord for Strand<S> {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.key.cmp(&other.key).reverse()
        }
    }
    impl<S> PartialOrd for Strand<S> {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    /// A wrapper around a binary heap which is limited to one finalize command.
    pub struct StrandHeap<S> {
        heap: heapless::BinaryHeap<Strand<S>, Max, STRAND_CAPACITY>,
        /// Tracks whether there is a finalize command in `self.heap`.
        has_finalize: bool,
    }

    impl<S> StrandHeap<S> {
        pub const fn new() -> Self {
            Self {
                heap: heapless::BinaryHeap::new(),
                has_finalize: false,
            }
        }

        /// Adds another strand to the heap.
        ///
        /// Errors if it would add a second finalize command or the heap is full.
        pub fn push(&mut self, strand: Strand<S>) -> Result<(), ClientError> {
            if matches!(strand.key.0, Priority::Finalize) {
                if self.has_finalize {
                    return Err(ClientError::ParallelFinalize);
                }
                self.has_finalize = true;
            }
            self.heap
                .push(strand)
                .map_err(|_| StorageError::StrandHeapOverflow(STRAND_CAPACITY))?;
            Ok(())
        }

        /// Pop a strand from the heap.
        pub fn pop(&mut self) -> Option<Strand<S>> {
            let strand = self.heap.pop()?;
            if matches!(strand.key.0, Priority::Finalize) {
                debug_assert!(self.heap.is_empty());
                debug_assert!(self.has_finalize);
                self.has_finalize = false;
            }
            Some(strand)
        }

        /// Pops last strand when only one strand remains.
        pub fn lone(&mut self) -> Option<Strand<S>> {
            if self.heap.len() != 1 {
                return None;
            }
            self.has_finalize = false;
            let item = self.heap.pop();
            debug_assert!(item.is_some());
            item
        }

        pub fn iter(&self) -> impl Iterator<Item = &Strand<S>> {
            self.heap.iter()
        }
    }
}
