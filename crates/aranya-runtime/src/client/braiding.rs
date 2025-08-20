use alloc::vec::Vec;

use buggy::BugExt;
use tracing::trace;

use crate::{ClientError, Command, Location, Prior, Segment, Storage};

// Note: `strand_heap::ParallelFinalize` is not exposed. This impl is for convenience in `braid`.
impl From<strand_heap::ParallelFinalize> for ClientError {
    fn from(_: strand_heap::ParallelFinalize) -> Self {
        Self::ParallelFinalize
    }
}

/// Returns the last common ancestor of two Locations.
///
/// This walks the graph backwards until the two locations meet. This
/// ensures that you can jump to the last common ancestor from
/// the merge command created using left and right and know that you
/// won't be jumping into a branch.
pub(super) fn last_common_ancestor<S: Storage>(
    storage: &S,
    left: Location,
    right: Location,
) -> Result<(Location, usize), ClientError> {
    trace!(%left, %right, "finding least common ancestor");
    let mut left = left;
    let mut right = right;
    while left != right {
        let left_seg = storage.get_segment(left)?;
        let left_cmd = left_seg.get_command(left).assume("location must exist")?;
        let right_seg = storage.get_segment(right)?;
        let right_cmd = right_seg.get_command(right).assume("location must exist")?;
        // The command with the lower max cut could be our least common ancestor
        // so we keeping following the command with the higher max cut until
        // both sides converge.
        if left_cmd.max_cut()? > right_cmd.max_cut()? {
            left = if let Some(previous) = left.previous() {
                previous
            } else {
                match left_seg.prior() {
                    Prior::None => left,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        assert!(left.command == 0);
                        if let Some((l, _)) = left_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *l
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok((left, left_cmd.max_cut()?));
                        }
                    }
                }
            };
        } else {
            right = if let Some(previous) = right.previous() {
                previous
            } else {
                match right_seg.prior() {
                    Prior::None => right,
                    Prior::Single(s) => s,
                    Prior::Merge(_, _) => {
                        assert!(right.command == 0);
                        if let Some((r, _)) = right_seg.skip_list().last() {
                            // If the storage supports skip lists we return the
                            // last common ancestor of this command.
                            *r
                        } else {
                            // This case will only be hit if the storage doesn't
                            // support skip lists so we can return anything
                            // because it won't be used.
                            return Ok((right, right_cmd.max_cut()?));
                        }
                    }
                }
            };
        }
    }
    let left_seg = storage.get_segment(left)?;
    let left_cmd = left_seg.get_command(left).assume("location must exist")?;
    Ok((left, left_cmd.max_cut()?))
}

/// Produces a deterministic ordering for a set of [`Command`]s in a graph.
pub(super) fn braid<S: Storage>(
    storage: &S,
    left: Location,
    right: Location,
) -> Result<Vec<Location>, ClientError> {
    use strand_heap::{Strand, StrandHeap};

    let mut braid = Vec::new();
    let mut strands = StrandHeap::new();

    trace!(%left, %right, "braiding");

    for head in [left, right] {
        strands.push(Strand::new(storage, head, None)?)?;
    }

    // Get latest command
    while let Some(strand) = strands.pop() {
        // Consume another command off the strand
        let (prior, mut maybe_cached_segment) = if let Some(previous) = strand.next.previous() {
            (Prior::Single(previous), Some(strand.segment))
        } else {
            (strand.segment.prior(), None)
        };
        if matches!(prior, Prior::Merge(..)) {
            trace!("skipping merge command");
        } else {
            trace!("adding {}", strand.next);
            braid.push(strand.next);
        }

        // Continue processing prior if not accessible from other strands.
        'location: for location in prior {
            for other in strands.iter() {
                trace!("checking {}", other.next);
                if (location.same_segment(other.next) && location.command <= other.next.command)
                    || storage.is_ancestor(location, &other.segment)?
                {
                    trace!("found ancestor");
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
    use alloc::collections::BinaryHeap;

    use crate::{
        ClientError, Command, CommandId, Location, Priority, Segment, Storage, StorageError,
    };

    pub struct Strand<S> {
        key: (Priority, CommandId),
        pub next: Location,
        pub segment: S,
    }

    impl<S: Segment> Strand<S> {
        pub fn new(
            storage: &impl Storage<Segment = S>,
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
        heap: BinaryHeap<Strand<S>>,
        /// Tracks whether there is a finalize command in `self.heap`.
        has_finalize: bool,
    }

    pub struct ParallelFinalize;

    impl<S> StrandHeap<S> {
        pub const fn new() -> Self {
            Self {
                heap: BinaryHeap::new(),
                has_finalize: false,
            }
        }

        /// Adds another strand to the heap.
        ///
        /// Errors if it would add a second finalize command.
        pub fn push(&mut self, strand: Strand<S>) -> Result<(), ParallelFinalize> {
            if matches!(strand.key.0, Priority::Finalize) {
                if self.has_finalize {
                    return Err(ParallelFinalize);
                }
                self.has_finalize = true;
            }
            self.heap.push(strand);
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
