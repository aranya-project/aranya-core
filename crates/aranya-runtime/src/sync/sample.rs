//! Builds the sample of command addresses carried by a sync request, and by
//! a sync reply whose uncovered region does not fit in one reply. See
//! `aranya-docs/docs/sync-sampling.md`.

use alloc::vec;

use aranya_crypto::Csprng;
use buggy::{Bug, BugExt as _};
use heapless::Vec;

use super::{COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, SyncError};
use crate::{
    Address, Prior,
    storage::{LocatedAddress, Location, MaxCut, Segment as _, Storage},
};

/// Heads get at most this many slots. The rest are reserved for random
/// commands.
const HEADS_MAX: usize = COMMAND_SAMPLE_MAX / 2;

/// Returns a uniformly random value in `0..n`.
fn random_below(rng: &impl Csprng, n: u64) -> Result<u64, Bug> {
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    u64::from_le_bytes(bytes)
        .checked_rem(n)
        .assume("n must be nonzero")
}

/// Returns a uniformly random index into a collection of length `len`.
pub(super) fn random_index(rng: &impl Csprng, len: usize) -> Result<usize, Bug> {
    let i = random_below(rng, len as u64)?;
    usize::try_from(i).assume("index fits in usize")
}

/// Walk back from `start` toward max cut `target`, which must not be above
/// `start`.
///
/// Takes the lowest skip-list entry at or above `target` when one exists,
/// otherwise steps to a prior. At a merge with no usable skip, `at_merge`
/// is given the parents with max cut at least `target` and the merge's LCA,
/// and returns where to continue, or `None` to stop there.
///
/// Returns the command at `target` when the walk reaches the segment that
/// contains it, or the first location at or below `target` that `at_merge`
/// leads to. If `at_merge` stops the walk, returns the merge's location.
pub(super) fn skip_jump<S: Storage>(
    storage: &S,
    start: Location,
    target: MaxCut,
    mut at_merge: impl FnMut(&[Location], Location) -> Result<Option<Location>, SyncError>,
) -> Result<Location, SyncError> {
    if start.max_cut < target {
        buggy::bug!("skip_jump target is above start");
    }
    let mut current = start;
    loop {
        if current.max_cut <= target {
            return Ok(current);
        }
        let seg = storage.get_segment(current)?;
        if seg.shortest_max_cut() <= target {
            return Ok(Location::new(current.segment, target));
        }

        let best = seg
            .skip_list()
            .iter()
            .copied()
            .filter(|s| s.max_cut >= target && s.max_cut < current.max_cut)
            .min_by_key(|s| s.max_cut);
        if let Some(skip) = best {
            current = skip;
            continue;
        }

        // The segment starts above `target`, so its higher parent is at or
        // above it: a merge's max cut is one more than its higher parent.
        current = match seg.prior() {
            Prior::None => buggy::bug!("root segment starts above target"),
            Prior::Single(p) => p,
            Prior::Merge(a, b) => {
                let mut parents: Vec<Location, 2> = Vec::new();
                for p in [a, b] {
                    if p.max_cut >= target {
                        parents.push(p).ok().assume("at most two parents")?;
                    }
                }
                let lca = seg
                    .skip_list()
                    .last()
                    .copied()
                    .assume("merge skip list must end with LCA")?;
                match at_merge(&parents, lca)? {
                    Some(p) => p,
                    None => return Ok(current),
                }
            }
        };
    }
}

/// Returns the floor for a peer whose cache holds `cache_heads`: a command
/// the peer holds such that everything we hold below it is one of its
/// ancestors.
///
/// Walks back from the heads' LCA to the highest command at or below the
/// lowest cache head. Every point on that walk is a command all heads pass
/// through, so every path to a cache head passes through the floor.
pub(super) fn floor<S: Storage>(
    storage: &S,
    cache_heads: &[LocatedAddress],
) -> Result<MaxCut, SyncError> {
    let Some(lowest) = cache_heads.iter().map(|h| h.max_cut).min() else {
        return Ok(MaxCut::new(0));
    };
    let lca = storage.get_heads()?.lca();
    if lca.max_cut <= lowest {
        return Ok(lca.max_cut);
    }
    let floor = skip_jump(storage, lca, lowest, |_, merge_lca| Ok(Some(merge_lca)))?;
    Ok(floor.max_cut)
}

/// Builds a sample over `storage`.
///
/// `head_groups` are added first, in order, into at most half the slots.
/// A group that does not fit in the remaining head slots contributes a
/// random subset that fills them. The remaining slots hold random commands:
/// commands at evenly spaced max cuts from the tallest head down to
/// `floor`, each reached from a random head tall enough to reach it. Random
/// commands for which `exclude` returns true are dropped.
pub(super) fn build<S: Storage>(
    storage: &S,
    head_groups: &[&[Address]],
    floor: MaxCut,
    rng: &impl Csprng,
    exclude: impl Fn(Address) -> bool,
) -> Result<Vec<Address, COMMAND_SAMPLE_MAX>, SyncError> {
    let mut sample: Vec<Address, COMMAND_SAMPLE_MAX> = Vec::new();

    // Heads.
    for group in head_groups {
        let room = HEADS_MAX.saturating_sub(sample.len());
        let mut group: vec::Vec<Address> = group
            .iter()
            .copied()
            .filter(|a| !sample.contains(a))
            .collect();
        if group.len() > room {
            // Partial Fisher-Yates: the first `room` entries become a
            // uniformly random subset.
            for i in 0..room {
                let rest = group.len().checked_sub(i).assume("i < len")?;
                let j = i
                    .checked_add(random_index(rng, rest)?)
                    .assume("index mustn't overflow")?;
                group.swap(i, j);
            }
            group.truncate(room);
        }
        for head in group {
            sample.push(head).ok().assume("heads fit in sample")?;
        }
    }

    let heads: vec::Vec<Location> = storage
        .get_heads()?
        .iter()
        .map(LocatedAddress::location)
        .collect();
    let Some(top) = heads.iter().map(|h| h.max_cut).max() else {
        return Ok(sample);
    };

    // Gap.
    let free = COMMAND_SAMPLE_MAX
        .checked_sub(sample.len())
        .assume("sample is not overfull")? as u64;
    if free == 0 {
        return Ok(sample);
    }
    let span = top.get().saturating_sub(floor.get());
    let gap = span.div_ceil(free).max(COMMAND_RESPONSE_MAX as u64);

    // Offset, uniform in gap/2..=gap.
    let half = gap.div_ceil(2);
    let width = gap
        .checked_sub(half)
        .and_then(|w| w.checked_add(1))
        .assume("offset range is nonempty")?;
    let offset = half
        .checked_add(random_below(rng, width)?)
        .assume("offset mustn't overflow")?;

    // Random commands.
    let mut position = top.get().checked_sub(offset);
    while let Some(t) = position.filter(|&t| t > floor.get()) {
        if sample.is_full() {
            break;
        }
        let target = MaxCut::new(t);
        let eligible = heads.iter().filter(|h| h.max_cut >= target).count();
        let pick = random_index(rng, eligible)?;
        let head = heads
            .iter()
            .filter(|h| h.max_cut >= target)
            .nth(pick)
            .copied()
            .assume("picked an eligible head")?;
        let location = skip_jump(storage, head, target, |parents, _| {
            Ok(Some(
                *parents
                    .get(random_index(rng, parents.len())?)
                    .assume("index in range")?,
            ))
        })?;
        let address = storage.get_command_address(location)?;
        if !exclude(address) && !sample.contains(&address) {
            sample.push(address).ok().assume("sample is not full")?;
        }
        position = t.checked_sub(gap);
    }

    Ok(sample)
}
