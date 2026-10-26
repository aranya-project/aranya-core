//! Builds the sample of command addresses carried by a sync request, and by
//! a sync reply whose uncovered region does not fit in one reply. See
//! `aranya-docs/docs/sync-sampling.md`.

use alloc::vec;
use core::num::NonZeroUsize;

use aranya_crypto::Csprng;
use buggy::{Bug, BugExt as _};
use heapless::Vec;

use super::{COMMAND_RESPONSE_MAX, COMMAND_SAMPLE_MAX, SyncError};
use crate::{
    Address, Prior,
    storage::{HeadSet, LocatedAddress, Location, MaxCut, Segment as _, Storage},
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

/// What [`skip_jump`] does at a merge with no usable skip-list entry.
pub(super) enum AtMerge<'a> {
    /// Stop at the merge.
    Stop,
    /// Continue from the merge's LCA, so the walk only visits commands
    /// every head passes through.
    Lca,
    /// Continue from a random parent with max cut at least the target.
    RandomParent(&'a dyn Csprng),
}

/// Walk back from `start` toward max cut `target`, which must not be above
/// `start`.
///
/// Takes the lowest skip-list entry at or above `target` when one exists,
/// otherwise steps to a prior. At a merge with no usable skip, does what
/// `at_merge` says.
///
/// Returns the command at `target` when the walk reaches the segment that
/// contains it, or the first location at or below `target` that a merge's
/// LCA leads to. With [`AtMerge::Stop`], returns the merge's location.
pub(super) fn skip_jump<S: Storage>(
    storage: &S,
    start: Location,
    target: MaxCut,
    at_merge: AtMerge<'_>,
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
            Prior::Merge(a, b) => match at_merge {
                AtMerge::Stop => return Ok(current),
                AtMerge::Lca => seg
                    .skip_list()
                    .last()
                    .copied()
                    .assume("merge skip list must end with LCA")?,
                AtMerge::RandomParent(rng) => {
                    let mut parents: Vec<Location, 2> = Vec::new();
                    for p in [a, b] {
                        if p.max_cut >= target {
                            parents.push(p).ok().assume("at most two parents")?;
                        }
                    }
                    *parents
                        .get(random_index(&rng, parents.len())?)
                        .assume("index in range")?
                }
            },
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
    let floor = skip_jump(storage, lca, lowest, AtMerge::Lca)?;
    Ok(floor.max_cut)
}

/// A sample of command addresses.
type Sample = Vec<Address, COMMAND_SAMPLE_MAX>;

/// Builds a sample over `storage`: the heads in `head_groups`, then random
/// commands spread evenly between the tallest graph head and `floor`.
/// Random commands for which `exclude` returns true are dropped.
pub(super) fn build<S: Storage>(
    storage: &S,
    head_groups: &[&[Address]],
    floor: MaxCut,
    rng: &impl Csprng,
    exclude: impl Fn(Address) -> bool,
) -> Result<Sample, SyncError> {
    let mut sample = Sample::new();
    add_heads(&mut sample, head_groups, rng)?;
    add_random_commands(&mut sample, storage, floor, rng, exclude)?;
    Ok(sample)
}

/// Adds `head_groups` to `sample` in order, into at most `HEADS_MAX` slots.
/// A group that does not fit in the slots left contributes a random subset
/// that fills them.
fn add_heads(
    sample: &mut Sample,
    head_groups: &[&[Address]],
    rng: &impl Csprng,
) -> Result<(), Bug> {
    for group in head_groups {
        let room = HEADS_MAX
            .checked_sub(sample.len())
            .assume("heads fit in their slots")?;
        let mut new: vec::Vec<Address> = group
            .iter()
            .copied()
            .filter(|a| !sample.contains(a))
            .collect();
        keep_random_subset(&mut new, room, rng)?;
        for head in new {
            sample.push(head).ok().assume("heads fit in sample")?;
        }
    }
    Ok(())
}

/// Shrinks `items` to a uniformly random subset of at most `n` of them.
fn keep_random_subset(
    items: &mut vec::Vec<Address>,
    n: usize,
    rng: &impl Csprng,
) -> Result<(), Bug> {
    if items.len() <= n {
        return Ok(());
    }
    // Partial Fisher-Yates: the first `n` entries become the subset.
    for i in 0..n {
        let rest = items.len().checked_sub(i).assume("i < len")?;
        let j = i
            .checked_add(random_index(rng, rest)?)
            .assume("index mustn't overflow")?;
        items.swap(i, j);
    }
    items.truncate(n);
    Ok(())
}

/// Fills the free slots of `sample` with commands at evenly spaced max cuts
/// between the tallest graph head and `floor`. Commands for which `exclude`
/// returns true are dropped.
fn add_random_commands<S: Storage>(
    sample: &mut Sample,
    storage: &S,
    floor: MaxCut,
    rng: &impl Csprng,
    exclude: impl Fn(Address) -> bool,
) -> Result<(), SyncError> {
    let heads = storage.get_heads()?;
    let Some(top) = heads.iter().map(|h| h.max_cut).max() else {
        return Ok(());
    };
    let free = COMMAND_SAMPLE_MAX
        .checked_sub(sample.len())
        .assume("sample is not overfull")?;
    let free = NonZeroUsize::new(free).assume("heads leave slots for random commands")?;

    let gap = gap(top, floor, free)?;
    let offset = random_offset(gap, rng)?;
    for target in positions(top, floor, gap, offset) {
        if sample.is_full() {
            break;
        }
        let address = random_command_at(storage, heads, target, rng)?;
        if !exclude(address) && !sample.contains(&address) {
            sample.push(address).ok().assume("sample is not full")?;
        }
    }
    Ok(())
}

/// The spacing between random commands: the span from `floor` to `top`
/// shared among `free` slots, but never less than one reply, since tighter
/// spacing saves less than a reply.
fn gap(top: MaxCut, floor: MaxCut, free: NonZeroUsize) -> Result<u64, Bug> {
    let span = top
        .get()
        .checked_sub(floor.get())
        .assume("floor is not above the tallest head")?;
    Ok(span
        .div_ceil(free.get() as u64)
        .max(COMMAND_RESPONSE_MAX as u64))
}

/// How far below the tallest head the first random command is, uniform in
/// `gap/2..=gap`. At least half a gap keeps it from nearly duplicating the
/// head, and a random offset means repeated rounds pick different commands.
fn random_offset(gap: u64, rng: &impl Csprng) -> Result<u64, Bug> {
    let half = gap.div_ceil(2);
    let width = gap
        .checked_sub(half)
        .and_then(|w| w.checked_add(1))
        .assume("offset range is nonempty")?;
    half.checked_add(random_below(rng, width)?)
        .assume("offset mustn't overflow")
}

/// The max cuts of the random commands: `offset` below `top`, then every
/// `gap` below that, while above `floor`.
fn positions(top: MaxCut, floor: MaxCut, gap: u64, offset: u64) -> impl Iterator<Item = MaxCut> {
    core::iter::successors(top.get().checked_sub(offset), move |t| t.checked_sub(gap))
        .take_while(move |&t| t > floor.get())
        .map(MaxCut::new)
}

/// The command at max cut `target`, reached by walking down from a random
/// head tall enough to reach it and taking a random parent at each merge.
fn random_command_at<S: Storage>(
    storage: &S,
    heads: &HeadSet,
    target: MaxCut,
    rng: &impl Csprng,
) -> Result<Address, SyncError> {
    let head = random_head_reaching(heads, target, rng)?;
    let location = skip_jump(storage, head, target, AtMerge::RandomParent(rng))?;
    Ok(storage.get_command_address(location)?)
}

/// A random head with max cut at least `target`.
fn random_head_reaching(
    heads: &HeadSet,
    target: MaxCut,
    rng: &impl Csprng,
) -> Result<Location, Bug> {
    let reaching = || heads.iter().filter(move |h| h.max_cut >= target);
    let pick = random_index(rng, reaching().count())?;
    reaching()
        .nth(pick)
        .map(LocatedAddress::location)
        .assume("picked a head that reaches the target")
}
