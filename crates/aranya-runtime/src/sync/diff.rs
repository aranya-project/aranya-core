//! Graph diffing algorithms for sync operations.
//!
//! These functions implement the core algorithms needed to determine what commands a peer has
//! (sampling) and what commands a peer needs (segment finding).
use buggy::BugExt as _;
use heapless::Vec;

use super::{
    Address, Location, MaxCut, PeerCache, Segment as _, Storage, SyncError, TraversalBuffers,
};

/// Sample commands from the local graph to include in a sync request.
///
/// Generates a bounded set of command addresses that represent our current graph state. The peer
/// uses this sample to determine which commands we're missing.
///
/// The sampling strategy walks backward from the current graph head, collecting the head address of
/// each segment. Paths that reach a known peer cache head are pruned, since we know the peer has
/// everything at and before that point.
///
/// # Limitations
/// The current strategy collects one address per segment, newest-first. If the local graph is
/// significantly ahead of the peer, the sample will only cover recent segments and the peer's
/// responder won't be able to narrow down what we're missing, and effectively send everything it
/// has.
///
/// A more sophisticated strategy (e.g. exponential backoff through history, or sampling at multiple
/// depths) would help the responder produce tighter diffs.
pub(super) fn sample_commands<const MAX_SAMPLES: usize, const MAX_HEADS: usize>(
    storage: &impl Storage,
    peer_cache: &PeerCache<MAX_HEADS>,
    buffers: &mut TraversalBuffers,
) -> Result<Vec<Address, MAX_SAMPLES>, SyncError> {
    let mut commands: Vec<Address, MAX_SAMPLES> = Vec::new();

    // Resolve peer cache heads to locations.
    // NB: It's safe to use `primary` here, `primary.get()` clears it before starting the BFS.
    let mut cache_locations: Vec<Location, MAX_HEADS> = Vec::new();
    for address in peer_cache.heads() {
        // If we're able to resolve a location, add it to the list.
        if let Some(loc) = storage.get_location(*address, &mut buffers.primary)? {
            cache_locations
                .push(loc)
                .ok()
                .assume("cache_locations should not be full")?;
        }

        // Include peer cache heads in the sample, the peer knows about these, and including them
        // helps in the responder's diff algorithm.
        if commands.len() < MAX_SAMPLES {
            commands
                .push(*address)
                .ok()
                .assume("already checked length")?;
        }
    }

    // BFS backward from graph head, collecting segment head addresses. The TraversalQueue pops by
    // highest max_cut (newest first) and deduplicates by segment, which gives us a breadth-first,
    // newest-first walk without revisiting segments.
    let head = storage.get_head()?;
    // NB: `primary` now holds the BFS frontier, so all inner traversal calls must use `secondary`.
    let queue = buffers.primary.get();
    queue.push(head)?;

    while commands.len() < MAX_SAMPLES {
        let Some(loc) = queue.pop()? else { break };

        // If this location is dominated by a peer cache head, the peer already has this command and
        // all its ancestors, so prune it.
        let mut dominated = false;
        for &cache_loc in &cache_locations {
            // If `loc` is in the same segment at an earlier point, it's dominated.
            if cache_loc.same_segment(loc) && loc.max_cut <= cache_loc.max_cut {
                dominated = true;
                break;
            }

            // Full check to see if `loc` is an ancestor of a peer cache head.
            let cache_seg = storage.get_segment(cache_loc)?;
            if storage.is_ancestor(loc, &cache_seg, &mut buffers.secondary)? {
                dominated = true;
                break;
            }
        }
        if dominated {
            continue;
        }

        let segment = storage.get_segment(loc)?;
        commands
            .push(segment.head_address()?)
            .ok()
            .assume("loop condition checks length")?;

        for prior in segment.prior() {
            queue.push(prior)?;
        }
    }

    Ok(commands)
}

/// Returns (partial) segments that a peer likely doesn't have.
///
/// Uses a single backward traversal with coverage propagation to eliminate all `is_ancestor()`
/// calls. See `aranya-docs/docs/find-needed-segments-optimization.md`.
///
/// Returns locations ordered so that ancestor segments come before descendants, so the requester
/// can apply commands in a valid order.
pub(super) fn find_needed_segments<const MAX_SAMPLES: usize, const MAX_SEGMENTS: usize>(
    samples: &Vec<Address, MAX_SAMPLES>,
    storage: &impl Storage,
    buffers: &mut TraversalBuffers,
) -> Result<Vec<Location, MAX_SEGMENTS>, SyncError> {
    // Resolve sample addresses to locations.
    // NB: It's safe to use `primary` here, `primary.get()` clears it afterwards.
    let mut have_locations: Vec<Location, MAX_SAMPLES> = Vec::new();
    for &addr in samples {
        if let Some(location) = storage.get_location(addr, &mut buffers.primary)? {
            let _ = have_locations.push(location);
        }
    }

    // Sort by descending `max_cut` so we can walk a cursor forwards as we descend through the graph.
    have_locations.sort_by_key(|loc| core::cmp::Reverse(loc.max_cut));

    // Index into `have_locations`; everything before this has a higher `max_cut` than the current
    // segment's `longest_max_cut` and can be skipped.
    let mut have_cursor: usize = 0;

    // Segments still to visit, popped by highest `max_cut`.
    let heads = buffers.primary.get();
    heads.push(storage.get_head()?)?;

    // Segments tentatively needed by the peer, flushed to `collected` once confirmed.
    let pending = buffers.secondary.get();

    // Finalized list of needed segments, bounded by `SEGMENT_MAX`. Only stores entries with the
    // lowest `max_cut` (ancestors first); if full, the entry with the highest `max_cut` is replaced
    // if the new one is lower.
    let mut collected: Vec<Location, MAX_SEGMENTS> = Vec::new();
    let mut prev_max_cut: Option<MaxCut> = None;

    while let Some((head, covered)) = heads.pop_covered()? {
        // Finalize all pending entries whose `shortest_max_cut` (stored as `max_cut`) is above this
        // entry's `longest_max_cut`. No future `have_location` can reach them since we process in
        // descending order.
        if prev_max_cut != Some(head.max_cut) {
            pending.drain_above(head.max_cut, |loc| push_bounded(&mut collected, loc))?;
            prev_max_cut = Some(head.max_cut);
        }

        let segment = storage.get_segment(head)?;

        // Case 1: The peer already has this segment (up to `head.max_cut`). Update `pending` to
        // reflect partial or full coverage so we don't send what the peer already has.
        if covered {
            // Update coverage for the current segment, up to the current `head.max_cut`.
            let longest = segment.longest_max_cut()?;
            pending.cover_up_to(head.segment, head.max_cut, longest)?;

            // The peer has some/all of the current segment, so it must also have all its ancestors.
            for prior in segment.prior() {
                heads.push_covered(prior, true)?;
            }

            // If all remaining heads are covered, any future paths we might explore lead to
            // segments the peer already has, so skip all that work.
            if heads.all_covered() && !heads.is_empty() {
                break;
            }
            continue;
        }

        // Advance `have_cursor` past any location whose segment we can no longer encounter (i.e.
        // have a higher `max_cut` than this segment's `longest_max_cut`).
        let longest = segment.longest_max_cut()?;
        while have_locations
            .get(have_cursor)
            .is_some_and(|h| h.max_cut > longest)
        {
            have_cursor = have_cursor
                .checked_add(1)
                .assume("index must not overflow")?;
        }

        // Look for a `have_location` in this segment (i.e. same `SegmentIndex` with a `max_cut`
        // inside this segment's `shortest_max_cut..=longest_max_cut`).
        let shortest = segment.shortest_max_cut();
        let mut best_have: Option<Location> = None;
        for &hloc in &have_locations[have_cursor..] {
            // If we hit a location below the segment's `shortest_max_cut`, we ran out of options.
            if hloc.max_cut < shortest {
                break;
            }

            // `have_locations` is sorted descending, so the first match is the highest `max_cut`.
            if hloc.segment == head.segment {
                best_have = Some(hloc);
                break;
            }
        }

        // Case 2: the current segment contains a location the peer already has (partial coverage).
        if let Some(hloc) = best_have {
            // The peer has some/all of the current segment, so it must also have all its ancestors.
            for prior in segment.prior() {
                heads.push_covered(prior, true)?;
            }

            // If the peer doesn't have the whole segment (i.e. we didn't encounter the location at
            // `longest_max_cut`), add a partial entry to `pending` starting from the next command.
            // Otherwise, the entire segment is covered, so we can skip processing the rest of it.
            if hloc.max_cut < longest {
                let next_max_cut = hloc
                    .max_cut
                    .checked_add(1)
                    .assume("command + 1 mustn't overflow")?;
                let partial_loc = Location {
                    max_cut: next_max_cut,
                    segment: head.segment,
                };
                pending.push(partial_loc)?;
            }
        }
        // Case 3: The peer doesn't have any locations in this segment, so add it to `pending` and
        // continue traversing prior segments.
        else {
            pending.push(segment.first_location())?;
            for prior in segment.prior() {
                heads.push(prior)?;
            }
        }

        // If all remaining heads are covered, any future paths we might explore lead to
        // segments the peer already has, so skip all that work.
        if heads.all_covered() && !heads.is_empty() {
            break;
        }
    }

    // Flush any remaining uncovered segments. The peer has all covered entries, so discard them.
    pending.drain_all(|loc| push_bounded(&mut collected, loc));

    // Sort to ensure causal order (parents before children).
    collected.sort();

    Ok(collected)
}

/// Insert a location into a bounded vec, keeping the lowest `max_cut` entries. If the vec is full,
/// replaces the highest `max_cut` entry if the new one is lower which prioritizes ancestors the
/// peer is most likely to need.
fn push_bounded<const SEGMENT_MAX: usize>(
    collected: &mut Vec<Location, SEGMENT_MAX>,
    loc: Location,
) {
    // Try to push the new location to the end of the vec. If it errors, it's full so we need to
    // overwrite the entry with the highest `max_cut`.
    if collected.push(loc).is_err() {
        let (max_idx, max_loc) = collected
            .iter()
            .enumerate()
            .max_by_key(|(_, l)| l.max_cut)
            .expect("non-empty");

        if loc.max_cut < max_loc.max_cut {
            collected[max_idx] = loc;
        }
    }
}
