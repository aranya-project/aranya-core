//! Graph diffing algorithms for sync operations.
//!
//! These functions implement the core algorithms needed to determine what commands a peer has
//! (sampling) and what commands a peer needs (segment finding).
use buggy::BugExt as _;
use heapless::{Deque, Vec};

use crate::{Address, Location, PeerCache, Segment as _, Storage, SyncError, TraversalBuffers};

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
pub fn sample_commands<const SAMPLE_MAX: usize, const HEAD_MAX: usize>(
    storage: &impl Storage,
    peer_cache: &PeerCache<HEAD_MAX>,
    buffers: &mut TraversalBuffers,
) -> Result<Vec<Address, SAMPLE_MAX>, SyncError> {
    let mut commands: Vec<Address, SAMPLE_MAX> = Vec::new();

    // Resolve peer cache heads to locations.
    // NB: It's safe to use `primary` here, `primary.get()` clears it before starting the BFS.
    let mut cache_locations: Vec<Location, HEAD_MAX> = Vec::new();
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
        if commands.len() < SAMPLE_MAX {
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

    while commands.len() < SAMPLE_MAX {
        let Some(loc) = queue.pop() else { break };

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

/// This (probably) returns a Vec of segment addresses where the head of each segment is not the
/// ancestor of any samples we have been sent. If that is longer than SEGMENT_BUFFER_MAX, it
/// contains the oldest segment heads where that holds.
///
/// Determine which graph segments a requesting peer is missing.
///
/// Given the set of command addresses the requester reported having, walk backward from the graph
/// head to find (partial) segments that contain commands the requester (probably) needs.
///
/// Returns locations ordered so that ancestor segments come before descendants, so the requester
/// can apply commands in a valid order.
pub fn find_missing_segments<const HAVE_MAX: usize, const SEGMENT_MAX: usize>(
    have: &[Address],
    storage: &impl Storage,
    buffers: &mut TraversalBuffers,
) -> Result<Vec<Location, SEGMENT_MAX>, SyncError> {
    // Resolve the requester's reported addresses to storage locations. Addresses that don't exist
    // in our graph are skipped; they may refer to commands from a different branch we don't have.
    // NB: It's safe to use `primary` here, since it's not being used for anything else.
    let mut have_locations: Vec<Location, HAVE_MAX> = Vec::new();
    for &addr in have {
        // TODO(ben): Use addresses we don't have to signal that we should sync with the peer?
        if let Some(location) = storage.get_location(addr, &mut buffers.primary)? {
            // If we hit capacity, stop resolving. The diff will be less precise but still correct;
            // we may send segments the requester already has, but we won't miss segments they need.
            if have_locations.is_full() {
                break;
            }
            have_locations
                .push(location)
                .ok()
                .assume("length checked above")?;
        }
    }

    // Filter out locations that are ancestors of other locations.
    //
    // If Location A is an ancestor of Location B, we only need to keep B since having B implies
    // having A and all ancestors.
    //
    // NB: This is O(n^2) where n = have_locations.len(). This is acceptable at n = 100, but if it
    // increases significantly, we should consider a different sorting method instead.
    //
    // Iterate backwards so we can safely remove by index.
    for i in (0..have_locations.len()).rev() {
        let location_a = have_locations[i];
        let mut is_ancestor_of_other = false;

        for &location_b in &have_locations {
            if location_a == location_b {
                continue;
            }

            // Lower max_cut in the same segment means it's an ancestor.
            if location_a.same_segment(location_b) && location_a.max_cut <= location_b.max_cut {
                is_ancestor_of_other = true;
                break;
            }

            // Full check to see if it's an ancestor.
            let segment_b = storage.get_segment(location_b)?;
            if storage.is_ancestor(location_a, &segment_b, &mut buffers.primary)? {
                is_ancestor_of_other = true;
                break;
            }
        }

        if is_ancestor_of_other {
            // NB: O(1) removal, order doesn't matter since we treat it as a set.
            have_locations.swap_remove(i);
        }
    }

    // BFS backward from graph head, collecting segments the requester needs.
    // NB: `primary` now holds the BFS frontier, so all inner traversal calls must use `secondary`.
    let queue = buffers.primary.get();
    queue.push(storage.get_head()?)?;

    // Use a Deque so we can use push_front (maintaining ancesor-before-descendent ordering) and
    // pop_back when at capacity.
    let mut result: Deque<Location, SEGMENT_MAX> = Deque::new();

    while let Some(head) = queue.pop() {
        // If this segment head is an ancestor of any "have" location, the requester already has
        // this command and all its ancestors, so prune it.
        let mut is_have_ancestor = false;
        for &have_location in &have_locations {
            let have_segment = storage.get_segment(have_location)?;
            if storage.is_ancestor(head, &have_segment, &mut buffers.secondary)? {
                is_have_ancestor = true;
                break;
            }
        }
        if is_have_ancestor {
            continue;
        }

        let segment = storage.get_segment(head)?;

        // If the requester has some of the commands in this segment, find where the missing portion starts.
        if let Some(latest_loc) = have_locations
            .iter()
            .filter(|&&location| location.same_segment(head))
            .max_by_key(|&&location| location.max_cut)
        {
            let next_max_cut = latest_loc
                .max_cut
                .checked_add(1)
                .assume("command + 1 mustn't overflow")?;
            let next_location = Location {
                max_cut: next_max_cut,
                segment: head.segment,
            };

            // If the requester already has up to the head, we don't need to send anything.
            let head_loc = segment.head_location()?;
            if next_location.max_cut > head_loc.max_cut {
                continue;
            }

            if result.is_full() {
                result.pop_back();
            }
            result
                .push_front(next_location)
                .ok()
                .assume("already made room above")?;
            continue;
        }

        // Requester has nothing from this segment, send from the beginning.
        for prior in segment.prior() {
            queue.push(prior)?;
        }

        if result.is_full() {
            result.pop_back();
        }
        let location = segment.first_location();
        result
            .push_front(location)
            .ok()
            .assume("already made room above")?;
    }

    // Flatten the deque into a sorted vec. Sorting ensures ancestor segments are sent before
    // descendants so the requester can apply them in order.
    let mut r: Vec<Location, SEGMENT_MAX> = Vec::new();
    for l in result {
        r.push(l).ok().assume("vec is the same length as deque")?;
    }
    r.sort();

    Ok(r)
}
