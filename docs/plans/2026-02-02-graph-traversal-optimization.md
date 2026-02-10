# Graph Traversal Optimization Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement bounded-memory graph traversal with entry-point tracking per the spec in `aranya-docs/docs/graph-traversal.md`.

**Architecture:** Replace the current simple segment-level visited tracking with a richer `CappedVisited` structure that tracks entry points (highest command visited) per segment. This enables skipping segment loads when re-entering at the same or lower command index, and incremental searching in `get_location_from`. Queue changes from LIFO to FIFO to align with eviction strategy.

**Tech Stack:** Rust, heapless crate (already a dependency), no-std compatible

**Reference Spec:** `/home/bzimmerman/git/aranya-docs/docs/graph-traversal.md`

---

## Task 1: Update CappedVisited Data Structure

**Files:**
- Modify: `crates/aranya-runtime/src/storage/visited.rs`

**Step 1: Write failing tests for new API**

Add these tests at the bottom of the existing `#[cfg(test)] mod tests` block:

```rust
#[test]
fn test_clear() {
    let mut visited = CappedVisited::<4>::new();
    visited.insert_or_update(1, 100, 5);
    visited.insert_or_update(2, 200, 3);
    assert!(visited.get(1).is_some());
    visited.clear();
    assert!(visited.get(1).is_none());
    assert!(visited.get(2).is_none());
}

#[test]
fn test_get() {
    let mut visited = CappedVisited::<4>::new();
    assert!(visited.get(1).is_none());
    visited.insert_or_update(1, 100, 5);
    let (min_mc, highest) = visited.get(1).unwrap();
    assert_eq!(min_mc, 100);
    assert_eq!(highest, 5);
}

#[test]
fn test_insert_or_update_new() {
    let mut visited = CappedVisited::<4>::new();
    visited.insert_or_update(1, 100, 5);
    let (min_mc, highest) = visited.get(1).unwrap();
    assert_eq!(min_mc, 100);
    assert_eq!(highest, 5);
}

#[test]
fn test_insert_or_update_existing_higher() {
    let mut visited = CappedVisited::<4>::new();
    visited.insert_or_update(1, 100, 5);
    visited.insert_or_update(1, 100, 8); // Higher command
    let (_, highest) = visited.get(1).unwrap();
    assert_eq!(highest, 8);
}

#[test]
fn test_insert_or_update_existing_lower() {
    let mut visited = CappedVisited::<4>::new();
    visited.insert_or_update(1, 100, 8);
    visited.insert_or_update(1, 100, 5); // Lower command - should not update
    let (_, highest) = visited.get(1).unwrap();
    assert_eq!(highest, 8);
}

#[test]
fn test_eviction_by_effective_max_cut() {
    let mut visited = CappedVisited::<3>::new();
    // Fill the set with different effective max_cuts
    visited.insert_or_update(1, 100, 10); // effective = 110
    visited.insert_or_update(2, 200, 50); // effective = 250 (highest)
    visited.insert_or_update(3, 150, 20); // effective = 170

    // Insert new - should evict segment 2 (highest effective max_cut = 250)
    visited.insert_or_update(4, 50, 5);

    assert!(visited.get(1).is_some()); // still present
    assert!(visited.get(2).is_none()); // evicted
    assert!(visited.get(3).is_some()); // still present
    assert!(visited.get(4).is_some()); // newly inserted
}

#[test]
fn test_segment_level_helpers() {
    let mut visited = CappedVisited::<4>::new();
    assert!(!visited.was_segment_visited(1));
    visited.mark_segment_visited(1, 100);
    assert!(visited.was_segment_visited(1));
    // mark_segment_visited uses CommandIndex::MAX
    let (_, highest) = visited.get(1).unwrap();
    assert_eq!(highest, usize::MAX);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p aranya-runtime visited::tests --no-default-features`
Expected: FAIL - methods don't exist

**Step 3: Update struct and implement new API**

Replace the entire contents of `crates/aranya-runtime/src/storage/visited.rs`:

```rust
//! Capped visited set for graph traversal.
//!
//! Provides bounded-memory tracking of visited segments during DAG traversal,
//! suitable for no-alloc embedded environments. Tracks entry points (highest
//! command visited) per segment to enable skipping segment loads and
//! incremental searching.

use heapless::Vec;

/// Index of a command within a segment.
pub type CommandIndex = usize;

/// A fixed-size visited set for graph traversal.
///
/// Tracks visited segments during backward traversal through the DAG.
/// Each entry records the segment ID, its minimum max_cut (for calculating
/// effective max_cut), and the highest command index we've entered at.
///
/// When the set is full, evicts the entry with the highest effective max_cut
/// (min_max_cut + highest_command), as this represents the newest point
/// visited and is least likely to be encountered again during backward
/// traversal.
///
/// # Correctness
///
/// The algorithm remains correct even when the set overflows:
/// - Eviction may cause a segment to be revisited
/// - Revisiting produces redundant work but not incorrect results
/// - The algorithm converges as long as progress is made toward the root
pub struct CappedVisited<const CAP: usize> {
    // (segment_id, min_max_cut, highest_command_visited)
    entries: Vec<(usize, usize, CommandIndex), CAP>,
}

impl<const CAP: usize> CappedVisited<CAP> {
    /// Creates a new empty visited set.
    #[inline]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Resets the visited set for reuse.
    #[inline]
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the min_max_cut and highest_command_visited for a segment
    /// if it exists in the set.
    #[inline]
    pub fn get(&self, segment: usize) -> Option<(usize, CommandIndex)> {
        self.entries
            .iter()
            .find(|(s, _, _)| *s == segment)
            .map(|(_, min_mc, highest)| (*min_mc, *highest))
    }

    /// Inserts a new segment or updates the highest_command_visited if the
    /// segment already exists and the new command is higher.
    ///
    /// When the set is full and a new segment needs to be inserted, evicts
    /// the entry with the highest effective max_cut (min_max_cut + highest_command).
    #[inline]
    pub fn insert_or_update(&mut self, segment: usize, min_max_cut: usize, command: CommandIndex) {
        // Single pass: check for existing segment and track eviction candidate
        let mut evict_idx = 0;
        let mut evict_effective_max_cut = usize::MIN;

        for (i, (s, min_mc, highest)) in self.entries.iter_mut().enumerate() {
            if *s == segment {
                // Segment exists - update highest_command if this entry point is higher
                if command > *highest {
                    *highest = command;
                }
                return;
            }
            // Track entry with highest effective max_cut for potential eviction
            // Use saturating_add to handle CommandIndex::MAX without overflow
            let effective_max_cut = min_mc.saturating_add(*highest);
            if effective_max_cut > evict_effective_max_cut {
                evict_effective_max_cut = effective_max_cut;
                evict_idx = i;
            }
        }

        // Segment not found - insert new entry
        if self.entries.len() < CAP {
            self.entries
                .push((segment, min_max_cut, command))
                .expect("len < CAP was checked");
        } else {
            // Evict entry with highest effective max_cut (already found above)
            self.entries[evict_idx] = (segment, min_max_cut, command);
        }
    }

    /// Marks an entire segment as visited (segment-level tracking only).
    ///
    /// Uses `CommandIndex::MAX` to indicate the entire segment has been visited.
    /// This allows a single buffer to be reused across different traversal
    /// operations that need segment-level vs entry-point tracking.
    #[inline]
    pub fn mark_segment_visited(&mut self, segment: usize, min_max_cut: usize) {
        self.insert_or_update(segment, min_max_cut, CommandIndex::MAX);
    }

    /// Checks if a segment was visited at any entry point.
    #[inline]
    pub fn was_segment_visited(&self, segment: usize) -> bool {
        self.get(segment).is_some()
    }
}

impl<const CAP: usize> Default for CappedVisited<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clear() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        visited.insert_or_update(2, 200, 3);
        assert!(visited.get(1).is_some());
        visited.clear();
        assert!(visited.get(1).is_none());
        assert!(visited.get(2).is_none());
    }

    #[test]
    fn test_get() {
        let mut visited = CappedVisited::<4>::new();
        assert!(visited.get(1).is_none());
        visited.insert_or_update(1, 100, 5);
        let (min_mc, highest) = visited.get(1).unwrap();
        assert_eq!(min_mc, 100);
        assert_eq!(highest, 5);
    }

    #[test]
    fn test_insert_or_update_new() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        let (min_mc, highest) = visited.get(1).unwrap();
        assert_eq!(min_mc, 100);
        assert_eq!(highest, 5);
    }

    #[test]
    fn test_insert_or_update_existing_higher() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 5);
        visited.insert_or_update(1, 100, 8); // Higher command
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, 8);
    }

    #[test]
    fn test_insert_or_update_existing_lower() {
        let mut visited = CappedVisited::<4>::new();
        visited.insert_or_update(1, 100, 8);
        visited.insert_or_update(1, 100, 5); // Lower command - should not update
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, 8);
    }

    #[test]
    fn test_eviction_by_effective_max_cut() {
        let mut visited = CappedVisited::<3>::new();
        // Fill the set with different effective max_cuts
        visited.insert_or_update(1, 100, 10); // effective = 110
        visited.insert_or_update(2, 200, 50); // effective = 250 (highest)
        visited.insert_or_update(3, 150, 20); // effective = 170

        // Insert new - should evict segment 2 (highest effective max_cut = 250)
        visited.insert_or_update(4, 50, 5);

        assert!(visited.get(1).is_some()); // still present
        assert!(visited.get(2).is_none()); // evicted
        assert!(visited.get(3).is_some()); // still present
        assert!(visited.get(4).is_some()); // newly inserted
    }

    #[test]
    fn test_segment_level_helpers() {
        let mut visited = CappedVisited::<4>::new();
        assert!(!visited.was_segment_visited(1));
        visited.mark_segment_visited(1, 100);
        assert!(visited.was_segment_visited(1));
        // mark_segment_visited uses CommandIndex::MAX
        let (_, highest) = visited.get(1).unwrap();
        assert_eq!(highest, usize::MAX);
    }

    #[test]
    fn test_empty_set() {
        let mut visited = CappedVisited::<256>::new();
        // First insert to empty set should succeed
        visited.insert_or_update(42, 100, 5);
        assert!(visited.get(42).is_some());
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p aranya-runtime visited::tests --no-default-features`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/aranya-runtime/src/storage/visited.rs
git commit -m "feat(storage): update CappedVisited with entry-point tracking

- Add min_max_cut and highest_command_visited tracking per segment
- Add clear(), get(), insert_or_update() methods
- Add segment-level helpers: mark_segment_visited(), was_segment_visited()
- Change eviction to use effective max_cut (min_max_cut + highest_command)
- Support incremental visiting for get_location_from optimization

Spec: aranya-docs/docs/graph-traversal.md"
```

---

## Task 2: Update is_ancestor to Use Entry-Point Tracking

**Files:**
- Modify: `crates/aranya-runtime/src/storage/mod.rs` (lines 291-346)

**Step 1: Understand current implementation**

The current `is_ancestor` implementation:
1. Gets the address of the search location
2. Adds segment's prior(s) to queue
3. Pops from queue
4. Checks if target found
5. Loads segment
6. Checks visited (after load)
7. Prunes by max_cut
8. Adds priors or skip targets

The spec requires:
1. Check if target found BEFORE visited check
2. Skip segment load if already visited at same/higher entry point
3. Use FIFO queue ordering (breadth-first)

**Step 2: Update is_ancestor implementation**

In `crates/aranya-runtime/src/storage/mod.rs`, replace lines 291-346 (the `is_ancestor` function):

```rust
    /// Determine whether the given location is an ancestor of the given segment.
    fn is_ancestor(
        &self,
        search_location: Location,
        segment: &Self::Segment,
    ) -> Result<bool, StorageError> {
        use alloc::collections::VecDeque;

        let search_segment = self.get_segment(search_location)?;
        let address = search_segment
            .get_command(search_location)
            .assume("location must exist")?
            .address()?;

        // Track visited segments to avoid revisiting via different paths.
        // Uses bounded memory with effective max_cut-based eviction.
        let mut visited = CappedVisited::<VISITED_CAPACITY>::new();
        let mut queue = VecDeque::new();
        queue.extend(segment.prior());

        while let Some(loc) = queue.pop_front() {
            // Check if we've found the target BEFORE visited check
            // This ensures entering a segment at different commands works correctly
            if loc.segment == search_location.segment && loc.command >= search_location.command {
                return Ok(true);
            }

            // Check if we can skip loading this segment entirely
            if let Some((_, highest)) = visited.get(loc.segment) {
                if loc.command <= highest {
                    continue; // Already visited at this entry point or higher
                }
            }

            // Must load segment
            let seg = self.get_segment(loc)?;
            let seg_min_max_cut = seg.shortest_max_cut();
            visited.insert_or_update(loc.segment, seg_min_max_cut, loc.command);

            // Prune: if target's max_cut is higher than this segment's highest,
            // the target cannot be in this segment or any of its ancestors.
            if address.max_cut > seg.longest_max_cut()? {
                continue;
            }

            // Try to use skip list to jump directly backward.
            // Skip list is sorted by max_cut ascending, so first valid skip
            // jumps as far back as possible.
            let mut used_skip = false;
            for (skip, skip_max_cut) in seg.skip_list() {
                if skip_max_cut >= &address.max_cut {
                    queue.push_back(*skip);
                    used_skip = true;
                    break;
                }
            }

            if !used_skip {
                // No valid skip - add prior locations to queue
                for prior in seg.prior() {
                    queue.push_back(prior);
                }
            }
        }
        Ok(false)
    }
```

**Step 3: Run existing tests to verify correctness**

Run: `cargo test -p aranya-runtime --no-default-features`
Expected: PASS (behavior should be identical, just more efficient)

**Step 4: Commit**

```bash
git add crates/aranya-runtime/src/storage/mod.rs
git commit -m "perf(storage): optimize is_ancestor with entry-point tracking

- Check target found BEFORE visited check per spec
- Skip segment load when already visited at same/higher entry point
- Use FIFO queue (VecDeque) instead of LIFO (Vec) for BFS ordering
- Track min_max_cut for effective eviction calculation

This reduces segment loads in graphs with repeated visits to same segments
at different entry points."
```

---

## Task 3: Update get_location_from with Incremental Search

**Files:**
- Modify: `crates/aranya-runtime/src/storage/mod.rs` (lines 186-235)

**Step 1: Update get_location_from implementation**

In `crates/aranya-runtime/src/storage/mod.rs`, replace lines 186-235 (the `get_location_from` function):

```rust
    /// Returns the location of Command with id by searching from the given location.
    fn get_location_from(
        &self,
        start: Location,
        address: Address,
    ) -> Result<Option<Location>, StorageError> {
        use alloc::collections::VecDeque;

        // Track visited segments to avoid revisiting via different paths.
        // Uses bounded memory with effective max_cut-based eviction.
        let mut visited = CappedVisited::<VISITED_CAPACITY>::new();
        let mut queue = VecDeque::new();
        queue.push_back(start);

        while let Some(loc) = queue.pop_front() {
            // Check visited status and determine search range
            let search_start = if let Some((_, highest)) = visited.get(loc.segment) {
                if loc.command <= highest {
                    continue; // Already searched this entry point or higher
                }
                // Only search commands we haven't seen
                highest.saturating_add(1)
            } else {
                0 // First visit - search from beginning
            };

            // Must load segment
            let segment = self.get_segment(loc)?;
            let seg_min_max_cut = segment.shortest_max_cut();
            visited.insert_or_update(loc.segment, seg_min_max_cut, loc.command);

            // Prune: if target's max_cut is higher than this segment's highest,
            // the target cannot be in this segment or any of its ancestors.
            let segment_max_cut = segment.longest_max_cut()?;
            if address.max_cut > segment_max_cut {
                continue;
            }

            // Search commands from search_start to loc.command (inclusive)
            // Check if target is in this segment using get_by_address first
            // (which may be optimized), then fall back to range check
            if let Some(found) = segment.get_by_address(address) {
                // Verify the found location is within our search range
                if found.command >= search_start && found.command <= loc.command {
                    return Ok(Some(found));
                }
            }

            // Try to use skip list to jump directly backward.
            // Skip list is sorted by max_cut ascending, so first valid skip
            // jumps as far back as possible.
            let mut used_skip = false;
            for (skip, skip_max_cut) in segment.skip_list() {
                if skip_max_cut >= &address.max_cut {
                    queue.push_back(*skip);
                    used_skip = true;
                    break;
                }
            }

            if !used_skip {
                // No valid skip - add prior locations to queue
                for prior in segment.prior() {
                    queue.push_back(prior);
                }
            }
        }
        Ok(None)
    }
```

**Step 2: Run existing tests to verify correctness**

Run: `cargo test -p aranya-runtime --no-default-features`
Expected: PASS

**Step 3: Commit**

```bash
git add crates/aranya-runtime/src/storage/mod.rs
git commit -m "perf(storage): optimize get_location_from with incremental search

- Track entry points to avoid re-searching same commands
- Use FIFO queue (VecDeque) for BFS ordering aligned with eviction
- Only search unsearched portion when re-entering segment at higher command

This reduces redundant command searches in graphs with merge points."
```

---

## Task 4: Add VecDeque Import

**Files:**
- Modify: `crates/aranya-runtime/src/storage/mod.rs` (top of file)

**Step 1: Verify import is needed**

Check if `alloc::collections::VecDeque` is already imported. If not, we used it inline with `use` statements in the functions. This is acceptable but we could also add it to the top-level imports.

The current approach with inline `use alloc::collections::VecDeque;` in each function is fine and keeps the change localized.

**Step 2: Run full test suite**

Run: `cargo test -p aranya-runtime`
Expected: PASS

**Step 3: Run clippy**

Run: `cargo clippy -p aranya-runtime --no-default-features -- -D warnings`
Expected: No new warnings

---

## Task 5: Update Documentation Comments

**Files:**
- Modify: `crates/aranya-runtime/src/storage/mod.rs`

**Step 1: Update VISITED_CAPACITY comment**

Update the comment at line ~22-34 to reflect the new entry size:

```rust
/// Default capacity for the visited segment cache used in graph traversal.
///
/// This bounds memory usage while allowing efficient traversal of graphs
/// with many concurrent branches. Each entry requires approximately 24 bytes
/// (8-byte segment_id + 8-byte min_max_cut + 8-byte highest_command_visited).
///
/// The capacity should accommodate the expected "active frontier" width
/// during backward traversal, which is bounded by peer count. Recommended:
/// - Embedded (small): 64 entries (~1.5 KB)
/// - Standard embedded: 256 entries (~6 KB)
/// - Server: 512 entries (~12 KB)
///
/// If capacity is exceeded, the algorithm remains correct but may revisit
/// segments (producing redundant work, not incorrect results).
const VISITED_CAPACITY: usize = 256;
```

**Step 2: Commit**

```bash
git add crates/aranya-runtime/src/storage/mod.rs
git commit -m "docs(storage): update VISITED_CAPACITY documentation

Reflect new entry size with min_max_cut and highest_command_visited tracking."
```

---

## Task 6: Run Full Test Suite and Benchmarks

**Step 1: Run all unit tests**

Run: `cargo make unit-tests`
Expected: PASS

**Step 2: Run correctness checks**

Run: `cargo make correctness`
Expected: PASS

**Step 3: If benchmarks exist, run them**

Check for benchmarks:
```bash
ls crates/aranya-runtime/benches/
```

If present:
Run: `cargo bench -p aranya-runtime`
Document any performance changes.

**Step 4: Final commit if any fixes needed**

```bash
git add -A
git commit -m "fix: address test/lint issues from graph traversal optimization"
```

---

## Future Tasks (Out of Scope for This Plan)

The following are mentioned in the spec but are larger changes that should be separate work items:

1. **find_needed_segments optimization** - The spec describes using `CappedVisited` with segment-level tracking in `find_needed_segments`. This requires changes to `sync/responder.rs` and is a separate performance optimization.

2. **Buffer passing by caller** - The spec suggests passing buffers from callers for reuse. This is an API change affecting all callers of `is_ancestor` and `get_location_from`.

3. **heapless::Deque for queue** - The spec uses `heapless::Deque` for truly no-alloc environments. Current implementation uses `alloc::collections::VecDeque` which requires alloc. A full no-alloc version would need heapless queues with fixed capacity.

---

## Verification Checklist

After completing all tasks:

- [ ] `cargo test -p aranya-runtime` passes
- [ ] `cargo clippy -p aranya-runtime --no-default-features -- -D warnings` clean
- [ ] `cargo make unit-tests` passes
- [ ] `cargo make correctness` passes
- [ ] Memory usage approximately matches spec estimates (~6 KB for 256 entries)
- [ ] Traversal algorithms match spec pseudocode logic
