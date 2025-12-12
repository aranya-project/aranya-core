# Graph Search Inefficiency Analysis

## Overview

The graph storage in aranya-runtime uses a DAG (Directed Acyclic Graph) structure where commands are organized into segments. Searching the graph for ancestors or specific locations was exhibiting exponential time complexity in graphs with many merge operations, taking millions of comparisons for graphs with only ~500 commands.

## Graph Structure

### Segments and Commands

Commands are grouped into **segments**. Each segment contains:
- A sequence of commands (stored in `Vec1<CommandData>`)
- A `prior` field indicating parent location(s): `Prior::None`, `Prior::Single(Location)`, or `Prior::Merge(Location, Location)`
- A `skip_list` for optimization: `Vec<(Location, MaxCut)>` to jump backwards quickly

### Location

A `Location` identifies a specific command by:
```rust
struct Location {
    segment: usize,  // Which segment
    command: usize,  // Index within segment
}
```

### Graph Topology

When multiple clients make concurrent changes, the graph develops branches. When branches are reconciled, **merge commands** are created that have two parents (`Prior::Merge`). This creates a diamond-like pattern:

```
     [A]         (common ancestor)
    /   \
  [B]   [C]      (divergent branches)
    \   /
     [D]         (merge - has two parents)
```

## The Problem

### Affected Functions

Two functions in `src/storage/mod.rs` perform graph traversal:

1. **`get_location_from`**: Finds a command by its address, starting from a given location
2. **`is_ancestor`**: Determines if a location is an ancestor of a given segment

Both use a queue-based BFS traversal pattern:

```rust
let mut queue = Vec::new();
queue.push(start);
while let Some(loc) = queue.pop() {
    // Process segment...
    // Add prior locations to queue
    queue.extend(segment.prior());  // <-- Problem: can add same segment multiple times
}
```

### Why Exponential Blowup Occurs

Without tracking visited segments, the same segment can be added to the queue **multiple times** through different traversal paths.

Consider a sequence of merges forming a "ladder" pattern:

```
    [S0]                   (init)
   /    \
[S1]    [S2]               (branch)
   \    /
    [M1]                   (merge 1)
   /    \
[S3]    [S4]               (branch)
   \    /
    [M2]                   (merge 2)
   /    \
[S5]    [S6]               (branch)
   \    /
    [M3]                   (merge 3)
     |
    ...
```

When traversing backward from the head:
- M3 has 2 parents (S5, S6)
- Both S5 and S6 lead back to M2
- M2 has 2 parents (S3, S4)
- Both S3 and S4 lead back to M1
- And so on...

**Without visited tracking:**
- From M3, we add S5 and S6 to the queue (2 items)
- Processing S5 adds M2 to queue; processing S6 also adds M2 to queue
- Now M2 is in the queue **twice**
- Each instance of M2 adds S3 and S4 to the queue
- Pattern continues exponentially

For `n` merge levels, we process up to **2^n** segment visits.

### Mathematical Analysis

Consider a graph with `n` sequential diamonds (merges). Let `V(k)` be the number of times we visit segments when searching from merge `k` to the root:

- V(0) = 1 (base case: init segment)
- V(k) = 2 * V(k-1) (each merge visits both branches, each branch leads to the previous merge)

This gives V(n) = 2^n.

**Example with n=10 merges:**
- Without visited tracking: 2^10 = 1,024 segment visits
- With visited tracking: ~20 segment visits (each segment visited once)

**Example with n=20 merges:**
- Without visited tracking: 2^20 = 1,048,576 segment visits
- With visited tracking: ~40 segment visits

The real-world graphs are more complex than a simple chain of diamonds, but the principle holds: any merge point acts as a "multiplication point" for the number of paths to traverse.

### Skip Lists Compound the Problem

The `skip_list` optimization adds additional edges for fast jumping backward in the graph. While this helps for simple lookups, in traversals without visited tracking, skip lists create even more paths to reach the same segments:

```rust
for (skip, max_cut) in segment.skip_list() {
    if max_cut >= &address.max_cut {
        queue.push(*skip);
        continue 'outer;
    }
}
queue.extend(segment.prior());
```

This can add segments via both skip list entries AND prior locations, multiplying the redundant visits.

### Real-World Impact

In the `generated_400_commands` test:
- 4 clients making concurrent changes
- ~400 commands with frequent branching and merging
- Creates many merge points throughout the graph

Without the optimization, this test **never completes** - it would require millions of comparisons. With visited segment tracking, it completes in seconds.

### Braiding Amplifies the Problem

The `braid` function in `src/client/braiding.rs` creates a deterministic ordering of commands when merging branches. It maintains a heap of "strands" (active traversal paths) and repeatedly:

1. Pops the highest-priority command
2. For each parent location, checks if it's an ancestor of any other strand
3. If not an ancestor, creates a new strand

```rust
// src/client/braiding.rs:121-135
'location: for location in prior {
    for other in strands.iter() {
        // ...
        if storage.is_ancestor(location, &other.segment)? {
            trace!("found ancestor");
            continue 'location;
        }
    }
    // Not an ancestor of any strand - create new strand
    strands.push(Strand::new(storage, location, ...)?)?;
}
```

This means `is_ancestor` is called **O(B * S)** times during braiding, where:
- B = number of commands in the braid
- S = number of active strands (typically 2, but can grow)

Each `is_ancestor` call could itself have exponential complexity without visited tracking.

For a graph with 400 commands and many merge points:
- Hundreds of `is_ancestor` calls
- Each potentially visiting thousands of segments
- Total comparisons: potentially **millions**

## The Current Fix

### Skip List Sort Order Fix

The skip list was being sorted by `Location` (segment, command) instead of by `max_cut`. This meant we weren't always jumping as far back as possible when using skip lists. Fixed by:

```rust
// Before: skips.sort();  // Sorted by Location
// After:
skips.sort_by_key(|(_, max_cut)| *max_cut);  // Sorted by max_cut ascending
```

This ensures the first valid skip entry jumps furthest back toward the root.

### Visited Segment Tracking

Visited segment tracking was added to prevent exponential revisits:

#### In `get_location_from`:
```rust
let mut visited = alloc::collections::BTreeSet::new();
// ...
while let Some(loc) = queue.pop() {
    if !visited.insert(loc.segment) {
        continue;  // Already processed this segment
    }
    // ... rest of traversal
}
```

#### In `is_ancestor`:
```rust
let mut visited = alloc::collections::BTreeMap::<usize, usize>::new();
// ...
while let Some(location) = queue.pop() {
    if let Some(&max_cmd) = visited.get(&location.segment) {
        if location.command <= max_cmd {
            continue;  // Already processed at higher command index
        }
    }
    visited.insert(location.segment, location.command);
    // ... rest of traversal
}
```

Note: `is_ancestor` uses a `BTreeMap` to track the highest command index visited per segment, because the same segment might be entered at different command positions (the function checks if `location.command >= search_location.command`).

## Trade-off: Unbounded Allocation

The visited tracking requires:
- **`BTreeSet<usize>`** for `get_location_from` - one entry per unique segment visited
- **`BTreeMap<usize, usize>`** for `is_ancestor` - one entry per unique segment visited

In the worst case, this could allocate O(S) entries where S is the number of segments in the graph. For a graph with many segments, this could be significant memory usage.

This conflicts with aranya-core's goal of minimizing unbounded allocations, particularly for embedded or no-alloc environments.

## Constraints for Future Solutions

Target environments include:
- **No-alloc embedded systems**: Cannot use dynamic allocation
- **Large peer counts**: Up to thousands of peers (satellite constellations, drone swarms)

### Key Observations

1. **Branch width bounded by peer count**: The maximum number of concurrent branches at any point in the graph equals the number of peers (P).

2. **Visited entries can be evicted based on max_cut**: Since we traverse backward (high max_cut → low max_cut), once all items in the queue have max_cut < X, we'll never encounter segments with max_cut ≥ X again. Visited entries above this threshold can be safely evicted.

## Proposed Solution: Capped Visited Set with Eviction

### Approach

Combine a fixed-size visited set with max_cut-based eviction:

1. Use a fixed-size array (capacity tuned to expected frontier width)
2. Track the maximum max_cut remaining in the queue
3. Evict entries with max_cut above this threshold (they'll never be seen again)
4. If still full after eviction, evict the entry with highest max_cut (LRU-style)

### Implementation Sketch

```rust
struct CappedVisited<const CAP: usize> {
    entries: [(usize, usize); CAP],  // (segment_id, max_cut)
    len: usize,
}

impl<const CAP: usize> CappedVisited<CAP> {
    fn contains(&self, segment: usize) -> bool {
        self.entries[..self.len].iter().any(|(s, _)| *s == segment)
    }

    fn insert(&mut self, segment: usize, max_cut: usize) -> bool {
        // Check if already present
        if self.contains(segment) {
            return false;
        }

        if self.len < CAP {
            self.entries[self.len] = (segment, max_cut);
            self.len += 1;
        } else {
            // Evict entry with highest max_cut (least likely to be seen again)
            let evict_idx = self.entries[..self.len]
                .iter()
                .enumerate()
                .max_by_key(|(_, (_, mc))| mc)
                .map(|(i, _)| i)
                .unwrap();
            self.entries[evict_idx] = (segment, max_cut);
        }
        true
    }

    fn evict_above(&mut self, threshold: usize) {
        // Remove entries with max_cut > threshold
        let mut write = 0;
        for read in 0..self.len {
            if self.entries[read].1 <= threshold {
                self.entries[write] = self.entries[read];
                write += 1;
            }
        }
        self.len = write;
    }
}
```

### Trade-offs

**Advantages:**
- ✅ Fixed memory regardless of graph size
- ✅ No dynamic allocation (suitable for no-alloc environments)
- ✅ Correct results guaranteed (may revisit segments but won't miss them)
- ✅ Graceful performance degradation in pathological cases

**Disadvantages:**
- ❌ May revisit segments if set capacity exceeded
- ❌ O(n) lookup within the set (could use sorted array with binary search)
- ❌ Requires tuning capacity for expected workloads

### Capacity Sizing

The "active frontier" during traversal is bounded by the number of concurrent branches, which is bounded by peer count. With aggressive max_cut-based eviction, the required capacity should be modest even for large peer counts.

Suggested starting point: 256-512 entries (~4-8 KB). Profile real-world graphs to refine.
