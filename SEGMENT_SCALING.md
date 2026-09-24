# Segment and Fact Index Scaling Issues

## Bottom line

**The runtime reads storage in pieces much larger than what it needs,
and those pieces grow as the graph grows.**

Linear storage can only read a stored item as a whole. Two of those
items have no size limit:

- A **segment** holds an entire linear run of commands.
- The **fact index** holds, after compaction, the entire fact database.

Yet the code that reads them treats a read as a cheap, fine-grained
lookup:

- it reads a segment once per command,
- it reads the fact index once per query,
- it reads a full fact index just to learn its offset or depth.

Nothing caches the decoded result, so every one of these reads pays for
the whole item again.

As a result, an operation meant to cost O(1), such as getting one
command or looking up one fact, actually costs O(size of the graph). Any
loop over commands or facts becomes O(n²):

1. **Braid is O(n²)** in the length of the branches being merged,
   because every command in a branch re-reads that branch's whole
   segment.
2. **Each fact query is O(total facts)**, because it re-reads the whole
   fact database. So n commands that each query facts cost O(n²).

Fixing this means either not repeating the reads (cache decoded items,
and stop reading whole items just to get one field) or making stored
items readable in smaller pieces (bounded segments, a paged fact index).

Both issues are reproduced by deterministic tests in
`crates/aranya-runtime/src/client/scaling_tests.rs` (see
[Demonstration tests](#demonstration-tests)).

## Background: how linear storage reads data

Every item in linear storage (segments, fact indexes, head sets) is
written once with `Write::append` as a length-prefixed postcard blob, and
read back with `Read::fetch<T>(offset)`:

- `libc` backend (`storage/linear/libc/imp.rs:539`, `File::load`): reads the
  4-byte length, allocates a `Vec` of that size, reads the full blob, then
  runs `postcard::from_bytes` into an owned `T`.
- In-memory test backend (`storage/linear/testing.rs`): runs
  `postcard::from_bytes` on the stored bytes.

There is no partial decode and no cache. Every `fetch` costs
O(size of the item), plus a syscall and an allocation on the `libc`
backend.

The two item types that matter here are:

| Item | Type | Contents | Size bound |
|---|---|---|---|
| Segment | `SegmentRepr` (`linear/mod.rs:80`) | header plus `Vec1<CommandData>`; each command has its full `data` bytes and all fact `updates` | **Unbounded.** A linear run of commands (for example a whole sync batch) becomes one segment. |
| Fact index | `FactIndexRepr` (`linear/mod.rs:123`) | `offset`, `prior`, `depth`, and a `BTreeMap<String, BTreeMap<Keys, Option<Bytes>>>` of facts | A delta over `prior`. After compaction, the **entire fact database**. |

## Issue 1: per-command segment access during braid is O(n²)

### Root cause

`LinearStorage::get_segment` (`storage/linear/mod.rs:730`) fetches and
decodes the full `SegmentRepr`: every command's payload and every
command's fact updates. Two places in the braid path call it once per
command:

1. **`evaluate_braid`, `client/transaction.rs:498`**

   ```rust
   while let Some(location) = iter.next().transpose()? {
       let segment = storage.get_segment(location)?;   // whole segment, per command
       let command = segment.get_command(location)...;
       policy.call_rule(&command, ...);
   }
   ```

   It fetches the segment only to get one command.

2. **`ConvergenceMap::advance_to`, `client/convergence_map.rs:289`**

   ```rust
   // Expand priors.
   let segment = storage.get_segment(loc)?;           // whole segment, per popped location
   if let Some(previous) = segment.previous(loc) { ... } else { segment.prior() ... }
   ```

   The BFS runs command by command and only needs
   `shortest_max_cut()` and `prior()` (`Segment::previous`,
   `storage/mod.rs:978`), which are a few bytes out of a blob that can be
   megabytes.

`braid()` itself (`client/braiding.rs:216`) is **not** affected: a
`Strand` keeps its segment while walking it, and `Strand::new` reuses the
cached segment when one is passed in (`braiding.rs:330`).

For a braid over a branch of `k` commands stored as one segment, both
call sites decode about `k × O(k)` bytes, which is O(k²).

### Impact

- Merging after a long offline period, or syncing a peer's long linear
  history, braids long single-segment branches.
- `commit` with multiple heads (`transaction.rs:160`) and `add_merge`
  (`transaction.rs:341`) both go through `evaluate_braid`.
- The newly supported very large commands (#758) make each decode
  proportionally more expensive.

Early release-build measurement (in-memory backend, two branches of `k`
commands, 200-byte payloads):

| k | commit time | bytes decoded |
|---|---|---|
| 250 | 65 ms | 56 MB |
| 500 | 279 ms | 240 MB |
| 1000 | 903 ms | 743 MB |
| 2000 | 3.6 s | 3.06 GB |

On the `libc` backend each of those fetches is also a pair of `pread`s
and an allocation of the full segment size.

### Proposed fix

- **Convergence BFS:** keep a small map from `SegmentIndex` to
  `(shortest_max_cut, prior)` for the lifetime of the `ConvergenceMap`, and
  answer `previous()` and `prior()` from it. Only a cache miss should call
  `get_segment`.
  - Skipping ahead inside a segment (for example jumping from `loc`
    straight to the segment's first command) is **not safe**. A location
    in the middle of a segment can be the `Prior::Single` of another
    segment, which makes it a convergence point whose arrival count must
    be tracked.
- **`evaluate_braid`:** cache decoded segments by `SegmentIndex` across
  loop iterations.
  - Caching only the last segment is **not enough**. Braid order
    interleaves strands by `(priority, id)`, so consecutive locations
    alternate between segments. Use a small LRU sized to the number of
    concurrent strands (heads), or at least a few entries.
- **Optional, broader:** an LRU of `Arc<SegmentRepr>` inside
  `LinearStorage::get_segment`. This also speeds up `lca_pair`, the sync
  responder and requester, `has_nearby_rich_anchor`, and
  `walk_collecting_skips`. It needs interior mutability, because
  `get_segment` takes `&self`. `Storage` has no `Send` bound, so a
  `RefCell` would work in `no_std` with `alloc`.
- **Longer term:** make segment access not require decoding every
  command, either by capping segment length or by storing per-command
  offsets so one command can be decoded on its own.

## Issue 2: fact queries re-decode whole index blobs

### Root causes

**A. Every query fetches and decodes the full fact index chain.**

- `LinearFactPerspective::query` (`linear/mod.rs:1020`, fetch at `:1029`):
  on a miss in the perspective's in-memory map, it fetches the prior
  `FactIndexRepr` **on every call** and wraps it in a temporary
  `LinearFactIndex`.
- `LinearFactIndex::query` (`linear/mod.rs:948`): walks the `prior` chain
  and fetches and decodes each blob, up to `MAX_FACT_INDEX_DEPTH` = 16
  (`linear/mod.rs:58`).
- The `query_prefix_inner` paths (`linear/mod.rs:971`, `:1048`/`:1055`)
  do the same and also build a new `BTreeMap` of all matches.
- `LinearStorage::fact_cache` (`linear/mod.rs:746`) decodes the full
  committed index for `Session::new` (`client/session.rs:56`). The session
  keeps it as `base_facts` and queries it (`session.rs:311`, `:323`), so
  the decode isn't wasted, but it is the same problem: the whole top layer
  is decoded up front, and queries that miss it still fetch and decode
  each prior layer.

After compaction, the bottom of the chain holds **every fact in the
graph**. A lookup for a key that doesn't exist (the common case for policy
`!exists` checks) therefore decodes the entire fact database. The decoded
data is thrown away after each query, so the next query in the same
policy rule decodes it again.

**B. Full blobs are decoded just to read one small field.**

This has two separate causes, each with its own fix.

*B1. `commit_heads` takes a decoded index but only needs its offset.*
`Storage::commit_heads` takes a full `FactIndex`, but it only uses the
offset:

```rust
self.writer.commit(&heads, FactCacheOffset::new(fact_cache.repr.offset))?;
```

The only way to get a `FactIndex` from a segment is `Segment::facts()`,
which fetches and decodes the whole blob. So both places that commit a
single head decode the entire fact database just to read one number:

- `Transaction::commit` (`transaction.rs:153`), the sync path:
  `storage.get_segment(head).facts()?`
- `ClientState::action` (`client.rs:315`), the action path:
  `segment.facts()?`. Every local action pays one full fact-index decode
  on top of its policy queries. The demonstration tests use the sync path
  and don't exercise this call.

These two sites are one issue with one fix: change `commit_heads` to take
an offset, and give `Segment` a way to return its fact index offset
without fetching it (`SegmentRepr` already stores it in its `facts`
field). Both call sites change together.

The multi-head branch of `commit` isn't affected: `evaluate_braid` gets
its `FactIndex` from `write_facts`, which returns the index it just built
without reading it back.

*B2. The prior index is decoded just to read its depth.*
`write_facts_with_prior` (`linear/mod.rs:534`, fetch at `:549`) decodes
the full prior `FactIndexRepr` to read its `depth`, which decides whether
to compact, and its `offset`. This happens on every segment write and
every `write_facts`. The fix is to carry `depth` alongside the offset.

**C. Compaction rewrites the whole database.**

`compact` (`linear/mod.rs:382`) merges the full chain into a new blob
with no prior about every 16 fact-index writes. That is O(F) work, and it
adds O(F) bytes to the file each time, so file growth is O(n·F/16) over n
commits.

### Impact

With F facts in the graph, each command that queries facts costs O(F),
so a device that performs n actions does O(n²) total work. In the
per-command test below, fact-index blobs are about 98% of all bytes
decoded, at about 12 fact-index fetches per command.

### Proposed fixes (cheapest first)

1. **Stop decoding just to read a field (root cause B).**
   - B1: let `commit_heads` take a `FactCacheOffset` (or a lightweight
     handle) instead of a decoded `FactIndex`, and give `Segment` a way to
     return its fact index offset without fetching it. Update both
     single-head commit sites (`transaction.rs:153`, `client.rs:315`). No
     file format change.
   - B2: carry `depth` next to `offset` in `FactPerspectivePrior::FactIndex`
     (and in `SegmentRepr` next to `facts`/`prior_facts`) so
     `write_facts_with_prior` doesn't need to fetch. No file format change
     if `depth` is worked out when the perspective is built; persisting it
     in `SegmentRepr` would be one.
   - Both are small and self-contained. Neither fixes query cost.
2. **Cache decoded fact indexes by offset (root cause A).**
   - A blob never changes after it is written, so its file offset is a
     perfect cache key and the cache never needs invalidating.
   - An LRU of `Arc<FactIndexRepr>` in the reader or storage turns each
     query into in-memory `BTreeMap` lookups along the chain.
   - Trade-off: the compacted base (the whole database) stays in memory.
     That memory is already being allocated on every query today; the
     cache just keeps it.
   - At minimum, decode the prior once per `LinearFactPerspective` (a lazy
     `OnceCell`) instead of once per query. This helps repeated queries
     within one rule or one braid, but still costs one full decode per
     perspective.
3. **Change the on-disk structure (root causes A and C).**
   - Store facts as paged, sorted blocks (B-tree or LSM style) so a point
     lookup reads O(log F) small pages, a prefix query reads only the
     pages in range, and compaction merges pages incrementally.
   - This is the only fix that keeps per-query memory and I/O bounded as
     the database grows. It is a file format change and needs a
     migration or version bump.

## Demonstration tests

### Files

| File | Change |
|---|---|
| `crates/aranya-runtime/src/storage/linear/testing.rs` | The in-memory backend counts fetches and bytes per storage. `LinearStorage::<Writer>::fetch_stats()` returns a cumulative `FetchStats { fetches, bytes }`, and `FetchStats` supports subtraction for before/after measurements. Counts are per storage, so tests running in parallel don't interfere. |
| `crates/aranya-runtime/src/client/scaling_tests.rs` | The three tests, a minimal test policy (`ScalePolicy`), and a table-printing helper (`Scaling`). |
| `crates/aranya-runtime/src/client.rs` | Registers `mod scaling_tests` under `#[cfg(test)]`. |

The `testing` module is behind the `testing` feature, which other crates
also use (for example `aranya-tcp-syncer`). The added cost there is two
relaxed atomic adds per fetch.

### Running

```text
cargo test -p aranya-runtime --lib scaling_tests -- --ignored --nocapture --test-threads=1
```

The tests are `#[ignore]`d so `cargo make unit-tests` stays green while
the issues are open. They take about 10 seconds in a debug build.

### Design

- **Deterministic.** They measure serialized bytes decoded, not
  wall-clock time. Command IDs and payloads are fixed, so every run
  prints the same numbers on any machine.
- **Scaling, not absolute cost.** Each test runs the same workload at five
  doubling sizes of `n` and prints fetches, bytes decoded, bytes per unit
  of work, and the growth factor per doubling:
  - work that doesn't depend on `n` stays about x1,
  - linear work grows about x2,
  - quadratic work grows about x4.
- **Pass/fail.** A test fails when the last doubling grows by at least
  1.5× the ideal rate, which is halfway to the next complexity class.
- **Test policy.** `ScalePolicy` either does nothing (`q` commands) or
  queries a key that never exists and inserts one new fact keyed by the
  command ID (`F` commands). The missing-key lookup is the worst case: it
  misses every layer of the chain.
- **Compaction phase.** Fact test sizes are multiples of
  `MAX_FACT_INDEX_DEPTH` (16), and the per-command window is 32 commands,
  so every size is compared at the same point in the compaction cycle.

### Tests and current output

**`braid_segment_decoding_is_linear`** (issue 1): two concurrent branches
of `n` commands with 64-byte payloads, off init, each written as one
segment. It measures the `commit` that braids them.

```
== braid two concurrent branches of n commands each (one segment per branch) ==
ideal: bytes decoded grow x2 per doubling of n; x4 means O(n^2)
       n    fetches    bytes decoded      bytes/command   growth
      50        187           941478               9414        -
     100        345          3501061              17505     x3.7
     200        620         12636107              31590     x3.6
     400       1410         57665166              72081     x4.6
     800       2662        218014153             136258     x3.8
```

Fetches grow linearly with `n`, but bytes decoded grow about x4 per
doubling, because each fetch decodes a segment whose size is itself
proportional to `n`.

**`fact_query_cost_is_independent_of_fact_count`** (issue 2, root cause A):
builds a linear graph with one fact per commit (like a device performing
`n` actions), takes a fact perspective at the head, and measures **one**
query for a missing key.

```
== one fact query (missing key) against a database of n facts ==
ideal: bytes decoded grow x1 per doubling of n; x2 means each query is O(n)
       n    fetches    bytes decoded        bytes/query   growth
     128          9             5336               5336        -
     256          2            10515              10515     x2.0
     512          3            21021              21021     x2.0
    1024          5            42033              42033     x2.0
    2048          9            84057              84057     x2.0
```

One lookup takes only 2 to 9 fetches (how many depends on where the head
is in the compaction cycle), but it decodes the entire fact database.

**`per_command_fact_cost_is_independent_of_fact_count`** (issue 2, root
causes A to C end to end): on top of `n` existing facts, it measures
adding and committing 32 more commands, each querying and inserting one
fact.

```
== add + commit one fact command on top of n existing facts ==
ideal: bytes decoded grow x1 per doubling of n; x2 means each command is O(n), so n commands are O(n^2)
       n    fetches    bytes decoded      bytes/command   growth
     128        768           258749               8085        -
     256        823           447769              13992     x1.7
     512        827           805124              25160     x1.8
    1024        858          1522888              47590     x1.9
    2048        915          2957148              92410     x1.9
```

Each test ends with a failure message like:

```
braid two concurrent branches of n commands each (one segment per branch): bytes decoded
grew x3.8 on the last doubling of n (ideal x2, failing at >= x3); see table above
```

### Using the tests to validate fixes

The tests exist to show the problem and to check fixes. After each fix,
rerun them and compare the tables with the output above.

What to expect once the fixes are in:

| Test | Today | After the fix |
|---|---|---|
| `braid_segment_decoding_is_linear` | about x4 per doubling; bytes/command doubles each row | about x2 per doubling; bytes/command roughly flat. Fetches should drop too, since cache hits skip `get_segment`. |
| `fact_query_cost_is_independent_of_fact_count` | x2.0 per doubling; about 41 bytes decoded per fact in the database | With a decoded fact-index cache (work item 4), close to 0 bytes. With a paged index (work item 6), a small number of pages; growth about x1, or slightly above for O(log n). |
| `per_command_fact_cost_is_independent_of_fact_count` | about x1.9 per doubling | About x1 once work items 3a, 3b and 4 are in. The segment reads that remain are small and don't depend on `n`. |

**Caveat: fixes that decode nothing.** The growth column divides one row's
bytes by the previous row's. If a fix makes a measurement decode **0
bytes** (most likely the fact query test with a warm cache), the ratio is
0 / 0 = NaN. The table shows `xNaN`, and the check fails, because
`NaN < limit` is false, even though the problem is fixed. When
validating a cache fix, read the table: a `bytes decoded` column of zeros,
or of small values that don't grow with `n`, means the fix worked. To
keep the tests as regression tests after that, handle the zero case in
`Scaling::run` (treat 0 → 0 as no growth and 0 → non-zero as unbounded)
before removing `#[ignore]`.

Also note:

- Numbers are **decoded bytes on the in-memory backend**. They show how
  cost scales, not wall-clock time. To confirm real-world gains, also time
  the operation on the `libc` backend in a release build.
- A cache that lives at storage level can be warmed while the test builds
  the graph, so the measured step shows the steady state with a warm
  cache. A cache scoped to one operation starts empty for each measurement.
  Both are valid; just know which one you're looking at when reading the
  table.

## What is needed to resolve

### Work items

| # | Issue | Change | Size |
|---|---|---|---|
| 1 | Braid | Segment metadata cache (`SegmentIndex` → `(shortest_max_cut, prior)`) in `ConvergenceMap::advance_to` | Small |
| 2 | Braid | Small segment LRU in `evaluate_braid` | Small |
| 3a | Facts | `commit_heads` takes an offset instead of a decoded `FactIndex`; update both single-head commit sites (`transaction.rs:153`, `client.rs:315`) (root cause B1) | Small |
| 3b | Facts | Carry `depth` alongside the prior fact index offset so `write_facts_with_prior` doesn't fetch (root cause B2) | Small to medium |
| 4 | Facts | Decoded `FactIndexRepr` cache keyed by offset (or at minimum once per perspective) | Medium |
| 5 | Both, optional | Storage-level `Arc<SegmentRepr>` LRU in `LinearStorage::get_segment` | Medium |
| 6 | Facts, long term | Paged on-disk fact index with incremental compaction | Large (format change) |

Items 1 and 2 should make `braid_segment_decoding_is_linear` pass. Item 4
should make `fact_query_cost_is_independent_of_fact_count` pass. Items 3a,
3b and 4 together should make `per_command_fact_cost_is_independent_of_fact_count`
pass. Item 3a on its own is the quickest win for local actions.

Item 6 is what keeps memory bounded when the fact database is larger
than we want to hold in memory.

### Acceptance criteria

- The scaling tables for all three tests show the expected growth (see
  [Using the tests to validate fixes](#using-the-tests-to-validate-fixes)).
  If the tests are kept as CI regression tests, handle the zero-bytes case
  in `Scaling::run` first, then remove `#[ignore]`.
- Existing `aranya-runtime` unit tests, braid tests, and
  `cargo make correctness` still pass.
- `no_std` canaries still build. Any cache must use `alloc` only (for
  example `BTreeMap`, `Arc`, `core::cell::RefCell`), not `std` types.

### Decisions needed

- **Memory budget for caches.** How many segments and fact-index blobs
  may be kept resident, and should the limit be configurable per
  platform (for example the `low-mem-usage` feature)?
- **Where caches live.** Scoped to one operation (`evaluate_braid`, one
  `ConvergenceMap`, one perspective), which is simple and needs no
  invalidation, or at storage level, which is broader but needs interior
  mutability behind `&self`.
- **Whether a file format change is acceptable** for item 3b (if `depth`
  is persisted in `SegmentRepr`) and 6, and the migration or versioning story.
- **Segment length cap.** Whether to also limit commands per segment, which
  bounds issue 1 regardless of caching but changes how sync batches are
  stored.

### Not yet investigated

- Other per-location `get_segment` callers that may have the same pattern:
  `sync/requester.rs:434`, `sync/responder.rs:216`, `:469`, `:701`,
  `storage/mod.rs:672`, `:851`.
- Real-disk cost on the `libc` backend. The tests measure decoded bytes on
  the in-memory backend; on disk each fetch also adds `pread` calls and a
  full-size allocation, so wall-clock impact will be higher.
