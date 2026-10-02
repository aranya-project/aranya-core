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

Nothing caches the result of a read, so every one of these reads pays
for the whole item again.

As a result, an operation meant to cost O(1), such as getting one
command or looking up one fact, actually costs O(size of the graph). Any
loop over commands or facts becomes O(n²):

1. **Braid is O(n²)** in the length of the branches being merged,
   because every command in a branch re-reads that branch's whole
   segment.
2. **Each fact query is O(total facts)**, because it re-reads the whole
   fact database. So n commands that each query facts cost O(n²).

Fixing this means either not repeating the reads (cache fetched items,
and stop reading whole items just to get one field) or making stored
items readable in smaller pieces (bounded segments, a paged fact index).

**Status after the switch to `rkyv` (#676):** storage now uses zero-copy
`rkyv` archives instead of postcard. That made each read much cheaper
(about 7× for per-command fact cost and about 70× for braid, see
[Effect of the `rkyv` switch](#effect-of-the-rkyv-switch)), but **it did
not change how cost scales.** Every root cause below is still present,
and all three demonstration tests still fail with the same growth rates.

Both issues are reproduced by deterministic tests in
`crates/aranya-runtime/src/client/scaling_tests.rs` (see
[Demonstration tests](#demonstration-tests)).

## Background: how linear storage reads data

Every item in linear storage (segments, fact indexes, head sets) is
written once with `Write::append` as a length-prefixed `rkyv` archive, and
read back with `Read::fetch<T>(offset)`, which returns a
`Read::Handle<T>` that derefs to `T::Archived`. Nothing is deserialized
into an owned `T`, but every fetch still validates the whole archive:

- Both backends call `Readable::yoke` (`storage/linear/io.rs:169`), which
  runs `rkyv::access` with `bytecheck`. Validation walks the entire
  archived structure: every command in a segment and every node of every
  fact map in a fact index.
- `libc` backend (`storage/linear/libc/imp.rs:550`, `File::load`): reads the
  4-byte length, allocates a zeroed buffer of that size, `pread`s the full
  blob into it, then validates it. The handle owns that buffer.
- In-memory test backend (`storage/linear/testing.rs`): validates the
  stored bytes in place. There is no copy and no allocation.

There is no partial read and no cache. Every `fetch` costs O(number of
elements in the item) for validation. On the `libc` backend it also
costs O(size of the item) for the read and the allocation, plus a
syscall.

Validation does not appear to touch byte payloads: the braid measurement
below validates about 4 GB of archives in about 60 ms. So on the in-memory
backend, cost now scales with the number of commands, updates and facts in
an item rather than with its raw size. The `libc` backend still copies
every byte.

The two item types that matter here are:

| Item | Type | Contents | Size bound |
|---|---|---|---|
| Segment | `SegmentRepr` (`linear/mod.rs:83`) | header plus `NonEmpty<CommandData>`; each command has its full `data` bytes and all fact `updates` | **Unbounded.** A linear run of commands (for example a whole sync batch) becomes one segment. |
| Fact index | `FactIndexRepr` (`linear/mod.rs:125`) | `offset`, `prior`, `depth`, and a `BTreeMap<String, TrieMap>` of facts (`linear/triemap.rs`) | A delta over `prior`. After compaction, the **entire fact database**. |

## Effect of the `rkyv` switch

#676 replaced postcard with `rkyv` and made `fetch` return a zero-copy
handle instead of an owned, deserialized value. Measured on the same
machine before and after (release build, in-memory backend):

| Workload | Before | After | Speedup | Growth per doubling |
|---|---|---|---|---|
| Braid commit, two branches of 2000 commands | 4.30 s | 63 ms | about 70× | about x4, unchanged |
| Add + commit one fact command on 8192 facts | 3.14 ms | 425 µs | about 7× | about x2, unchanged |
| Build a graph of 8192 facts, one per commit | 11.6 s | 1.52 s | about 8× | about x4, unchanged |

The constant factor dropped because nothing is deserialized into owned
`BTreeMap`s and `Vec`s any more. The scaling did not change because the
access pattern did not: the same call sites still fetch the same whole
items the same number of times, and each fetch still validates (and on
`libc`, reads and allocates) the whole item. The full tables are under
each issue below.

The braid speedup is larger because on the in-memory backend validation
skips byte payloads, so payload size no longer matters there. On the
`libc` backend each fetch still reads every payload byte, so expect a
smaller gain on disk.

## Issue 1: per-command segment access during braid is O(n²)

### Root cause

`LinearStorage::get_segment` (`storage/linear/mod.rs:731`) fetches and
validates the full `SegmentRepr`: every command and every command's fact
updates. On the `libc` backend it also reads and allocates every
command's payload. Two places in the braid path call it once per
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
   `storage/mod.rs:990`), which are a few bytes out of a blob that can be
   megabytes.

`braid()` itself (`client/braiding.rs:216`) is **not** affected: a
`Strand` keeps its segment while walking it, and `Strand::new` reuses the
cached segment when one is passed in (`braiding.rs:330`).

For a braid over a branch of `k` commands stored as one segment, both
call sites fetch about `k` segments of `O(k)` commands each, which is
O(k²).

### Impact

- Merging after a long offline period, or syncing a peer's long linear
  history, braids long single-segment branches.
- `commit` with multiple heads (`transaction.rs:160`) and `add_merge`
  (`transaction.rs:341`) both go through `evaluate_braid`.
- The newly supported very large commands (#758) make each fetch
  proportionally more expensive on the `libc` backend, which reads and
  allocates every payload byte.

Release-build measurement, in-memory backend, two branches of `k`
commands with 200-byte payloads, timing the `commit` that braids them.
Both columns were measured on the same machine.

| k | before `rkyv` | after `rkyv` | bytes fetched (after) |
|---|---|---|---|
| 500 | 213 ms | 3.2 ms | 204 MB |
| 1000 | 1.06 s | 15 ms | 981 MB |
| 2000 | 4.30 s | 63 ms | 4.13 GB |
| 4000 | 16.3 s | 224 ms | 14.7 GB |

Both columns still grow about x4 per doubling of `k`. On the `libc`
backend each of those fetches is also a pair of `pread`s and an
allocation of the full segment size, so the `libc` cost is closer to the
"bytes fetched" column than the in-memory timing suggests.

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
- **`evaluate_braid`:** cache fetched segments by `SegmentIndex` across
  loop iterations.
  - Caching only the last segment is **not enough**. Braid order
    interleaves strands by `(priority, id)`, so consecutive locations
    alternate between segments. Use a small LRU sized to the number of
    concurrent strands (heads), or at least a few entries.
- **Optional, broader:** an LRU of segment handles inside
  `LinearStorage::get_segment`. This also speeds up `lca_pair`, the sync
  responder and requester, `has_nearby_rich_anchor`, and
  `walk_collecting_skips`. It needs interior mutability, because
  `get_segment` takes `&self`. `Storage` has no `Send` bound, so a
  `RefCell` would work in `no_std` with `alloc`.
  - A `Read::Handle` owns its buffer and isn't `Clone`, so a cache needs a
    shareable handle, for example by putting the buffer behind an
    `Rc`/`Arc` before yoking it.
- **Longer term:** make segment access not require reading and
  validating every command, either by capping segment length or by
  storing per-command offsets so one command can be read on its own.

## Issue 2: fact queries re-fetch whole index blobs

### Root causes

**A. Every query fetches and validates the full fact index chain.**

- `LinearFactPerspective::query` (`linear/mod.rs:1062`, fetch at `:1073`):
  on a miss in the perspective's in-memory map, it fetches the prior
  `FactIndexRepr` **on every call** and wraps it in a temporary
  `LinearFactIndex`.
- `LinearFactIndex::query` (`linear/mod.rs:959`): walks the `prior` chain
  and fetches and validates each blob, up to `MAX_FACT_INDEX_DEPTH` = 16
  (`linear/mod.rs:61`).
- The `query_prefix_inner` paths (`linear/mod.rs:986`, `:1090`/`:1098`)
  do the same and also build a new `TrieMap` of all matches.
- `LinearStorage::fact_cache` (`linear/mod.rs:747`) fetches the full
  committed index for `Session::new` (`client/session.rs:56`). The session
  keeps it as `base_facts` and queries it (`session.rs:311`, `:323`), so
  the fetch isn't wasted, but it is the same problem: the whole top layer
  is read up front, and queries that miss it still fetch and validate
  each prior layer.

After compaction, the bottom of the chain holds **every fact in the
graph**. A lookup for a key that doesn't exist (the common case for policy
`!exists` checks) therefore validates the entire fact database, and on
the `libc` backend reads it from disk. The lookup inside each layer is now
a cheap probe into the archived `TrieMap`, but the fetched handle is
thrown away after each query, so the next query in the same policy rule
fetches and validates it again.

**B. Full blobs are fetched just to read one small field.**

This has two separate causes, each with its own fix.

*B1. `commit_heads` takes a fetched index but only needs its offset.*
`Storage::commit_heads` takes a full `FactIndex`, but it only uses the
offset:

```rust
self.writer.commit(
    &heads,
    FactCacheOffset::new(fact_cache.repr.offset.to_native()),
)?;
```

The only way to get a `FactIndex` from a segment is `Segment::facts()`,
which fetches and validates the whole blob. So both places that commit a
single head read the entire fact database just to get one number:

- `Transaction::commit` (`transaction.rs:153`), the sync path:
  `storage.get_segment(head).facts()?`
- `ClientState::action` (`client.rs:315`), the action path:
  `segment.facts()?`. Every local action pays one full fact-index fetch
  on top of its policy queries. The demonstration tests use the sync path
  and don't exercise this call.

These two sites are one issue with one fix: change `commit_heads` to take
an offset, and give `Segment` a way to return its fact index offset
without fetching it (`SegmentRepr` already stores it in its `facts`
field). Both call sites change together.

The multi-head branch of `commit` isn't affected: `evaluate_braid` gets
its `FactIndex` from `write_facts`, which returns the index it just built
without reading it back.

*B2. The prior index is fetched just to read its depth.*
`write_facts_with_prior` (`linear/mod.rs:536`, fetch at `:551`) fetches
the full prior `FactIndexRepr` to read its `depth`, which decides whether
to compact, and its `offset`. This happens on every segment write and
every `write_facts`. The fix is to carry `depth` alongside the offset.

**C. Compaction rewrites the whole database.**

`compact` (`linear/mod.rs:379`) merges the full chain into a new blob
with no prior about every 16 fact-index writes. That is O(F) work, and it
adds O(F) bytes to the file each time, so file growth is O(n·F/16) over n
commits.

### Impact

With F facts in the graph, each command that queries facts costs O(F),
so a device that performs n actions does O(n²) total work. In the
per-command test below, fact-index blobs make up nearly all bytes
fetched.

Release-build measurement, in-memory backend, adding and committing one
fact command on top of `n` existing facts (averaged over 256 commands),
plus the time to build the `n`-fact graph one command per commit. Both
were measured on the same machine.

| n | per command, before `rkyv` | per command, after `rkyv` | build graph, before | build graph, after |
|---|---|---|---|---|
| 1024 | 352 µs | 50 µs | 158 ms | 23 ms |
| 2048 | 697 µs | 96 µs | 654 ms | 97 ms |
| 4096 | 1.39 ms | 182 µs | 2.70 s | 352 ms |
| 8192 | 3.14 ms | 425 µs | 11.6 s | 1.52 s |

Per-command cost still doubles with `n`, and building the graph is still
O(n²).

### Proposed fixes (cheapest first)

1. **Stop fetching whole blobs just to read a field (root cause B).**
   - B1: let `commit_heads` take a `FactCacheOffset` (or a lightweight
     handle) instead of a fetched `FactIndex`, and give `Segment` a way to
     return its fact index offset without fetching it. Update both
     single-head commit sites (`transaction.rs:153`, `client.rs:315`). No
     file format change.
   - B2: carry `depth` next to `offset` in `FactPerspectivePrior::FactIndex`
     (and in `SegmentRepr` next to `facts`/`prior_facts`) so
     `write_facts_with_prior` doesn't need to fetch. No file format change
     if `depth` is worked out when the perspective is built; persisting it
     in `SegmentRepr` would be one.
   - Both are small and self-contained. Neither fixes query cost.
2. **Cache fetched fact indexes by offset (root cause A).**
   - A blob never changes after it is written, so its file offset is a
     perfect cache key and the cache never needs invalidating.
   - An LRU of shareable fact-index handles in the reader or storage
     turns each query into archived `TrieMap` probes along the chain,
     with no fetch or validation. As with segments, this needs a
     `Clone`-able handle (buffer behind `Rc`/`Arc`).
   - Trade-off: the compacted base (the whole database) stays in memory.
     On the `libc` backend that memory is already being allocated on
     every query today; the cache just keeps it.
   - At minimum, fetch the prior once per `LinearFactPerspective` (a lazy
     `OnceCell`) instead of once per query. This helps repeated queries
     within one rule or one braid, but still costs one full fetch per
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
| `crates/aranya-runtime/src/storage/linear/testing.rs` | The in-memory backend counts fetches and the serialized bytes of each fetched item, per storage. `LinearStorage::<Writer>::fetch_stats()` returns a cumulative `FetchStats { fetches, bytes }`, and `FetchStats` supports subtraction for before/after measurements. Counts are per storage, so tests running in parallel don't interfere. |
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

- **Deterministic.** They measure the serialized bytes of every item
  fetched (and so validated), not wall-clock time. Command IDs and payloads are fixed, so every run
  prints the same numbers on any machine.
- **Scaling, not absolute cost.** Each test runs the same workload at five
  doubling sizes of `n` and prints fetches, bytes fetched, bytes per unit
  of work, and the growth factor per doubling:
  - work that doesn't depend on `n` stays about x1,
  - linear work grows about x2,
  - quadratic work grows about x4.
- **Pass/fail.** A test fails when the last doubling grows by at least
  1.5× the ideal rate, which is halfway to the next complexity class. If
  neither of the last two sizes fetched any bytes, there is no growth and
  the test passes (see `growth` and its test `growth_handles_zero_bytes`).
- **Test policy.** `ScalePolicy` either does nothing (`q` commands) or
  queries a key that never exists and inserts one new fact keyed by the
  command ID (`F` commands). The missing-key lookup is the worst case: it
  misses every layer of the chain.
- **Compaction phase.** Fact test sizes are multiples of
  `MAX_FACT_INDEX_DEPTH` (16), and the per-command window is 32 commands,
  so every size is compared at the same point in the compaction cycle.

### Tests and current output

Output below is from the code after the `rkyv` switch (#676). The column
headers still say "bytes decoded"; they count bytes fetched. Byte counts
are about 1.3 to 1.7× higher than they were with postcard, because `rkyv`
archives are larger (fixed-width integers and alignment padding). Growth
rates are unchanged.

**`braid_segment_decoding_is_linear`** (issue 1): two concurrent branches
of `n` commands with 64-byte payloads, off init, each written as one
segment. It measures the `commit` that braids them.

```
== braid two concurrent branches of n commands each (one segment per branch) ==
ideal: bytes decoded grow x2 per doubling of n; x4 means O(n^2)
       n    fetches    bytes decoded      bytes/command   growth
      50        188          1243808              12438        -
     100        346          4567544              22837     x3.7
     200        621         16381544              40953     x3.6
     400       1411         74507624              93134     x4.5
     800       2663        281196008             175747     x3.8
```

Fetches grow linearly with `n`, but bytes fetched grow about x4 per
doubling, because each fetch reads a segment whose size is itself
proportional to `n`.

**`fact_query_cost_is_independent_of_fact_count`** (issue 2, root cause A):
builds a linear graph with one fact per commit (like a device performing
`n` actions), takes a fact perspective at the head, and measures **one**
query for a missing key.

```
== one fact query (missing key) against a database of n facts ==
ideal: bytes decoded grow x1 per doubling of n; x2 means each query is O(n)
       n    fetches    bytes decoded        bytes/query   growth
     128          9            10520              10520        -
     256          2            16800              16800     x1.6
     512          3            33416              33416     x2.0
    1024          5            66656              66656     x2.0
    2048          9           133144             133144     x2.0
```

One lookup takes only 2 to 9 fetches (how many depends on where the head
is in the compaction cycle), but it fetches the entire fact database.

**`per_command_fact_cost_is_independent_of_fact_count`** (issue 2, root
causes A to C end to end): on top of `n` existing facts, it measures
adding and committing 32 more commands, each querying and inserting one
fact.

```
== add + commit one fact command on top of n existing facts ==
ideal: bytes decoded grow x1 per doubling of n; x2 means each command is O(n), so n commands are O(n^2)
       n    fetches    bytes decoded      bytes/command   growth
     128        834           592432              18513        -
     256        889           910024              28438     x1.5
     512        893          1500872              46902     x1.6
    1024        924          2689504              84047     x1.8
    2048        981          5063576             158236     x1.9
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
| `fact_query_cost_is_independent_of_fact_count` | x2.0 per doubling; about 65 bytes fetched per fact in the database | With a fact-index cache (work item 4), close to 0 bytes. With a paged index (work item 6), a small number of pages; growth about x1, or slightly above for O(log n). |
| `per_command_fact_cost_is_independent_of_fact_count` | about x1.9 per doubling | About x1 once work items 3a, 3b and 4 are in. The segment reads that remain are small and don't depend on `n`. |

**Fixes that fetch nothing.** If a fix makes a measurement fetch **0
bytes** (most likely the fact query test with a warm cache), the growth
column shows `x-` and the check passes. Growing from 0 to a non-zero
count counts as unbounded growth and fails.

Also note:

- Numbers are **fetched bytes on the in-memory backend**. They show how
  cost scales, not wall-clock time. Since the `rkyv` switch the in-memory
  backend is zero-copy, so its wall-clock time understates the `libc`
  backend, which still reads and allocates every fetched byte. To confirm
  real-world gains, also time the operation on the `libc` backend in a
  release build.
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
| 3a | Facts | `commit_heads` takes an offset instead of a fetched `FactIndex`; update both single-head commit sites (`transaction.rs:153`, `client.rs:315`) (root cause B1) | Small |
| 3b | Facts | Carry `depth` alongside the prior fact index offset so `write_facts_with_prior` doesn't fetch (root cause B2) | Small to medium |
| 4 | Facts | Fact-index handle cache keyed by offset (or at minimum once per perspective) | Medium |
| 5 | Both, optional | Storage-level segment handle LRU in `LinearStorage::get_segment` | Medium |
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
  To keep them as CI regression tests, remove `#[ignore]`.
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
- **Skipping validation.** Every fetch runs `bytecheck` over the whole
  archive. Items read back from our own file could use
  `rkyv::access_unchecked` (or validate once and cache), which removes the
  per-fetch O(elements) walk. The trade-off is that a corrupted or
  tampered file becomes undefined behavior instead of an `IoError`.

### Not yet investigated

- Other per-location `get_segment` callers that may have the same pattern:
  `sync/requester.rs:434`, `sync/responder.rs:216`, `:469`, `:701`,
  `storage/mod.rs:684`, `:863`.
- Real-disk cost on the `libc` backend. The tests measure fetched bytes on
  the in-memory backend, which is now zero-copy; on disk each fetch also
  adds `pread` calls and a full-size allocation, so wall-clock impact will
  be higher than the in-memory timings above.
