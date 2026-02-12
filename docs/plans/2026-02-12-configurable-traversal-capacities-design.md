# Configurable Traversal Buffer Capacities via View Types

## Problem

The traversal buffer capacities (`VISITED_CAPACITY` and `QUEUE_CAPACITY`, both 256) are
compile-time constants baked into type aliases. Different deployment targets need different
capacities (64 for small embedded, 256 for standard embedded, 512 for server), but there
is no way to select them without changing the source.

PR #522 review feedback requested making these configurable. Reviewer jdygert-spok
specifically suggested using heapless 0.9 view types (`DequeView`, `VecView`) to decouple
capacity from the algorithm code.

## Approach: Const Generics + View Types

Split each buffer type into a **sized owner** (generic over capacity) and an **unsized view**
(capacity-erased). Generics exist on the owning types but stop at the API boundary — all
algorithm code works with views.

```
Sized (owns storage)              Unsized (used in APIs)
─────────────────────             ─────────────────────
CappedVisited<CAP>          →     CappedVisitedView
  wraps Vec<Entry, CAP>            wraps VecView<Entry>

Deque<Location, Q>          →     DequeView<Location>
  (heapless provides both)

TraversalBufferPair<V, Q>   →     TraversalBufferPairView<'a>
  owns CappedVisited<V>            holds &mut CappedVisitedView
  owns Deque<Location, Q>          holds &mut DequeView<Location>

TraversalBuffers<V, Q>           (no view needed — never passed
  owns two Pairs                   directly to algorithms)
```

Default capacities `V = 256, Q = 256` on all generic types, so existing code compiles
unchanged.

## CappedVisitedView

`CappedVisited<CAP>` wraps `heapless::Vec<(SegmentIndex, MaxCut, MaxCut), CAP>`. With
heapless 0.9, `Vec<T, N>` auto-coerces to `&mut VecView<T>`, enabling a view wrapper:

```rust
#[repr(transparent)]
pub struct CappedVisitedView {
    entries: VecView<(SegmentIndex, MaxCut, MaxCut)>,
}

pub struct CappedVisited<const CAP: usize> {
    entries: Vec<(SegmentIndex, MaxCut, MaxCut), CAP>,
}
```

All method logic (`get`, `insert_or_update`, `mark_segment_visited`, `was_segment_visited`,
`clear`) moves to `CappedVisitedView`. `CappedVisited<CAP>` inherits these via
`Deref`/`DerefMut`:

```rust
impl<const CAP: usize> Deref for CappedVisited<CAP> {
    type Target = CappedVisitedView;
    fn deref(&self) -> &CappedVisitedView {
        // Safety: CappedVisitedView is #[repr(transparent)] over VecView
        unsafe { &*(self.entries.as_view() as *const VecView<_> as *const CappedVisitedView) }
    }
}
```

The `#[repr(transparent)]` + pointer cast pattern is the same one heapless uses internally.

## TraversalBufferPairView

```rust
pub struct TraversalBufferPairView<'a> {
    pub visited: &'a mut CappedVisitedView,
    pub queue: &'a mut DequeView<Location>,
}
```

`TraversalBufferPair::get()` changes its return type from
`(&mut TraversalVisited, &mut TraversalQueue)` to `TraversalBufferPairView<'_>`.
It still clears both buffers before returning.

## API Boundaries

Functions that currently take `&mut TraversalBufferPair` change to
`TraversalBufferPairView<'_>`:

- `Storage::get_location()`
- `Storage::get_location_from()`
- `Storage::commit()`
- `Storage::is_ancestor()`
- `braid()`
- `Transaction::locate()`
- `PeerCache::add_command()`

Functions that take `&mut TraversalBuffers` (like `find_needed_segments`,
`Transaction::commit`) keep taking the generic owned type — they create views from their
owned pairs and pass those to the algorithm functions.

`push_queue` changes to `push_queue(queue: &mut DequeView<Location>, loc: Location)` and
uses `queue.capacity()` (runtime) instead of the `QUEUE_CAPACITY` constant for the error
message.

### Where generics propagate vs. stop

| Layer | Generic? |
|---|---|
| `TraversalBuffers<V, Q>`, `TraversalBufferPair<V, Q>` | Yes (owns storage) |
| `ClientState<PS, SP, V, Q>` | Yes (owns TraversalBuffers) |
| `SyncRequester<V, Q>`, `SyncResponder<V, Q>` | Yes (owns TraversalBuffers) |
| `Storage` trait methods | No (takes views) |
| `braid()`, `locate()`, `push_queue()` | No (takes views) |

## Convenience Type Aliases

```rust
pub type TraversalBuffersSmall    = TraversalBuffers<64, 64>;
pub type TraversalBuffersStandard = TraversalBuffers<256, 256>;  // = default
pub type TraversalBuffersLarge    = TraversalBuffers<512, 512>;
```

## heapless 0.8 → 0.9 Upgrade

Prerequisite step. heapless is used in 6 files across 3 crates:

| Crate | File | Types Used |
|---|---|---|
| `aranya-runtime` | `storage/visited.rs` | `Vec` |
| `aranya-runtime` | `sync/requester.rs` | `Vec` |
| `aranya-runtime` | `sync/responder.rs` | `Vec`, `Deque` |
| `aranya-runtime` | `sync/dispatcher.rs` | `Vec` |
| `aranya-policy-vm` | `machine.rs` | `Vec` (aliased as `HVec`) |
| `aranya-quic-syncer` | `lib.rs` | `Vec`, `FnvIndexMap` |

Known breaking changes: `Vec::capacity()` no longer const, new optional `LenT` param
(defaults to `usize`). The `serde` feature and `postcard` compatibility must be verified.

## Migration Order

1. Upgrade heapless 0.8 → 0.9, fix breakage, run full test suite
2. Add `CappedVisitedView` — move method impls to view, add Deref/DerefMut
3. Make `TraversalBufferPair` and `TraversalBuffers` generic with defaults
4. Introduce `TraversalBufferPairView`, change `get()` return type, update `push_queue`
5. Convert Storage trait methods to take views
6. Convert remaining algorithm functions (`braid`, `locate`, `PeerCache::add_command`)
7. Propagate generics to owners (`ClientState`, `SyncRequester`, `SyncResponder`)
8. Add convenience type aliases and a test with non-default capacities

Each step should compile and pass existing tests before proceeding.
