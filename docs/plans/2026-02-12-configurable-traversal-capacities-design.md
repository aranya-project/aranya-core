# Caller-Controlled Traversal Buffer Allocation

## Problem

`TraversalBuffers` (two pairs of visited set + queue, ~12 KB on 64-bit) is currently
constructed internally by `ClientState`, `SyncRequester`, `SyncResponder`, and test
infrastructure. This forces stack allocation at the point of construction, which is
problematic for embedded targets with limited stack space.

PR #522 review feedback requested making the allocation controllable. The simplest step
toward that is letting the caller own the allocation and pass it in.

## Approach: Pass TraversalBuffers into Constructors

No changes to types, capacities, or the Storage trait. The only change: structs that
currently create `TraversalBuffers::new()` internally instead accept them as a constructor
parameter. This lets callers choose how to allocate:

```rust
// Stack (current behavior, just explicit now):
let buffers = TraversalBuffers::new();
let client = ClientState::new(policy_store, provider, buffers);

// Heap:
let buffers = Box::new(TraversalBuffers::new());
let client = ClientState::new(policy_store, provider, *buffers);
// (or change the field to Box<TraversalBuffers> if heap is always preferred)

// Static:
static BUFFERS: TraversalBuffers = TraversalBuffers::new();
// (requires interior mutability wrapper for &mut access)
```

## What Changes

### Structs that own TraversalBuffers

| Struct | File | Current constructor |
|---|---|---|
| `ClientState<PS, SP>` | `client.rs:59` | `new(policy_store, provider)` |
| `SyncRequester` | `sync/requester.rs:102` | `new(graph_id, rng)`, `new_session_id(graph_id, session_id)` |
| `SyncResponder` | `sync/responder.rs:157` | `new()`, `Default::default()` |

Each constructor gains a `buffers: TraversalBuffers` parameter. The internal
`TraversalBuffers::new()` calls are removed.

### Local construction sites (not struct fields)

These create `TraversalBuffers` as local variables and are unaffected by the struct
constructor changes, but are listed for completeness:

| Location | File |
|---|---|
| `MemStorageProvider::new_storage` | `storage/memory.rs:104` |
| `GraphBuilder::init` | `client/transaction.rs:674` |
| DSL test runner | `testing/dsl.rs:550` |

These can stay as-is (local stack allocation is fine for tests and one-shot operations).

## What Does NOT Change

- `TraversalBuffers`, `TraversalBufferPair`, `CappedVisited` types — unchanged
- `Storage` trait methods — unchanged
- Algorithm code — unchanged
- heapless version — stays at 0.8
- Capacities — stay at 256/256
