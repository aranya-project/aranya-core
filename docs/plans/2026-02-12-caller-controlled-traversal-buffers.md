# Caller-Controlled Traversal Buffer Allocation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let callers control TraversalBuffers allocation by passing them into constructors instead of creating them internally.

**Architecture:** Remove internal `TraversalBuffers::new()` from `ClientState`, `SyncRequester`, and `SyncResponder` constructors. Add a `buffers` parameter instead. No type changes, no algorithm changes.

**Tech Stack:** Rust, heapless 0.8 (unchanged)

---

### Task 1: Update ClientState to accept TraversalBuffers

**Files:**
- Modify: `crates/aranya-runtime/src/client.rs:75-83`

**Step 1: Change ClientState::new() signature**

Add `buffers: TraversalBuffers` parameter and remove internal construction:

```rust
// Before (line 77):
pub const fn new(policy_store: PS, provider: SP) -> Self {
    Self {
        policy_store,
        provider,
        buffers: TraversalBuffers::new(),
    }
}

// After:
pub const fn new(policy_store: PS, provider: SP, buffers: TraversalBuffers) -> Self {
    Self {
        policy_store,
        provider,
        buffers,
    }
}
```

**Step 2: Verify it compiles (expect errors from callers)**

Run: `cargo check -p aranya-runtime 2>&1 | head -50`
Expected: Compilation errors at every `ClientState::new()` call site — these are fixed in Task 2.

---

### Task 2: Update all ClientState::new() call sites

**Files (add `TraversalBuffers::new()` as third argument to each call):**
- Modify: `crates/aranya-runtime/src/client/transaction.rs` — lines 845, 874, 914, 945, 971, 997, 1026 (test `graph!` macro calls)
- Modify: `crates/aranya-runtime/src/testing/dsl.rs` — line 560
- Modify: `crates/aranya-runtime/src/testing/vm.rs` — lines 357, 424, 463, 627, 643
- Modify: `crates/aranya-runtime/benches/vm.rs` — lines 20, 115
- Modify: `crates/aranya-model/src/tests/mod.rs` — lines 96, 173, 1299, 1368
- Modify: `crates/aranya-quic-syncer/tests/test.rs` — line 300
- Modify: `crates/aranya-quic-syncer/benches/quic_syncer.rs` — line 67
- Modify: `crates/aranya-quic-syncer/examples/quic_syncer.rs` — line 114
- Modify: `crates/aranya-runtime/src/lib.rs` — line 21 (doc comment)
- Modify: `crates/aranya-runtime/src/vm_policy.rs` — line 83 (doc comment)

**Step 1: Add TraversalBuffers::new() to each call site**

Each `ClientState::new(ps, sp)` becomes `ClientState::new(ps, sp, TraversalBuffers::new())`.

Some files may need a new import: `use crate::TraversalBuffers;` or adjust existing imports.

**Step 2: Verify compilation**

Run: `cargo check --workspace`
Expected: Clean compilation (SyncRequester/SyncResponder errors come later).

**Step 3: Run tests**

Run: `cargo test -p aranya-runtime`
Expected: All tests pass.

**Step 4: Commit**

```
feat: accept TraversalBuffers in ClientState constructor

Lets callers control allocation of traversal buffers instead of
forcing internal stack allocation. Addresses PR #522 feedback.
```

---

### Task 3: Update SyncRequester to accept TraversalBuffers

**Files:**
- Modify: `crates/aranya-runtime/src/sync/requester.rs:111-139`

**Step 1: Change both constructors**

```rust
// new() — add buffers parameter (line 113):
pub fn new<R: Csprng>(graph_id: GraphId, rng: &mut R, buffers: TraversalBuffers) -> Self {
    // ... same body but replace `buffers: TraversalBuffers::new()` with `buffers`
}

// new_session_id() — add buffers parameter (line 130):
pub fn new_session_id(graph_id: GraphId, session_id: u128, buffers: TraversalBuffers) -> Self {
    // ... same body but replace `buffers: TraversalBuffers::new()` with `buffers`
}
```

**Step 2: Update all SyncRequester call sites**

Each `SyncRequester::new(graph_id, rng)` becomes
`SyncRequester::new(graph_id, rng, TraversalBuffers::new())`.

Each `SyncRequester::new_session_id(graph_id, sid)` becomes
`SyncRequester::new_session_id(graph_id, sid, TraversalBuffers::new())`.

Call sites:
- `crates/aranya-model/src/model.rs:509`
- `crates/aranya-quic-syncer/src/lib.rs:381`
- `crates/aranya-quic-syncer/benches/quic_syncer.rs:160`
- `crates/aranya-quic-syncer/tests/test.rs:72,128,139,166,196,239,248`
- `crates/aranya-quic-syncer/examples/quic_syncer.rs:69`
- `crates/aranya-runtime/src/testing/dsl.rs:938`
- `crates/aranya-runtime/src/testing/vm.rs:589`

**Step 3: Verify and test**

Run: `cargo check --workspace && cargo test -p aranya-runtime`
Expected: All pass.

**Step 4: Commit**

```
feat: accept TraversalBuffers in SyncRequester constructors
```

---

### Task 4: Update SyncResponder to accept TraversalBuffers

**Files:**
- Modify: `crates/aranya-runtime/src/sync/responder.rs:169-183`

**Step 1: Change constructor and Default impl**

```rust
// new() — add buffers parameter (line 171):
pub fn new(buffers: TraversalBuffers) -> Self {
    Self {
        session_id: None,
        graph_id: None,
        state: SyncResponderState::New,
        bytes_sent: 0,
        next_send: 0,
        message_index: 0,
        has: Vec::new(),
        to_send: Vec::new(),
        buffers,
    }
}
```

Remove the `Default` derive (line 156) since `new()` now takes a parameter. If
`Default` is needed, implement it explicitly with `TraversalBuffers::new()`.
Check whether anything calls `SyncResponder::default()` — if so, keep the manual
`Default` impl.

**Step 2: Update all SyncResponder call sites**

Each `SyncResponder::new()` becomes `SyncResponder::new(TraversalBuffers::new())`.

Call sites:
- `crates/aranya-quic-syncer/src/lib.rs:338,423`
- `crates/aranya-runtime/src/testing/dsl.rs:99`

**Step 3: Verify and test**

Run: `cargo check --workspace && cargo test -p aranya-runtime`
Expected: All pass.

**Step 4: Run the full test suite**

Run: `cargo make unit-tests`
Expected: All pass across the workspace.

**Step 5: Commit**

```
feat: accept TraversalBuffers in SyncResponder constructor
```

---

### Task 5: Update doc comments

**Files:**
- Modify: `crates/aranya-runtime/src/lib.rs:21` (doc example)
- Modify: `crates/aranya-runtime/src/vm_policy.rs:83` (doc example)

**Step 1: Update doc examples to pass TraversalBuffers**

These are `//!` doc comments showing usage. Add `TraversalBuffers::new()` to the
`ClientState::new()` calls.

**Step 2: Run doc tests**

Run: `cargo test -p aranya-runtime --doc`
Expected: Pass (or already not compiled if behind cfg).

**Step 3: Run correctness checks**

Run: `cargo make correctness`
Expected: All pass.

**Step 4: Commit**

```
docs: update examples for new ClientState constructor signature
```
