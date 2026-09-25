---
layout: page
title: Policy Obligation Analysis
permalink: "/policy-obligation-analysis/"
---

# Policy Obligation Analysis

## Overview

The policy language distinguishes two kinds of terminating errors (see
[Errors](/policy-book/reference/errors.md)):

- **Rejections** are anticipated failures. A `check` whose expression
  is false, or coalescing a `None` with `or`, produces one deliberately.
  They are part of normal operation.
- **Runtime exceptions** are violations of execution invariants that
  the policy author did not anticipate. Policy code cannot detect or
  recover from them, they do not run `recall` blocks, and they surface
  as errors to the application.

Five runtime exceptions concern fact mutations:

1. `create` of a fact whose key already exists.
2. `update` of a fact that does not exist.
3. `update F[k]=>{v: x} to {..}` when the stored value of `v` is not
   `x`.
4. `delete` of a fact that does not exist.
5. Manipulating the same fact (fact name plus key values) more than
   once in a single `finish` block.

All five are *provable* properties. A well-written policy already
contains the evidence that the exception cannot happen, in the form of
checks and queries that run before the `finish` block. This document
describes a static analysis, the **obligation/observation analysis**,
that walks the policy's control flow and collects that evidence
(*observations*). It then verifies that every fact mutation's
precondition (*obligation*) is discharged by an observation on every
path that reaches it. When the analysis reports nothing, the policy is
statically free of these runtime exceptions.

The analysis is opt-in and reports warnings, not errors.

### Why this matters now

The runtime does not enforce most of these invariants:

| Invariant | Enforced by | Behavior when violated |
|-----------|-------------|------------------------|
| `create` of an existing fact | Nothing | Silently overwrites the fact |
| `update` of a missing fact | VM `Update` instruction | Command fails |
| `update` with mismatched stated values | VM `Update` instruction | Command fails |
| `delete` of a missing fact | Nothing | Silently does nothing |
| Same fact manipulated twice in a `finish` | Nothing | Both mutations apply |

`VmPolicyIO::fact_insert` and `fact_delete`
(`aranya-runtime/src/vm_policy/io.rs`) delegate to
`LinearFactPerspective::insert` and `delete`
(`aranya-runtime/src/storage/linear/mod.rs`). The insert is an
unconditional map insert, and the delete removes the key or writes a
tombstone without checking that it existed. Only the VM's test I/O
implementation raises `MachineIOError::FactExists` and `FactNotFound`.
Until the runtime closes that gap (see [Future work](#future-work)),
this analysis is the only defense against silent fact clobbering. Once
the runtime enforces the invariants, the analysis turns runtime
exceptions into compile-time diagnostics.

## Core concepts

### Obligations

An **obligation** is a precondition attached to a statement that must
be provable at every point the statement can execute.

| Statement | Obligation | Postcondition |
|-----------|------------|---------------|
| `create F[k]=>{..}` | `F[k]` does **not** exist | `F[k]` exists |
| `update F[k] to {..}` | `F[k]` exists | `F[k]` exists |
| `update F[k]=>{v: x} to {..}` | `F[k]` exists and its stored `v` is `x` | `F[k]` exists |
| `delete F[k]` | `F[k]` exists | `F[k]` does not exist |

Every mutation is both a *consumer* of knowledge (its obligation) and a
*producer* of knowledge (its postcondition). This is why the analysis
tracks fact **state** rather than a bag of one-shot observations. After
`create F[k]`, the path knows `F[k]` exists, so a second `create F[k]`
on the same path cannot be proven.

### Observations

An **observation** is knowledge about the fact database established by
executing a statement and continuing past it. A `check`'s `else`
expression and an `or`'s right-hand side must be terminal
(`Never`-typed), so continuing past them means the check passed or the
query found a fact.

```policy
check !exists Account[user: this.user] else recall already_enrolled()
```

After this statement, the path knows `Account[user: this.user]` does
not exist.

```policy
let account = query Account[user: this.user] or recall account_not_found()
```

After this statement, the path knows `Account[user: this.user]` exists,
and that `account` holds its stored values.

### Polarity

Observations and obligations have **polarity**: negative (does not
exist, needed by `create`) or positive (exists, needed by `update` and
`delete`). Polarity matters because the bind marker `?` behaves
differently under each. See
[Subsumption and key matching](#subsumption-and-key-matching).

### The fact-state lattice

The analysis tracks an abstract state per fact literal encountered on
a path:

```
        Unknown
       /       \
   Exists    NotExists
```

- All facts start `Unknown` at the top of a `policy` or `recall` block,
  except in an `init` command (see [Init commands](#init-commands)).
- Observations refine `Unknown` to `Exists` or `NotExists`.
- Mutations *require* a state (their obligation) and *set* the state to
  their postcondition.

This is a strongest-postcondition analysis flowing forward along each
control-flow path. There are no joins in the usual dataflow sense. The
policy language has no general loops (`map` is the only iteration
construct, handled specially), and `finish` blocks terminate execution,
so the analysis simply enumerates paths.

### The finish-block touched set

Independent of fact state, a single `finish` block must not manipulate
one fact more than once, even `delete F[k]` followed by `create F[k]`
(use `update` instead). The analysis keeps a set of the fact literals
touched by the current `finish` block, including mutations inside the
finish functions it calls. A second mutation whose key *may equal* an
already-touched key is flagged.

The conservative direction flips here. To discharge an obligation, the
analysis must *prove* two keys equal. To flag a double manipulation, it
must *fail to prove them distinct*. The analysis uses syntactic
equality for "may equal", so it only flags identical keys and accepts
false negatives.

### Init commands

A command with `attributes { init: true }` always runs against an empty
fact database. The runtime guarantees this: a command with no parent
must have init priority, and a command with a parent must not (see
`aranya-runtime/src/vm_policy.rs` and the priority check in
`aranya-runtime/src/storage/linear/mod.rs`).

So in an init command's `policy` and `recall` blocks, every fact starts
known not to exist. That knowledge is dropped for a fact name as soon
as a fact with that name is mutated, and for every fact at a call the
analysis cannot follow. An `update` or `delete` of a fact that cannot
exist yet gets a note that it always fails.

## Observation sources

| Form | Refinement on continuation | Status |
|------|----------------------------|--------|
| `check !exists F[k] else <terminal>` | `NotExists F[k]` | Implemented |
| `check exists F[k] else <terminal>` | `Exists F[k]` | Implemented |
| `let x = query F[k] or <terminal>` | `Exists F[k]`, and `x` holds its values | Implemented |
| `attributes { init: true }` | Every fact `NotExists` | Implemented |
| `if exists F[k] { A } else { B }` | `Exists` in A, `NotExists` in B | Future |
| `match` or `if` on a stored query result | `Exists` in the Some arm, `NotExists` in the None arm | Future |
| `check query F[k] is Some else <terminal>` | `Exists F[k]` | Future |
| `at_most 0 F[k…?]` | `NotExists F[k…?]` | Future |
| `at_least 1 F[k…?]` | Some match exists | Future |

### Opaque observation points

Any expression that touches a fact but that the extractor cannot
interpret is **opaque**. Examples are compound booleans mixing several
queries, negations of disjunctions, `if` conditions, `match`
scrutinees, and counting queries. The analysis learns nothing from an
opaque expression, but it records the fact name and span. When an
obligation for the same fact name cannot be proven, those spans are
listed in the warning, so the author sees which expression the analysis
gave up on.

Queries inside pure functions are not visible to the analysis, not even
as opaque points.

## Subsumption and key matching

Discharging an obligation requires deciding whether an observed fact
literal covers the mutated one.

**Key matching.** Fact names must match, and key field expressions must
match structurally, ignoring spans and types. Literals, identifiers,
enum references, field access, and calls to pure functions with
matching arguments are compared. Any other expression compares unequal,
which is the conservative direction. To handle trivial aliasing, the
analysis substitutes `let`-bound names with simple values before
comparing, so `let uid = this.user` followed by
`check !exists F[user: uid]` covers `create F[user: this.user]`.

**Bind-marker subsumption is polarity-dependent.**

- *Negative observations get stronger with binds.* `NotExists
  F[user: ?]` means no fact of `F` exists at all, so it covers
  `NotExists F[user: e]` for any expression `e`. The typed syntax tree
  omits trailing binds, so a negative observation covers an obligation
  when its keys are a prefix of the obligation's keys.
- *Positive observations get weaker with binds.* `Exists F[user: ?]`
  proves only that *some* fact exists, not `F[user: e]` for a
  particular `e`. So a positive observation must name exactly the same
  keys.

### Proving an update's stated values

When an `update` states current values, as in `update F[k]=>{v: x} to
{..}`, the VM requires the stored values to match. The analysis accepts
a stated value when, after `let` substitution, it has the form
`q.v` for the same field `v`, and `q` was bound by
`let q = query F[k] or <terminal>` with exactly the same key. This is
the common idiom:

```policy
let counter = query Counter[name: this.name]=>{value: ?} or recall reject()
finish {
    update Counter[name: this.name]=>{value: counter.value} to {value: new_value}
}
```

Any other stated value, such as a literal or a field read from a
different fact, gets a warning.

### Invalidation

State is conservatively invalidated when something may have changed the
fact database between an observation and an obligation:

- A mutation of fact `F` sets the state of the matching literal to its
  postcondition. It forgets every other literal of `F`, since their
  keys may alias the mutated one. It also forgets query results for `F`
  and init knowledge for `F`.
- A `map` body forgets knowledge of the facts it mutates before it is
  analyzed, because an observation about one iteration says nothing
  about the next.
- A call the analysis cannot follow forgets everything. See
  [Finish functions](#finish-functions).

Observations established in the `policy` block survive into `finish`
blocks unchanged. No fact mutation can occur between them, because the
compiler restricts mutations to finish contexts.

## Analysis algorithm

The analysis lives in `crates/aranya-policy-compiler/src/obligation.rs`
and runs on the typed syntax tree (`aranya_policy_ast::thir`) during
compilation. The typed tree is the right level: fact literals are
explicit structured values, types are resolved, and branch polarity is
syntactically evident, since `check` and `or` failure arms are
`Never`-typed.

`CompileState::compile_statements` in `compile.rs` calls the analysis
right after a block is lowered:

- For a command `policy` or `recall` block, it runs the analysis,
  passing whether the command is an init command.
- For a finish function body, it records the lowered statements and
  parameter names. Finish functions are compiled before commands, so
  every body is recorded before any command that calls it is analyzed.

For each command `policy` and `recall` block:

1. Walk statements in order, threading the fact state, the `let`
   substitution environment, query bindings, and the opaque points.
2. `let` and `check`: apply the observation if the form is recognized.
   Otherwise record the expression's fact references as opaque.
3. `if` and `match`: walk each arm with a clone of the state, then
   continue each arm into the statements after the branch. Statements
   after a branch are analyzed once per path. Policy blocks are small
   and loop-free, so path explosion is not a practical concern.
4. `map`: forget knowledge of the facts the body mutates, walk the
   body once, and continue after it. Nothing learned inside the body is
   kept after it.
5. `finish`: check each mutation's obligation against the incoming
   state, apply its postcondition, and maintain the touched set. Follow
   calls into finish functions. A `finish` block terminates the path.
6. `return` and `recall` statements terminate the path.

Recall blocks are analyzed like policy blocks, with the same
observation forms.

### Finish functions

Mutations inside finish functions are checked at each call site. At a
call, the analysis binds the function's parameters to the caller's
arguments, after substituting the caller's `let` bindings. It then
checks the function body against the caller's state, sharing the
caller's touched set. So a check in the command discharges an
obligation inside the function, a call from inside a function is
followed the same way, and a fact changed both in the `finish` block and
in a called function is flagged as manipulated twice.

A warning inside a finish function carries a note for each call on the
path that reached it, innermost first. The same function reached from
several commands produces one warning listing every call site.

A call the analysis cannot follow forgets all state: known facts, query
bindings, and init knowledge. That covers two cases:

- A call to a function that is not a known finish function, or whose
  argument count does not match.
- A recursive call, meaning a call to a function already on the call
  stack. This also gets its own warning, since the mutations reached
  through it go unchecked.

The policy language forbids recursion, but the compiler does not
currently reject it ([#607], [#751]). Mutually recursive finish
functions compile today. The call-stack guard keeps the analysis
terminating. Once the compiler rejects recursion, the recursion warning
becomes unreachable.

[#607]: https://github.com/aranya-project/aranya-core/issues/607
[#751]: https://github.com/aranya-project/aranya-core/issues/751

### Deduplication

Because statements after a branch are analyzed once per path, one
mutation can fail on several paths, and a shared finish function can
fail from several commands. Warnings with the same span and message are
merged, keeping the first one's position and the union of their notes.
This happens per block and again across the whole policy.

## Diagnostics

An unmet obligation produces a warning at the mutation's span. The
title names the fact literal as written in the source, a short label
marks the statement, and footnotes explain the exception and suggest a
fix:

```
warning: cannot prove `Counter[name: this.name]` does not exist before `create`
    |
179 |             create Counter[name: this.name]=>{value: this.value}
    |             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this fact may already exist
    |
    = note: creating a fact that already exists is a runtime exception
    = help: check that it does not exist first: `check !exists Counter[name: this.name] else ...`
```

| Warning | Label |
|---------|-------|
| cannot prove `F[k]` does not exist before `create` | this fact may already exist |
| cannot prove `F[k]` exists before `update` or `delete` | this fact may not exist |
| cannot prove the stated values of `F[k]` match the stored fact before `update` | the stored values may differ |
| `F[k]` is manipulated more than once in this finish block | manipulated again here |
| cannot check fact mutations through recursive call to `f` | recursive call |

Opaque points touching the same fact are shown as secondary
annotations labeled "touches `F` but is too complex to analyze". Calls
that led into a finish function are labeled "in this call to `f`".

## Interface

- `Compiler::analyze_obligations(bool)` enables the analysis. It is off
  by default.
- `Compiler::compile_with_diagnostics()` returns the compiled module and
  the warnings. `Compiler::compile()` is unchanged.
- `ObligationWarning` holds the span, message, label, span notes, and
  footnotes of a warning. `ObligationWarning::render(source)` renders it
  with `annotate-snippets`, like compiler errors.
- The `policy-compiler` binary takes `--check-obligations` and prints
  warnings to stderr.

```bash
cargo run -p aranya-policy-compiler --bin policy-compiler -- \
    --check-obligations --stub-ffi --no-validate \
    crates/aranya-core-example/src/policy.md
```

On the core example policy, this reports one real bug: `SetCounter`
creates `Counter[name: this.name]` without checking that it does not
exist. The init command's creates and `IncrementCounter`'s update are
proven.

## Testing

The unit tests at the bottom of `obligation.rs` compile small policies
with the analysis enabled and assert on the warnings. They cover:

- each obligation passing with its observation and warning without it;
- path sensitivity, with a check on only one branch;
- deduplication across paths, with merged notes;
- bind-marker subsumption for negative observations only, and `let`
  aliases;
- update stated values from a query, through a `let` alias, from a
  literal, and from a query of a different fact;
- init commands, including `init: false`;
- finish functions: caller checks, call-site notes, nested calls,
  double manipulation across a call, one warning for a function shared
  by two commands, and recursion;
- rendering of the title, label, note, and help.

## Known limitations

- **Branch refinement.** `if` and `match` conditions are opaque, so a
  policy that tests `exists` in an `if` gets no credit for it.
- **Double manipulation is syntactic.** Only identical keys are flagged,
  so two mutations whose keys are equal at runtime but written
  differently are missed.
- **Distinct keys of one fact in an init command.** After
  `create F[k1]`, the analysis cannot prove `F[k2]` is still absent,
  because it cannot prove `k1` and `k2` differ. A second create of the
  same fact name with a different key warns.
- **Query-derived keys.** `let f = query F[k: ?] or ..` does not prove
  `Exists F[k: f.k]`.
- **Pure functions** are not analyzed, so queries inside them are not
  observations or opaque points.

## Future work

- **Branch refinement:** `if exists`, `match` on query results, and
  `check query F[k] is Some` as observation sources.
- **Counting queries:** `at_most 0`, `at_least 1`, and `exactly N` as
  observation sources with polarity per the table above.
- **Query-derived keys:** `let f = query F[k: ?] or ..` proving
  `Exists F[k: f.k]`.
- **Pure function summaries**, so queries inside helpers count as
  observations at the call site.
- **Bytecode-level analyzer:** port the analysis to the
  path-enumerating tracer (`src/tracer.rs`, `Analyzer` trait in
  `src/tracer/analyzers.rs`) so compiled modules can be checked without
  source. This requires branch-polarity tracking in the tracer and light
  abstract interpretation to reconstruct fact literals from
  `FactNew`, `Query`, and `Create` instruction sequences.
- **Runtime enforcement:** make `LinearFactPerspective::insert` and
  `delete` enforce `FactExists` and `FactNotFound`, and enforce the
  touched-set rule, so the documented semantics hold for unanalyzed
  policies too. The static analysis then guarantees those exceptions
  are unreachable.
- **Default-on, then errors:** make the analysis default-on once it has
  run cleanly on real policies such as the daemon policy, then promote
  warnings to errors.
- **New obligation kinds:** the framework is not fact-specific.
  Candidates include every `policy` block reaching a `finish` on some
  path, envelope-author checks before privileged mutations, or
  invariants declared in policy source.

## Terminology

This document uses policy-book terminology throughout: *key* and
*value* fields of a fact, *bind marker* (`?`), *rejection* and *runtime
exception*, *recall*. The analysis introduces *obligation*,
*observation*, *polarity*, *opaque observation point*, and *touched
set*. Code, diagnostics, and future docs should use these terms
consistently.
