---
layout: page
title: Policy Obligation Analysis
permalink: "/policy-obligation-analysis/"
---

# Policy Obligation Analysis

## Overview

The policy language distinguishes two kinds of terminating errors (see
[Errors](/policy-book/reference/errors.md)):

- **Rejections** — anticipated failures, produced deliberately by a
  `check` whose expression is false or by coalescing a `None` with
  `or`. These are part of normal operation.
- **Runtime exceptions** — violations of execution invariants that the
  policy author did not anticipate. They cannot be detected or
  recovered from in policy code, do not execute `recall` blocks, and
  surface as errors to the application.

Several runtime exceptions concern the fact database:

- `create` of a fact whose key already exists.
- `update` or `delete` of a fact that does not exist.
- Manipulating the same fact (fact name plus key values) more than
  once in a single `finish` block.

These are all *provable* properties: a well-written policy already
contains the evidence that the exception cannot happen, in the form of
checks and queries executed before the `finish` block. This document
describes a static analysis — the **obligation/observation analysis**
— that walks the policy's control flow, collects that evidence
(*observations*), and verifies that every fact mutation's precondition
(*obligation*) is discharged by an observation on every path that
reaches it. When the analysis succeeds, the policy is statically free
of these runtime exceptions.

The analysis is designed as a general framework. The first version
targets a single obligation — duplicate `create` — with a small,
easily analyzable set of observation forms, and reports warnings
rather than errors. Later versions extend the same machinery to
`update`/`delete` obligations and richer observation forms.

### Why this matters now

The policy book documents duplicate `create` as a runtime exception,
but the production runtime does not currently enforce it:
`VmPolicyIO::fact_insert` (`aranya-runtime/src/vm_policy/io.rs`)
delegates to `LinearFactPerspective::insert`
(`aranya-runtime/src/storage/linear/mod.rs`), which is an
unconditional map insert — a second `create` silently **overwrites**
the first fact. Only the VM's test I/O implementation raises
`MachineIOError::FactExists`. Until the runtime closes that gap
(tracked as related work, below), this static analysis is the only
line of defense against silent fact clobbering. Once the runtime does
enforce it, the analysis upgrades the failure from a runtime exception
to a compile-time diagnostic.

## Core concepts

### Obligations

An **obligation** is a precondition attached to a statement that must
be provable at every point the statement can execute. Fact mutations
carry the following obligations:

| Statement            | Obligation                  | Postcondition          |
|----------------------|-----------------------------|------------------------|
| `create F[k]=>{...}` | `F[k]` does **not** exist   | `F[k]` exists          |
| `update F[k] to {..}`| `F[k]` exists               | `F[k]` exists          |
| `delete F[k]`        | `F[k]` exists               | `F[k]` does not exist  |

Note that every mutation is both a *consumer* of knowledge (its
obligation) and a *producer* of knowledge (its postcondition). This is
why the analysis tracks fact **state** rather than a bag of
one-shot observations: after `create F[k]`, the flow knows `F[k]`
exists, so a second `create F[k]` on the same path fails its
obligation with no extra machinery.

A **deferred obligation** is one that need not hold at the statement
itself but must hold by the end of every execution path through the
policy. The framework supports these via a per-path queue checked when
a path terminates. (No v1 obligation is deferred; the mechanism exists
for future obligations such as "every command policy must be able to
justify its recall reachability".)

### Observations

An **observation** is knowledge about fact-database state established
by executing an expression and taking a particular branch of control
flow. Observations are inherently *branch-outcome shaped*: a single
expression establishes different knowledge on its success and failure
arms.

```policy
check !exists Account[user: this.user] else recall already_enrolled()
```

On the fall-through arm (the `else` expression is terminal, so
fall-through is the only continuation), this establishes
`NotExists Account[user: this.user]`.

```policy
let account = query Account[user: this.user] or recall account_not_found()
```

On the fall-through arm this establishes
`Exists Account[user: this.user]` (and binds the fact's fields).

### Polarity

Observations and obligations have **polarity**: negative
(`NotExists`, needed by `create`) or positive (`Exists`, needed by
`update`/`delete`). Polarity matters because the bind marker `?`
behaves differently under each — see
[Subsumption](#subsumption-and-key-matching).

### The fact-state lattice

The analysis tracks, per fact literal encountered on a path, an
abstract state:

```
        Unknown
       /       \
   Exists    NotExists
```

- All facts start `Unknown` at the top of a `policy` or `recall`
  block.
- Observations refine `Unknown` to `Exists` or `NotExists` on the arm
  where they hold.
- Mutations *require* a state (their obligation) and *set* the state
  to their postcondition.

This is a strongest-postcondition analysis flowing forward along each
control-flow path. There are no joins in the usual dataflow sense: the
policy language has no general loops (`map` is the only iteration
construct, handled specially), and `finish` blocks terminate
execution, so the analysis simply enumerates paths.

### The finish-block touched set

Independent of fact state, the policy book forbids manipulating one
fact (name + key values) more than once in a single `finish` block —
even `delete F[k]` followed by `create F[k]` (use `update` instead).
The analysis enforces this with a per-finish-block set of touched fact
literals: a second mutation whose key *may equal* an already-touched
key is an error. Note the conservative direction flips here: for
obligations we must *prove* keys equal to discharge; for the touched
set we must *fail to prove them distinct* to flag. v1 uses syntactic
equality for "may equal" and only flags identical keys, accepting
false negatives (this rule is enforced at runtime regardless).

## Observation sources

The extractor maps an expression to a pair of fact-state refinements:
*(state on success arm, state on failure arm)*. The full menu the
framework anticipates:

| Form | Success arm | Failure arm |
|------|-------------|-------------|
| `check !exists F[k] else <terminal>` | `NotExists F[k]` | — (terminal) |
| `check exists F[k] else <terminal>` | `Exists F[k]` | — (terminal) |
| `let x = query F[k] or <terminal>` | `Exists F[k]` | — (terminal) |
| `check query F[k] is Some else <terminal>` | `Exists F[k]` | — (terminal) |
| `unwrap query F[k]` | `Exists F[k]` | — (runtime exception) |
| `if exists F[k] { A } else { B }` | `Exists F[k]` in A | `NotExists F[k]` in B |
| `match` / `if` on a stored query result | `Exists` in Some-arm | `NotExists` in None-arm |
| `at_most 0 F[k…?]` | `NotExists F[k…?]` | `Exists` (some match) |
| `at_least 1 F[k…?]` (= `exists`) | `Exists` (some match) | `NotExists F[k…?]` |

Because `exists` is sugar for `at_least 1`, counting queries fold into
the same polarity rules.

### Opaque observation points

Any expression touching a fact that the extractor cannot interpret —
compound booleans mixing several queries, negations of disjunctions,
query results laundered through helper functions, counting queries
with bounds other than 0/1 — returns **opaque**. The analysis does not
learn state from it, but it records *(fact name, span)* as a
**candidate observation point**. These records drive diagnostics (see
below) and provide a measure of which patterns are worth whitelisting
next: whichever opaque forms show up most often adjacent to unmet
obligations in real policies.

## Subsumption and key matching

Discharging an obligation requires deciding: does the observed fact
literal cover the mutated fact literal?

**Key matching.** v1 uses syntactic structural equality of fact
literals: same fact name, and pairwise-matching key field expressions.
The AST already provides span-insensitive structural comparison
(`matches_fact_literal` / `matches_fact_field` in
`aranya-policy-ast/src/ast.rs`), which is exactly this test. To reduce
false positives from trivial aliasing (`let uid = this.user; check
!exists F[user: uid]; … create F[user: this.user]`), the analysis
performs one-step substitution of `let`-bound names before comparing.

**Bind-marker subsumption is polarity-dependent.**

- *Negative observations get stronger with binds.* `NotExists
  F[user: ?]` means no fact of `F` exists at all, which subsumes
  `NotExists F[user: e]` for any expression `e`. So an observation
  with a bind in a key position discharges a `create` obligation with
  any expression in that position (binds are illegal in `create`
  itself).
- *Positive observations get weaker with binds.* `Exists F[user: ?]`
  proves only that *some* fact exists; it does not discharge `Exists
  F[user: e]` for a concrete `e`. The exception — keys derived from
  the query result itself (`let f = unwrap query F[user: ?]` proves
  `Exists F[user: f.user]`) — is future work.

Formally: an observation discharges an obligation when polarities
match, fact names match, and for each key position, either the
expressions match structurally, or (negative polarity only) the
observation has a bind where the obligation has any expression.

### Invalidation

State must be conservatively invalidated when something may have
changed the fact database between observation and obligation:

- A mutation of fact `F` sets the state of the *matching* literal to
  its postcondition and resets any *other* literal of `F` whose key
  may alias it to `Unknown`. (v1: literals of the same fact name that
  are not syntactically identical are reset.)
- A call to a `finish function` resets all facts it may mutate. v1,
  which does not analyze across function boundaries, resets
  *everything* at such calls; a later version uses per-function
  summaries.

Observations established in the `policy` block survive into `finish`
blocks unchanged — no fact mutation can occur between them, because
mutations are compiler-restricted to finish contexts.

## Analysis algorithm

The analysis runs in `aranya-policy-compiler` on the typed HIR
(`aranya_policy_ast::thir`), immediately after lowering. THIR is the
right level: fact literals are explicit structured values (rather than
VM stack constructions), types are resolved, and branch polarity is
syntactically evident (`check`/`or` failure arms are `Never`-typed
terminals).

For each command `policy` block and each `recall` block:

1. Walk statements in order, threading the fact-state map, the opaque
   observation list, and the deferred-obligation queue.
2. `let` / `check` / expression statements: run the extractor. Since
   `check … else <terminal>` and `or <terminal>` have terminal failure
   arms, apply the success-arm refinement and continue.
3. `if` / `match`: recurse into each arm with a *clone* of the state,
   applying arm-specific refinements where the scrutinee is an
   analyzable query form. Statements after the branch are analyzed
   once per path (simple path enumeration; policy blocks are small and
   loop-free, so path explosion is not a practical concern — the
   existing bytecode tracer already enumerates paths the same way).
4. `map`: the body is analyzed with a fresh `Unknown` state for facts
   the body mutates, and obligations arising inside the body must be
   discharged inside the same iteration (an observation about iteration
   *i* says nothing about iteration *i+1*).
5. `finish` blocks: mutations check obligations against the incoming
   state, update state, and maintain the touched set. A finish block
   terminates the path; drain the deferred-obligation queue.
6. Recall blocks are analyzed like policy blocks. `check` is not
   permitted in recall blocks, so observations there come from
   `or <terminal>`, `match`, and `if`.

Function boundaries: v1 is intraprocedural. Pure helper functions are
not analyzed (queries inside them are opaque from the caller's view,
recorded as opaque points at the call site if the function is known to
touch facts). `finish function`s conservatively invalidate all state,
and obligations *inside* them are checked only against observations
provable within the function itself (typically none) — expected to
warn in v1; summaries fix this later.

## Diagnostics

An unmet obligation produces a diagnostic at the mutation's source
span, via the compiler's existing span machinery (`CompileError` /
`CodeMap`), naming the obligation and the path condition:

```
warning: cannot prove `Account[user: this.user]` does not exist before `create`
  --> policy.md:42:9
   |
42 |         create Account[user: this.user]=>{balance: 0}
   |
   = note: `create` of an existing fact is a runtime exception
```

When opaque observation points touching the same fact were skipped on
that path, they are listed — satisfying the requirement that skipped,
possibly-relevant observations are surfaced rather than silently
ignored:

```
   = note: the following expressions touch `Account` but were too
           complex to analyze:
           policy.md:38:15: `check !(exists Account[user: this.user] && limit_ok)`
   = help: restructure as `check !exists Account[user: this.user]`
           followed by `check limit_ok`
```

This keeps false positives cheap to triage: the author either
restructures to a whitelisted form or knows exactly which expression
the analyzer gave up on.

## v1 scope

Deliberately minimal:

- **Obligation checked:** `create` requires `NotExists` on the same
  key. (`update`/`delete` obligations, and the touched-set rule, are
  designed above but may land in v1.1.)
- **Observation whitelist:**
  - `check !exists <FactLiteral> else <terminal>`
  - `let x = query <FactLiteral> or <terminal>` (establishes `Exists`
    — used for invalidation precision, and ready for the positive
    obligations)
  - Everything else is opaque-with-record.
- **Key matching:** syntactic equality plus one-step `let`
  substitution; negative-polarity bind subsumption.
- **Interprocedural:** none. Finish-function calls invalidate all
  state.
- **Invocation:** opt-in flag on the `policy-compiler` binary
  (alongside the existing `--no-validate` wiring in
  `src/bin/policy-compiler/main.rs`), e.g. `--check-obligations`.
- **Severity:** warnings only. Existing policies keep compiling. The
  flag graduates to default-on, then to error, as the whitelist covers
  real-world policies.

## Future work

- **Positive obligations:** enable `update`/`delete` `Exists`
  obligations and the finish-block touched-set rule.
- **Richer counting:** `at_most 0` / `at_least 1` / `exactly N` as
  observation sources with polarity per the table above.
- **Query-result-derived keys:** `let f = unwrap query F[k: ?]`
  proving `Exists F[k: f.k]`.
- **Interprocedural summaries:** per-function observation/mutation
  summaries for pure helpers and `finish function`s, replacing
  wholesale invalidation.
- **Bytecode-level analyzer:** port the analysis to the existing
  path-enumerating tracer (`src/tracer.rs`, `Analyzer` trait in
  `src/tracer/analyzers.rs`) so *compiled modules* can be validated
  without source. Requires branch-polarity tracking in the tracer and
  light abstract stack interpretation to reconstruct fact literals
  from `FactNew`/`Query`/`Create` instruction sequences.
- **Runtime enforcement:** make `LinearFactPerspective::insert` (and
  `update`/`delete` paths) enforce `FactExists`/`FactNotFound` so the
  documented runtime-exception semantics hold even for unanalyzed
  policies. The static analysis then guarantees those exceptions are
  unreachable.
- **New obligation kinds:** the framework is not fact-specific.
  Candidates: every `policy` block must reach a `finish` on some path
  (today's `FinishAnalyzer`, reframed), envelope-author checks before
  privileged mutations, or domain-specific invariants declared in the
  policy source.

## Implementation plan

All new code in `crates/aranya-policy-compiler` unless noted.

**Phase 1 — data model and extractor.**
New module `src/obligation.rs` (or `src/obligation/`):
`FactState` (`Unknown`/`Exists`/`NotExists`), a state map keyed by
canonicalized fact literal (fact name + key fields, after `let`
substitution), `OpaquePoint { fact_name, span }`, and the observation
extractor over THIR expressions returning
`(success_refinement, failure_refinement) | Opaque`. Reuse
`matches_fact_literal`/`matches_fact_field` from `aranya-policy-ast`
for subsumption, extended with the polarity-aware bind rule.

**Phase 2 — path walker.**
THIR statement walker per command `policy`/`recall` block, invoked
from the compile pipeline after lowering: path recursion over
`if`/`match`, refinement on `check`/`or` fall-through, `map` body
rules, finish-block obligation checks plus touched set, finish-function
invalidation.

**Phase 3 — diagnostics and wiring.**
Warning type carrying mutation span, obligation description, and the
opaque-point list; rendered through the existing span/`CodeMap`
machinery. Add the opt-in `--check-obligations` flag to
`src/bin/policy-compiler/main.rs` next to `no_validate`, and a library
entry point so `aranya-policy-ifgen`/tests can call it.

**Phase 4 — tests.**
Policy fixtures following the existing `*.fail.policy` /
passing-fixture convention in the compiler's test suite:
- pass: the policy book's `Enroll` (check-then-create) and
  `AddBalance` (query-or-recall-then-update) idioms;
- warn: create with no prior check; create on only one branch of an
  `if` where the other branch lacks the observation; two creates of
  the same literal in one finish; opaque-point reporting for a
  compound `check`;
- subsumption: bind-marker observation discharging concrete create;
  `let`-aliased keys.

## Terminology

This document uses policy-book terminology throughout: *key* vs
*value* fields of a fact, *bind marker* (`?`), *rejection* vs *runtime
exception*, *recall*. The analysis names introduced here —
*obligation*, *observation*, *polarity*, *opaque observation point*,
*deferred obligation* — should be used consistently in code,
diagnostics, and future docs.
