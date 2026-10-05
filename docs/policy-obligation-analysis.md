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
construct, and it is only allowed in actions), and `finish` blocks
terminate execution, so the analysis simply enumerates paths.

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

| Form | What the path learns | Status |
|------|----------------------|--------|
| `check c else <terminal>` | What `c` proves when true | Implemented |
| `let x = e or <terminal>` | What `e is Some` proves; if `e` is a query, `x` holds the fact | Implemented |
| `if c { A } else { B }` | A learns what `c` proves when true, B what it proves when false | Implemented |
| `match` on an optional | The `Some(x)` arm learns `is Some`, the `None` arm `is None`; on a query, `x` holds the fact | Implemented |
| `attributes { init: true }` | Every fact `NotExists` | Implemented |
| `let f = query F[k: ?] or ..` | `Exists F[k: f.k]`, and `f` holds that fact | Implemented |
| `let x = match e { .. }`, `let x = if ..`, `let x = { .. : e }` | What holds when some arm produced a value; `match query F[k] { Some(x) => x  None => <terminal> }` makes `x` hold the fact | Implemented |

### Conditions

Conditions are evaluated to a pair: what they prove when true, and what
they prove when false. Either side can be *impossible*, which is how
contradictory branches are detected.

| Condition | When true | When false |
|-----------|-----------|------------|
| `exists F[k]` | `Exists F[k]` | `NotExists F[k]` |
| `query F[k] is Some` | `Exists F[k]` | `NotExists F[k]` |
| `query F[k] is None` | `NotExists F[k]` | `Exists F[k]` |
| `!c` | `c` when false | `c` when true |
| `a && b` | Both sides' true facts | Only facts both sides prove when false |
| `a \|\| b` | Only facts both sides prove when true | Both sides' false facts |
| `at_least 1 F[k]` | Some match exists | `NotExists F[k]` |
| `at_least n F[k]`, `exactly n F[k]` | Some match exists | Nothing |
| `at_most n F[k]` | Nothing | Some match exists |
| `true`, `false` | Nothing, or impossible | Impossible, or nothing |
| A call to a pure function | From the function's summary | From the function's summary |
| `if c { :a } else { :b }` | What both arms prove when true, each under its side of `c` | Likewise when false |
| `match e { p => a  .. }` | What every arm proves when true, each under its pattern and the earlier patterns failing | Likewise when false |
| `{ stmts : e }` | What `e` proves on every path through `stmts` that reaches it | Likewise when false |

Count limits must be at least 1, so `at_most 0` is not valid policy;
`!(at_least 1 F[k])` is the way to count to zero. "Some match exists"
is recorded as `Exists` on the counted pattern. When the pattern has a
bind marker, that says nothing about a particular key, so it cannot
discharge an `update` or `delete` obligation.

A literal with a value filter, such as `exists F[k]=>{v: 0}`, proves
`Exists F[k]` when it matches, since some fact with that key exists.
When it does not match it proves nothing: a fact with that key may
still exist with another value. A filter made only of bind markers,
`=>{v: ?}`, is no filter. This was found by the adversarial tests
below; before the fix, `check !exists F[k]=>{v: 0}` wrongly discharged
a `create F[k]`, and wrongly pruned a later `if exists F[k]` branch as
impossible.

A `let` whose value is substitutable is replaced by its value wherever
the name appears. Substitutable values include fact reads (`exists`,
`query`, and counts) and pure function calls, not just simple values.
The fact database cannot change during a policy block, so the same
expression gives the same value wherever it appears. So this proves
`Device[device_id: id]` exists after the `if`:

```policy
let device = query Device[device_id: id]
if device is None { recall missing_device() }
```

### Keys read from query results

A query with a bind marker only proves that *some* matching fact
exists, which cannot discharge an `update` or `delete` obligation on
its own. But when the result is bound to a name, that name holds
exactly one fact, and its key is the query's keys followed by the
name's remaining key fields:

```policy
let member = query Member[team: t, device: ?] or recall not_member()
finish { delete Member[team: t, device: member.device] }
```

After the `let`, the path knows `Exists Member[team: t]` and
`Exists Member[team: t, device: member.device]`, and `member` is
recorded as holding the latter, so `update ..=>{rank: member.rank}` is
proven too. The typed syntax tree drops trailing bind markers, so the
query's keys are always a prefix of the schema's key fields; the
analysis fills in the rest from the fact definition. The same applies
to a `match` arm that is exactly `Some(member)` on a query. An arm that
lists `Some(member)` alongside `None` proves nothing, since the arm
can run when there is no fact.

A call to a pure function counts as a query when every exit that can
return `Some` returns a query of the same fact with the same keys, in
the caller's terms. Exits returning the literal `None` are ignored.
So `let m = find_member(t) or recall ..` and
`match find_member(t) { Some(m) => .. }` work for:

```policy
function find_member(t int) option[struct Member] {
    return query Member[team: t, device: ?]
}
```

A helper whose exits query different keys, or that returns `Some` of a
local variable, does not qualify.

### `if`, `match`, and block expressions

An `if` expression's arms are always block expressions, `{ stmts : e }`,
and a `match` expression's arms are bare expressions. Each arm is
evaluated on a copy of the path that knows the arm's condition: the
`if` condition or its negation, or the arm's pattern matching after the
earlier patterns failed. What the arm's value proves is combined with
what that copy knows, and the arms are joined with the same rule as
`||`: only what every arm proves is kept. An arm whose expression has
type `Never`, such as `recall r()` or `{ :return v }`, never produces a
value, so it drops out of the join. This is why `if c { :exists F[k] }
else { :false }` proves `F[k]` exists: the `else` arm can't be true.

An arm without a value still runs. A `return` in it is an exit of the
enclosing function, and a block in it is walked, so a `finish` there is
checked. The same holds for the `else` of a `check` and the right side
of an `or`: when they are blocks, `if`s, or `match`es, they are walked
on the path where they run.

A block's statements are walked exactly like a policy block, forking at
nested `if` and `match` statements and ending at a failing `check` or a
`finish`. Every path that reaches the final expression contributes what
it knows, with block-local `let`s substituted. Facts that mention a name
bound inside the block or by the arm's pattern are dropped, both from
what the path knows and from what the arm's value proves. Outside the
arm those names are unbound, or, in a helper's caller, they name
something else. Knowledge established by a `check` or
`or recall` inside an arm carries out, which is what makes
`let d = match e { Ok(d) => d  Err(e) => recall reject() }` an
observation: the path past the `let` knows what the `Ok` path knew. When
every value-producing arm is `Some(x) => x` on a query, the `let` name
holds the fact the query read, as with `let x = query .. or ..`.

The value of an `if`, `match`, or block is not substituted for the name
it is bound to, so `let ok = if ..` followed by `check ok` proves
nothing. Write the condition in the `check`, or bind the query
result instead.

### Opaque observation points

Any expression that touches a fact but that the extractor cannot
interpret is **opaque**. Examples are comparisons, `count_up_to`, calls
that can't be followed, and blocks with more paths than the exit
limit. The
analysis learns nothing from an opaque expression, but it records the
fact name and span. When an obligation for the same fact name cannot be
proven, those spans are listed in the warning, so the author sees which
expression the analysis gave up on.

A condition that touches a fact but proves nothing about it is recorded
the same way. For example, `!exists F[k] || ok` proves nothing about
`F`, because `ok` alone may be what made it true.

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
`let q = query F[k] or <terminal>` or a `Some(q)` arm with exactly the
same key, counting keys read from `q` itself (see
[Keys read from query results](#keys-read-from-query-results)). This is
the common idiom:

```policy
let counter = query Counter[name: this.name]=>{value: ?} or recall reject()
finish {
    update Counter[name: this.name]=>{value: counter.value} to {value: new_value}
}
```

Any other stated value, such as a literal or a field read from a
different fact, gets a warning.

An update that states some values and binds the rest with `?` always
fails, because the VM compares the stated values with the whole stored
value list. It gets its own warning. Binding every value with `?`
skips the comparison.

### Invalidation

State is conservatively invalidated when something may have changed the
fact database between an observation and an obligation:

- A mutation of fact `F` sets the state of the matching literal to its
  postcondition. It forgets every other literal of `F`, since their
  keys may alias the mutated one. It also forgets query results for `F`
  and init knowledge for `F`.
- A `map` statement forgets everything. `map` is only allowed in
  actions, which the analysis does not walk, so this is never reached
  today; if the language ever allows it in a policy block, its body
  may mutate any fact any number of times.
- A call the analysis cannot follow forgets everything. See
  [Finish functions](#finish-functions).
- Binding a name again, with a `let` or a `match` arm, forgets every
  fact, substitution, and query binding that mentioned the earlier
  binding. A name can be reused once the block that bound it ends, but
  the walk carries a branch's state into the statements after it, where
  a fact written in terms of the old name would silently mean the new
  one.

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
2. `let` and `check`: add what the condition proves to the path.
3. `if` and `match`: walk each arm with a clone of the state, adding
   what its condition proves when true and what every earlier
   condition proves when false. The `else` branch, or the code after an
   `if` without one, learns that every condition was false. Then
   continue each arm into the statements after the branch. Statements
   after a branch are analyzed once per path. Policy blocks are small
   and loop-free, so path explosion is not a practical concern.
4. **Impossible paths** are skipped. When what a path learns
   contradicts what it already knows, such as `if exists F[k]` after
   `check !exists F[k]`, the path cannot run, so nothing on it is
   reported.
5. `map`: forget everything. Only actions may contain `map`, so this
   is unreachable for the blocks the analysis walks.
6. `finish`: check each mutation's obligation against the incoming
   state, apply its postcondition, and maintain the touched set. Follow
   calls into finish functions. A `finish` block terminates the path.
7. `return` and `recall` statements terminate the path.

Recall blocks are analyzed like policy blocks, with the same
observation forms.

A block expression reuses the same walk. Its statements are walked with
a flag set that keeps the state of every path that runs off their end,
the way a pure function keeps the state at every `return`. Those end
states are the block's arms. Function exits found inside the block
still go to the function's summary, so the two never mix. The
`max_exit_paths` limit bounds the number of ends; a block with more is
opaque.

### Pure functions

A call to a pure function in a condition or a `let` is evaluated through
the function's **summary**. The summary lists the function's *exits*:
each way it can return, with the value it returns and what is known on
the path to it. A `check c else return v` and an `e or return v` inside
the function are exits too, where `c` was false or `e` was `None`.

At a call, the function's parameters are replaced by the caller's
arguments. When the call is used as a condition, its true side keeps
only what holds on every exit whose return value could be true, and
likewise for the false side. An exit that returns the literal `false`
can't make the call true, so it doesn't weaken the true side. For
example, `check device_has_perm(id, perm)` proves
`AssignedRole[device_id: id]` exists here:

```policy
function device_has_perm(device_id id, perm enum Perm) bool {
    let role = query AssignedRole[device_id: device_id] or return false
    return role_has_perm(role.role_id, perm)
}
```

A fact or return value that mentions one of the function's local
variables can't be expressed in the caller's terms, so it is dropped.
Keeping it would be unsound: a caller variable with the same name holds
something else. A return value that is an `if`, `match`, or block is
kept, with the names its blocks and arms bind allowed inside it.
Substituting the caller's arguments into such a value is refused when
an argument mentions a name one of those blocks or arms binds, since
the argument would then refer to that binding instead.

A `return` inside an expression is an exit too. The walk records the
ones in `e or return v`, `check c else return v`, and arms without a
value, including a `return` inside a block arm such as
`if c { :return v } else { .. }`. Any other `return`, such as one inside
a returned value, a fact key, a call argument, or a `match` scrutinee,
would be an exit the summary misses. So every summary passes a census:
each `return` in the function body must be one the walk recorded, or a
statement-level one on no path that can run, such as inside a branch a
contradiction rules out. If any is left over, the function is treated
as unknown.

Summaries are computed on first use and cached. A function is not
summarized, and calls to it are treated as unknown, when:

- it has more exits than the configured limit
  (`Compiler::max_exit_paths`, 64 by default), or a block in it has
  more ways through it than that, which leaves the block's final
  expression unevaluated;
- it is recursive, directly or through other functions;
- a `return` in it fails the census.

A call that is treated as unknown is recorded as an opaque point for
every fact its function's body mentions, so warnings about those facts
point at the call.

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
currently reject it ([#607], [#751]). Recursive pure functions and
mutually recursive finish functions compile today. The call-stack guard keeps the analysis
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
| the stated values of `F[k]` can never match the stored fact | this update always fails |
| `F[k]` is manipulated more than once in this finish block | manipulated again here |
| cannot check fact mutations through recursive call to `f` | recursive call |

Opaque points touching the same fact are shown as secondary
annotations labeled "touches `F` but is too complex to analyze". Calls
that led into a finish function are labeled "in this call to `f`".

## Interface

- `Compiler::analyze_obligations(bool)` enables the analysis. It is off
  by default.
- `Compiler::max_exit_paths(usize)` sets the most exits recorded for one
  pure function. The default is `DEFAULT_MAX_EXIT_PATHS`, 64.
- `Compiler::compile_with_diagnostics()` returns the compiled module and
  the warnings. `Compiler::compile()` is unchanged.
- `ObligationWarning` holds the span, message, label, span notes, and
  footnotes of a warning. `ObligationWarning::render(source)` renders it
  with `annotate-snippets`, like compiler errors.
- The `policy-compiler` binary takes `--check-obligations` and
  `--max-exit-paths <N>`, and prints warnings to stderr.

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

The unit tests in `crates/aranya-policy-compiler/src/obligation/tests/`
compile small policies with the analysis enabled and assert on the
warnings. The shared helpers live in `obligation/tests.rs`, and each
file covers one feature, in the order below:

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
- conditions: `&&`, `!(.. || ..)`, `||` proving nothing, and counting
  queries;
- branches: `if exists` on both sides, early `recall`, `else if`,
  `is None` after a query, `match` on a query, and impossible branches;
- pure functions: one-line helpers, helpers that return `false` when a
  fact is missing, helpers returning a query, helpers combining checks,
  the exit limit, recursion, and a helper's local variable not being
  mistaken for the caller's;
- keys read from query results: `delete` and `update` with the full
  key after `let .. or`, after a `Some(m)` arm, with a value filter,
  through a `let` alias, through a finish function, through a helper
  returning the query (with `let` and with `match`), and in an init
  command; warnings for an arm mixing `Some(m)` and `None`, for a
  mutation of the same fact earlier in the finish block, for a helper
  whose exits query different keys, and for a helper returning `Some`
  of a local;
- rebinding: a `let` or `Some(m)` arm reusing a name forgets facts
  about the earlier binding, including a mention nested in another
  fact's key;
- expressions: `if` and `match` in a `check`, blocks with `let`,
  `check`, `if`, and `match` statements, a `match` `let` binding the
  query result and learning from its producing arms, an `if` returning
  a query before `or recall`, a helper returning an `if`, an arm
  returning from a helper, a nested `return` making a helper unknown, a
  `finish` inside a block being checked, blocks over the exit limit,
  an `else` arm that proves nothing, and arm-bound and block-local
  names not leaking;
- rendering of the title, label, note, and help.

### Adversarial tests

The `attacks_*` files hold policies written to get a wrong "proven"
out of the analysis. Each attack is a policy whose mutation can fail
at runtime, asserting that the analysis warns, paired with a control
twin that removes the trick and asserts no warnings, so the warning is
attributable to the attack rather than to the analysis going opaque
for an unrelated reason. They are grouped by the assumption they
target:

- `attacks_polarity.rs`: value filters on every negative form, bind
  prefixes never discharging an exact key, and a negative observation
  of one key saying nothing about another;
- `attacks_names.rs`: `Ok`/`Err` arm rebinding, finish-function and
  helper parameters named like caller variables, block-local query
  bindings, alias chains, arm-expression bindings, a helper's arm name
  leaking into its caller, and an argument captured by a binder inside
  a helper;
- `attacks_state.rs`: keys that may alias in one finish block, directly
  and through a finish function, a finish function dropping the
  caller's query binding, a recursive call in an init command, recall
  blocks not inheriting policy knowledge, and double manipulation across
  a call;
- `attacks_helpers.rs`: early exits returning `true`, exits recorded
  from inside a block in an arm, mutual recursion, non-substitutable
  locals in exit facts, arguments rebound after a call, summaries
  reused across commands, `return`s inside a returned value, a `match`
  scrutinee, a block argument, an `if` arm, and a block over the exit
  limit, and a base command's `get_key`;
- `attacks_paths.rs`: prefix and exact patterns of opposite polarity
  that are not contradictions, counting queries, init pruning against
  its non-init twin, and `!(a && b)` proving nothing;
- `attacks_expressions.rs`: condition facts not surviving arms, an arm
  weakened by `||` or a `_ => true` default, `if` arms querying
  different keys, a `match` binding of another query, a block binding
  the outer `let`'s own name, block-scoped names in a condition block,
  a nested `return` in an `if` arm, and a `finish` inside an arm
  without a value, a `check`'s `else`, or an `or`'s right side.

Branch coverage of `obligation.rs` is complete: `cargo llvm-cov
--branch` reports every branch side taken. The tests that closed the
gap live in the feature file of the rule they reach, not in a file of
their own: the `||` join and its deduplication in `conditions.rs`,
impossible paths and note merging in `paths.rs` and `branches.rs`,
mutual recursion and `test_fail` terminals in `pure_functions.rs`,
strict substitution failing inside each expression form in
`strict_substitution.rs`, literal
`Some` and `Ok` arms in `branches.rs`, the binding rules and the
rebinding visitor in `bound_keys.rs`, the key-matching forms in
`mutations.rs`, and the visitor corners in `expressions.rs`. Branches
that no valid policy could take, such as a `return` outside a function
or a call to an undefined finish function, were removed from the code
rather than left untested.

`assumptions.rs` guards what the analysis assumes the compiler
enforces: no shadowing, keys as schema-order prefixes, no calls or
queries in finish expressions, `map` only in actions, and the
accepted and rejected `match` arm forms. A language change that breaks
one fails there rather than silently unsounding the analysis.

Each attack that defends a single rule was checked by disabling that
rule and confirming the attack fails: the value-filter rule, `Ok`/`Err`
forgetting, finish-function parameter substitution, block-scoped
substitution, `or return` exits, the arm-local fact filter, a
mutation forgetting other keys of its fact, the return census, the
statement-level and arm exits it counts on paths that can't run,
walking arms without a value and terminal blocks, the block-limit
rule, the arm-name filter on what an arm proves, capture refusal, the
`get_key` guard, and the partial-update check. Attacks on `map` could not
be written because `map` is only allowed in actions, which cannot
mutate facts.

The campaign found three false negatives, all fixed:

- the value-filter bug described under [Conditions](#conditions);
- a `match` arm `Some(1)` that fails to match was treated as proving
  the value is `None`, so a later `Some(x)` or `None` arm was pruned
  as impossible and its mutations went unchecked. A literal `Some`
  pattern now proves nothing when it fails, since the value may be
  another `Some`. Only a binding pattern `Some(x)` proves `None`;
- a `return` nested inside a fact key or call argument in a helper's
  condition was never recorded as an exit, so the helper's true side
  kept facts the missed exit did not guarantee. The census described
  under [Pure functions](#pure-functions) now catches every such
  `return`.

A code review found seven more, all fixed, each pinned by an attack and
a control:

- a `return` inside a returned value, inside a `match` scrutinee, or as
  a statement in a block expression in an argument was never recorded
  as an exit. When every exit of a helper was lost this way, a `check`
  on the call marked the rest of the command impossible and hid its
  warnings;
- a fact proven by a helper's `match` arm kept the arm's binding name,
  so it leaked into the caller, where that name meant a different
  variable;
- substituting a caller's argument into a helper could place it inside
  a block or arm that binds a name the argument mentions, capturing it;
- a base command's `get_key` block was recorded as a pure function
  named `get_key`, replacing a user function with that name;
- an update that stated some values and bound the rest always fails at
  runtime, but was accepted.

Fixing those turned up two more of the same kind, also fixed. A
`return` in a block arm of an `if` expression was never recorded as an
exit. A `finish` inside an arm without a value, a `check`'s `else`, or
an `or`'s right side was never checked.

Every test asserts something the rule it names can change. A test
whose result would be the same with the rule broken, such as "no
warnings" after a mutation the path proves anyway, is not kept: an
audit of the suite removed several and rewrote others so the rule is
the only thing standing between the prover and a wrong answer.

## Known limitations

- **`count_up_to`** is opaque.
- **Branching `let` values are not substituted.** `let ok = if ..`
  followed by `check ok` proves nothing, though `ok` still matches
  itself by name in fact keys.
- **Blocks over the exit limit** are opaque, like functions with too
  many exits. In a function, one makes the function unknown.
- **A `return` the walk can't record**, such as one inside a returned
  value or a `match` scrutinee, makes its function unknown.
- **Double manipulation is syntactic.** Only identical keys are flagged,
  so two mutations whose keys are equal at runtime but written
  differently are missed.
- **Distinct keys of one fact in an init command.** After
  `create F[k1]`, the analysis cannot prove `F[k2]` is still absent,
  because it cannot prove `k1` and `k2` differ. A second create of the
  same fact name with a different key warns.
- **FFI calls** are not substituted, so a key computed by an FFI call is
  compared by the name of the variable holding it.
- **Helper knowledge** is limited to facts expressed in the helper's
  parameters and globals.

## Future work

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
