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
control-flow path. The policy language has no general loops (`map` is
the only iteration construct, and it is only allowed in actions), and
`finish` blocks terminate execution, so the analysis can follow each
path separately. Paths that reach the same state are merged, which
loses nothing. Only past a limit on the number of paths are different
states joined, as in a usual dataflow analysis. See
[Merging and joining paths](#merging-and-joining-paths).

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
known not to exist. After a `create` or `update`, that holds only for
facts that provably differ from the one mutated, as described under
[Invalidation](#invalidation), and a call the analysis cannot follow
drops it entirely. So an init command can create `F[k: 1]` and then
`F[k: 2]`, but creating `F[k: x]` after `F[k: 1]` warns. An `update`
or `delete` of a fact that cannot exist yet gets a note that it always
fails.

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
| A call to a pure function wherever it always runs | What every exit of the function knows | Implemented |
| A fact literal with the whole key and a value filter, matching | The fact exists with those stored values | Implemented |
| `a == b`, where one side is a stored value | The other side is that stored value too | Implemented |

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
| `a && b` | Both sides' true facts | Only what holds both where `a` was false and where `a` was true and `b` false |
| `a \|\| b` | Only what holds both where `a` was true and where `a` was false and `b` true | Both sides' false facts |
| `a == b` | What a stored value on one side says about the other | Nothing |
| `a != b` | Nothing | What a stored value on one side says about the other |
| `at_least 1 F[k]` | Some match exists | `NotExists F[k]` |
| `at_least n F[k]`, `exactly n F[k]` | Some match exists | Nothing |
| `at_most n F[k]` | Nothing | Some match exists |
| `true`, `false` | Nothing, or impossible | Impossible, or nothing |
| A call to a pure function | From the function's summary | From the function's summary |
| `if c { :a } else { :b }` | What both arms prove when true, each under its side of `c` | Likewise when false |
| `match e { p => a  .. }` | What every arm proves when true, each under its pattern and the earlier patterns failing | Likewise when false |
| `{ stmts : e }` | What `e` proves on every path through `stmts` that reaches it | Likewise when false |

Every condition also learns, on both sides, what the calls it always
makes guarantee. See [Pure functions](#pure-functions).

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
impossible. When a matching literal names the whole key, it also
proves the fact's stored values for the fields it filters on. With a
bind marker in the key, it says nothing about any one fact's values.

A `let` whose value is substitutable is replaced by its value wherever
the name appears. Substitutable values include fact reads (`exists`,
`query`, and counts), pure function calls, and struct literals, not
just simple values. The fact database cannot change during a policy
block, so the same expression gives the same value wherever it
appears. So this proves `Device[device_id: id]` exists after the `if`:

```policy
let device = query Device[device_id: id]
if device is None { recall missing_device() }
```

A field read from a struct literal is the value the literal gave it, so
a `RoleInfo { role_id: id, .. }` passed to a finish function lets a key
written `role.role_id` in its body match `id`. A literal composed from
another struct, as in `Info { v: 0, ...key }`, gives `key.k` for the
field it took from `key`.

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

A key the query gave is linked to the field that reads it back. After
`let label = query Label[label_id: this.label_id] or ..`, a key written
`label.label_id` is `this.label_id`. Unlike the fact's stored values,
this holds after any mutation, since the variable never changes, so
this is proven:

```policy
finish {
    delete Label[label_id: label.label_id]
    delete Rank[object_id: label.label_id]
}
```

The link applies to fact keys once `let` names, and a finish function's
parameters, are replaced by the caller's values, so a parameter that
shares a name with a caller's variable never picks up its link. Binding
the name again forgets it.

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
interpret is **opaque**. Examples are fact reads inside comparisons,
`count_up_to`, calls that can't be followed, and blocks with more paths
than the exit limit. The
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
a stated value when, after `let` substitution, it is known to be the
stored `v` of `F[k]`:

- `q.v`, where `q` was bound by `let q = query F[k] or <terminal>` or a
  `Some(q)` arm with exactly the same key, counting keys read from `q`
  itself (see
  [Keys read from query results](#keys-read-from-query-results));
- a value a matching fact literal with the whole key filtered on, as
  in `check exists F[k]=>{v: x}`;
- a call to a pure function whose every exit returns the same stored
  value, such as `a.balance` where `a` holds `Account[user: u]`, in the
  caller's terms;
- a value checked equal to any of these, in either order, as in
  `check q.v == x`.

The analysis records these as *value entries*: the fact exists, and a
field of it holds a value. Like other facts, they are combined across
branches, carried out of helpers, and dropped when something may change
them. Equalities are followed one step at a time, from a value already
known to be stored, so `check a == b` followed by `check b == q.v` does
not make `a` a stored value. This is the common idiom:

```policy
let counter = query Counter[name: this.name]=>{value: ?} or recall reject()
finish {
    update Counter[name: this.name]=>{value: counter.value} to {value: new_value}
}
```

Any other stated value, such as a literal nothing filtered on or a
field read from a different fact, gets a warning.

An update that states some values and binds the rest with `?` always
fails, because the VM compares the stated values with the whole stored
value list. It gets its own warning. Binding every value with `?`
skips the comparison.

### Invalidation

State is conservatively invalidated when something may have changed the
fact database between an observation and an obligation:

- A mutation of `F[k]` sets the state of `F[k]` to its postcondition.
  What the path knows about a fact that provably differs from `F[k]`,
  meaning another fact or a key where both give different literals, is
  kept. Of what it knows about one that may be `F[k]`:
  - a `create` keeps everything. Creating a fact removes none, and if a
    fact the path knew existed was the one created, the `create` raised
    an exception, which its own obligation covers;
  - a `delete` keeps only absence, since it may have removed the fact;
  - an `update` keeps only absence too. The fact still exists, but its
    values may have changed, and a second mutation of the same fact in
    one finish block is an exception that the touched set only catches
    for identical keys. Forgetting that the fact exists keeps a second
    mutation of what may be the same fact from being proven.

  An `update` or `delete` also forgets query results and stored values
  for facts that may be `F[k]`. A `create` or `update` may make a fact
  exist where the path knew it absent, so from then on, absence holds
  only for facts that provably differ from every fact created or
  updated since the block began. That covers observed absence and an
  init command's empty database alike: after
  `check !exists F[k: x, j: ?]`, creating `F[k: x, j: 1]` and then
  `F[k: x, j: 2]` is proven.
- A `map` statement forgets everything. `map` is only allowed in
  actions, which the analysis does not walk, so this is never reached
  today; if the language ever allows it in a policy block, its body
  may mutate any fact any number of times.
- A call the analysis cannot follow forgets everything. See
  [Finish functions](#finish-functions).
- Binding a name again, with a `let` or a `match` arm, forgets every
  fact, substitution, query binding, and key link that mentioned the
  earlier binding. A name can be reused once the block that bound it ends, but
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
3. `if` and `match`: walk each arm from a clone of every path's state,
   adding what its condition proves when true and what every earlier
   condition proves when false. The `else` branch, or the code after an
   `if` without one, learns that every condition was false. At the end
   of each arm, forget the names it bound, then merge the paths out of
   all the arms, as described under
   [Merging and joining paths](#merging-and-joining-paths), and walk the
   statements after the branch once per remaining path.
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

### Merging and joining paths

Walking each way through a block separately would take time
exponential in the number of branches: each `if` doubles the paths
through the code after it. Two steps keep the walk bounded.

- **Paths with the same state are merged.** At the end of each branch,
  the names it bound are forgotten, since nothing after the branch can
  refer to them. Branches that differ only in their locals, or that
  learn the same facts, then reach the same state, and the code after
  them is walked once. This loses nothing: the paths knew the same
  things. Their opaque points are kept, once each.
- **Past the path limit, paths are joined.** When more distinct states
  than the limit (`Compiler::max_paths`, 64 by default) reach one
  point, they are joined into one state that keeps only what every path
  knows: the facts all of them imply, combined as for `||`, and the
  substitutions and query bindings they all share. This is sound but
  loses any correlation between branches from that point on.

A join is never silent, because what it drops can cause false
positives. Every join is reported at the branch whose paths were
joined, with a warning naming the facts it dropped. On the joined path,
each of those facts gets a note pointing at the join, so a later
warning about one of them shows where its proof may have been lost and
says it may be a false positive. A join inside a pure function is
reported once, when the function is first summarized.

Block expressions are walked the same way. The paths that run off the
end of a block's statements are the block's arms, and every one of them
reaches the block's final expression. Function exits found inside the
block still go to the function's summary.

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

A call doesn't have to be the whole condition. Wherever a call always
runs, in a comparison, a `let` value, an argument, a fact key, a struct
field, or a `match` scrutinee, it returns through one of its exits, so
what every exit knows holds afterward. So
`check this.old_rank == get_object_rank(id)` proves
`Rank[object_id: id]` exists when the helper fails without it, and so
does `let rank = get_object_rank(id)`. A call that may not run counts
only where it ran. `a && b` and `a || b` keep what `a` proves on both
of their outcomes, since `b` runs only after `a`, and the arms of an
`if` or `match` are combined as described under
[`if`, `match`, and block expressions](#if-match-and-block-expressions).
A call in a `debug_assert` doesn't count, since release builds skip it.

An exit knows what returning its value implies: the calls in the value
returned, and that `x` was `Some` when the value is `x or <terminal>`.
An exit whose value can't be computed on its path is no exit at all.
An exit that returns a stored value records it, so a caller can use the
call's value as that stored value.

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
  (`Compiler::max_exit_paths`, 64 by default);
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

One mutation can fail on several paths that stay apart, and a shared
finish function can fail from several commands. Warnings with the same
span and message are merged, keeping the first one's position and the
union of their notes. This happens as warnings are added, and again
across the whole policy.

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
| paths were joined here, dropping facts about `F` that only some of them knew | more than N distinct paths leave this branch |

Opaque points touching the same fact are shown as secondary
annotations labeled "touches `F` but is too complex to analyze". Joins
that dropped facts about it are labeled "paths were joined here,
dropping facts about `F`", and the warning gets a note that it may be a
false positive. Calls that led into a finish function are labeled "in
this call to `f`".

## Interface

- `Compiler::analyze_obligations(bool)` enables the analysis. It is off
  by default.
- `Compiler::max_exit_paths(usize)` sets the most exits recorded for one
  pure function. The default is `DEFAULT_MAX_EXIT_PATHS`, 64.
- `Compiler::max_paths(usize)` sets the most distinct paths kept at one
  point before they are joined. The default is `DEFAULT_MAX_PATHS`, 64.
- The analyzer is only built when the analysis is enabled.
- `Compiler::compile_with_diagnostics()` returns the compiled module and
  the warnings. `Compiler::compile()` is unchanged.
- `ObligationWarning` holds the span, message, label, span notes, and
  footnotes of a warning. `ObligationWarning::render(source)` renders it
  with `annotate-snippets`, like compiler errors.
- The `policy-compiler` binary takes `--check-obligations`,
  `--max-exit-paths <N>`, and `--max-paths <N>`, and prints warnings to
  stderr.

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
- merging and joining paths: a correlation between branches kept when
  their paths stay apart or merge, and lost past the path limit, a join
  keeping what every path knows, one copy of each note on merged paths,
  and long chains of branches finishing in bounded time, enforced by a
  time limit so a regression fails rather than hangs;
- join reporting: the join warning naming only the facts it dropped,
  the note and false-positive footnote on a warning it caused, and a
  join inside a helper reported once;
- bind-marker subsumption for negative observations only, and `let`
  aliases;
- update stated values from a query, through a `let` alias, from a
  literal, and from a query of a different fact; values checked equal
  to a query's, in either order and through a `let`; values returned by
  a helper, directly or through another; values filtered on by
  `exists`, `query`, `at_least`, a `match` arm, and a bound-key query;
  through a finish function; alongside a key checked equal to the same
  value; and after creating another fact;
- struct fields: a key read from a struct literal passed to a finish
  function, bound by `let`, read in the command, nested in another
  struct, and composed from another struct, and a stored value read
  from a struct field;
- what a mutation keeps: keys that differ by an int, string, bool, or
  enum literal, in a command and an init command; absence of a key
  prefix surviving creates of parts of it; and what a `create`,
  `update`, and `delete` each keep;
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
- helper calls proving their facts compared, bound by `let`, passed as
  an argument, in a fact key, in a struct field, returned through `or`,
  through helpers that call helpers, inside a returned value, on the
  left of `&&` and `||`, and as a `match` scrutinee; and an exit whose
  value can't be computed not counting;
- keys read from query results: `delete` and `update` with the full
  key after `let .. or`, after a `Some(m)` arm, with a value filter,
  through a `let` alias, through a finish function, through a helper
  returning the query (with `let` and with `match`), and in an init
  command; warnings for an arm mixing `Some(m)` and `None`, for a
  mutation of the same fact earlier in the finish block, for a helper
  whose exits query different keys, and for a helper returning `Some`
  of a local; and a key the query gave read back from its result,
  after another mutation, in a `match` arm, through a finish function,
  and in a condition;
- rebinding: a `let` or `Some(m)` arm reusing a name forgets facts
  about the earlier binding, including a mention nested in another
  fact's key;
- expressions: `if` and `match` in a `check`, blocks with `let`,
  `check`, `if`, and `match` statements, a `match` `let` binding the
  query result and learning from its producing arms, an `if` returning
  a query before `or recall`, a helper returning an `if`, an arm
  returning from a helper, a nested `return` making a helper unknown, a
  `finish` inside a block being checked, blocks over the exit limit,
  an `else` arm that proves nothing, arm-bound and block-local names
  not leaking, and arms proving absences of different extents;
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
  leaking into its caller, an argument captured by a binder inside
  a helper, a key read back after its name was bound again or from
  a parameter named like the caller's variable, and a struct field read
  from the wrong field or from a parameter named like the caller's
  variable;
- `attacks_state.rs`: keys that may alias in one finish block, directly
  and through a finish function, a finish function dropping the
  caller's query binding, a recursive call in an init command, recall
  blocks not inheriting policy knowledge, double manipulation across
  a call, two keys both checked absent that may be one fact, a prefix's
  absence after creating what may be part of it, an `update` then a
  `delete` of what may be one fact, and a `delete` dropping the query
  result of what may be the deleted fact;
- `attacks_calls.rs`: a helper's facts from a call that may not run, on
  the right of `&&`, `||`, or `or`, as a condition and in a `let`, in
  an arm of an `if` or `match`, and in a `debug_assert`, and from a call
  whose exits disagree;
- `attacks_values.rs`: stored values checked unequal, equal on one
  branch only, equal to a key, of another fact, of another field,
  filtered on with a bind marker in the key, which must also not stand
  in for the missing key, and returned by a helper whose exits return
  different values or that read through a key it bound;
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
walking arms without a value and terminal blocks, the arm-name filter on what an arm proves, capture refusal, the
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

Writing the attacks for the four precision fixes of 2026-10-05 caught
one design error before it landed. Keeping a fact's existence after an
`update` of a fact that may be the same one would have proven a second
mutation of it. That is an exception the touched set misses for keys
written differently, and dropping the existence is what flags it.

Every test asserts something the rule it names can change. A test
whose result would be the same with the rule broken, such as "no
warnings" after a mutation the path proves anyway, is not kept: an
audit of the suite removed several and rewrote others so the rule is
the only thing standing between the prover and a wrong answer.

### The daemon policy

`obligation/tests/data/daemon-policy.md` is Aranya's daemon policy,
ported to the current syntax by `port-daemon-policy.py` next to it. It
is a test artifact, not the production policy, and its preamble lists
what the port changed. It compiles against the daemon's real FFI
schemas, which are dev-dependencies of the compiler. Two tests use it:

- `daemon_policy_warnings` keeps its warnings in a snapshot, one line
  per warning followed by its calling contexts, so a change in
  precision shows up as a diff to review;
- `injected_bug_warns` injects bugs the policy's guards prevent, by
  dropping a guard, pointing it at the wrong key, or inverting a
  branch. Each must add a warning at the mutation the guard protected.
  These are the analysis finding real bugs in real code, so a precision
  change that silences one is unsound.

Measured on 2026-10-05, the analysis added about 5 ms to a 5 ms
debug-build compile and joined no paths. Joins first appear with the
path limit lowered to 2.

The analysis first raised 14 warnings there, and none is a real bug:
under the policy's invariants, every mutation it flags succeeds. Five
came from gaps in the analysis, since fixed. A helper's facts counted
only where its call was a whole condition, values checked equal to a
stored value weren't tracked, a mutation forgot every other key of its
fact, and a key read back from a query wasn't linked to the key it
used. The 9 left need knowledge the policy doesn't state:

- **Keys derived from the command's own ID.** In this policy, no
  fact can hold such a key before the command runs, because every
  command that stores an ID taken from a field first checks that its
  object exists. That is a property of the whole policy, not of one
  command. Elsewhere, a member who has seen a command could author a
  concurrent one that stores its ID from a field, and the merge could
  order that one first;
- **Invariants between facts.** For example, a `Device` fact implies
  its three key facts and its `Rank`, and a `RoleAssignmentIndex` entry
  implies the matching `AssignedRole`. The policy checks some of these
  only in debug builds.

| Warning | From | Cause |
|---|---|---|
| `create Role` | `CreateRole`, `SetupDefaultRole` | Own ID |
| `create Rank` | `CreateLabel`, `CreateRole`, `SetupDefaultRole` | Own ID |
| `create Rank` | `CreateTeam`, after the device's `Rank` | Own ID, distinct from the device's ID |
| `create Rank` | `AddDevice` | Invariant |
| `create RoleHasPerm` | `SetupDefaultRole` | Own ID |
| `create RoleAssignmentIndex` | `ChangeRole` | Invariant on a stored value |
| `delete` of the three device key facts | `RemoveDevice` | Invariant |
| `delete Rank` | `RemoveDevice`, when a device removes itself | Invariant |
| `create Label` | `CreateLabel` | Own ID |

A warning shared by several commands, such as the one in
`set_object_rank`, goes away only when every command's cause does.
Knowing which IDs are fresh would clear 3 of the 9. The rank create
needs that and an invariant. The other 5 need invariants alone. Each
cause was confirmed on a copy of the policy by adding the checks it
stands for.

A third cause was found that way and fixed. `create_role_facts` takes a
`RoleInfo` and keys its facts by `role.role_id`, and the analysis didn't
see that this is the ID the caller put in the struct. Now a field read
from a struct literal is the field's value. That clears nothing on its
own here, since the role's ID is the command's own.

Three commands rely on an invariant where the policy checks a similar
one elsewhere. `AddDevice` checks that four of the five facts it
creates are absent, but not `Rank`. `ChangeRole` creates a
`RoleAssignmentIndex` entry without the absence check `AssignRole`
makes before creating one. `RemoveDevice` deletes a device's key facts
on the strength of its `Device` fact, which `valid_device_invariants`
ties to them only in debug builds.

## Known limitations

- **`count_up_to`** is opaque.
- **Branching `let` values are not substituted.** `let ok = if ..`
  followed by `check ok` proves nothing, though `ok` still matches
  itself by name in fact keys.
- **Past the path limit, branches lose their correlation.** Paths are
  joined, keeping only what every one of them knows, so a later branch
  can't rely on an earlier one having gone the same way. Each join is
  reported, and warnings it may have caused say so.
- **A `return` the walk can't record**, such as one inside a returned
  value or a `match` scrutinee, makes its function unknown.
- **Double manipulation is syntactic.** Only identical keys are flagged,
  so two mutations whose keys are equal at runtime but written
  differently are missed.
- **Keys differ only by literals.** Two keys are known to differ only
  where both give different literals. A checked `x != y` is not used,
  so after `delete F[k: x]`, nothing is known about `F[k: y]`.
- **FFI calls** are not substituted, so a key computed by an FFI call is
  compared by the name of the variable holding it.
- **Helper knowledge** is limited to facts expressed in the helper's
  parameters and globals. A call inside a block that is itself inside
  a compared expression doesn't count.
- **Struct fields are followed only on literals.** A field read through
  `substruct` or a cast with `as` isn't recognized as the field it came
  from, so a fact key read that way matches nothing.
- **Equalities are followed one step, to stored values only.** A
  checked `a == b` says nothing until one side is a stored value, and
  an equality between other values isn't used to match keys.
- **Properties of the whole policy** are unknown. A key derived from
  the command's own ID may be absent because of how every other command
  stores IDs, and one fact may imply another, but the analysis sees one
  command at a time.
  [The daemon policy](#the-daemon-policy) shows how often these come
  up.

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
  warnings to errors. The daemon policy raises 9 false positives
  today. [The daemon policy](#the-daemon-policy) lists their causes.
- **Declared invariants, next:** state relationships between facts in
  the schema, such as a `Device` implying its three key facts, or a key
  that must refer to an existing fact. Each becomes an obligation every
  command must prove holds when it finishes, and that every command may
  then assume holds when it starts. The analysis checks the relationships
  the policy declares instead of trying to discover them. Declared
  references would also settle keys built from the command's own ID:
  when every key holding another object's ID must refer to an existing
  fact, no fact can hold a command's ID before that command runs.
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
