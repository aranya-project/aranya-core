# Proving the obligation analysis correct: discussion notes

Status: deferred on 2026-09-28. This records a design discussion so it
can be resumed later. It is not part of the published design doc,
`policy-obligation-analysis.md`.

## Questions

1. How would we prove the obligation checker correct, given the policy
   language has no formal semantics or requirements to prove against?
   Can those be lightweight and focused on what the checker needs? What
   other challenges would we face?
2. On another project, the language was defined in SMT-LIB, leaning on
   SMT-LIB's existing formalization and using Z3 and other solvers to
   execute it as an oracle. Would that work here, given how bounded
   policies are? Compile a policy to SMT-LIB, express the proof
   obligations in SMT-LIB, and solve them with Z3. It would not be the
   production checker, but it would give a reference implementation with
   a formal semantics.

## Background

The adversarial tests found three false negatives, all fixed:

- A value filter on a negative observation was ignored, so
  `check !exists F[k]=>{v: 0}` proved `F[k]` absent.
- A `match` arm `Some(1)` that failed to match was treated as proving the
  value is `None`, pruning later `Some(x)` and default arms.
- A `return` nested inside a fact key or call argument in a helper's
  condition was never recorded as an exit.

Branch coverage of `obligation.rs` is complete, but coverage and
hand-written attacks only find the bugs someone thinks to look for.

## Part 1: a lightweight spec

The analysis depends on a narrow slice of the language, so the spec only
needs that slice. Everything else stays uninterpreted. That makes the
theorem stronger, not weaker: it holds for every possible meaning of the
parts left undefined. Anywhere a proof gets stuck marks an assumption the
analysis makes that nobody wrote down.

### The requirement

Soundness plus termination. Precision and diagnostic quality are not part
of the claim, so notes, spans, and message text drop out of the model.

```text
For every command block B, starting database D0, and inputs:
  if the analysis reports no warnings for B,
  then no run of B applies a create, update, or delete whose
  precondition fails, or touches one key twice in a finish block.
For an init command, D0 is empty.
```

### The model

- **Database.** A finite map from a fact name and key to values. A block
  reads a fixed D0, and a finish block applies its mutations to it in
  order. The five exceptions are predicates on that sequence.
- **Fact reads** get real semantics: `exists`, `query`, and the counting
  forms, with and without value filters. Which fact a `?` query returns
  is left unspecified, since the analysis never depends on it.
- **Control flow** gets real semantics: `let`, `check`, `if`, `match`
  including which values each pattern accepts, block expressions,
  `finish`, `e or <terminal>`, the terminal forms, and short-circuiting
  `&&` and `||`. The first draft of this spec left out `&&` and `||`,
  which led to the testing mistake described under Open items.
- **Everything else** is an uninterpreted, deterministic function of its
  inputs that may abort. Command fields, the envelope, and
  foreign-function results are inputs.

Not needed: the graph, sync, merges, perspectives, crypto, or the VM
instruction set. The theorem quantifies over every D0, so the only
runtime fact that enters is that an init command sees an empty database.

### Assumption register

What the analysis needs from outside, what enforces it, and what relies
on it. The guards in
`crates/aranya-policy-compiler/src/obligation/tests/assumptions.rs` cover
the compiler-enforced ones marked "guarded".

| Assumption | Enforced by | Relied on by |
|------------|-------------|--------------|
| No shadowing of an enclosing local or a global | Compiler, guarded | Rebinding: a `let` never mentions its own name |
| Fact keys are schema-order prefixes | Lowering, guarded | Prefix coverage, full-key patterns |
| Mutations only in finish contexts | Compiler | The database is fixed during a block |
| No calls or queries in finish expressions | Compiler, guarded | Key expressions mean their value in D0 |
| A finish ends its path, even inside a block expression | Code generation, guarded | Block end collection |
| Terminal forms never continue | Type system | `check`, `or`, and arm handling |
| `map` only in actions | Compiler, guarded | The walker's `map` arm is unreachable |
| `&&` and `\|\|` short-circuit | Code generation | The spec and any oracle |
| Init commands see an empty database | Runtime | Init knowledge |
| Pure functions are deterministic | Design expectation only | Matching and substituting pure calls |

Pure functions can call foreign functions. For example,
`authorized_device_key_ids` in
`crates/aranya-model/src/tests/ffi-policy.md` calls
`idam::derive_device_id`. So the last row assumes every foreign function
is deterministic.

### The meaning of the analysis state

This is the invariant a proof maintains.

```text
A concrete state (bindings ρ, pre-state D0, current database D) satisfies
an analysis state when:
  each Exists pattern names a fact present in D
  each NotExists pattern names a key prefix with no fact in D
  each substitution x := e has ρ(x) equal to e evaluated in ρ and D0
  each query binding x : p has ρ(x) equal to the stored fact at p in D
  if the database started empty, D has no fact of any name not yet mutated
Key expressions are always evaluated against D0, never against D.
```

The last line is a real subtlety. It holds only because finish
expressions can't contain calls or queries.

## Part 2: the proof

A simulation argument. Every concrete run follows some path the analysis
walks, and the invariant holds at each step, so every obligation the
analysis discharged holds in the run. The work splits into lemmas:

- **Conditions.** What the analysis says a condition proves when true or
  false really holds in that case.
- **Pruning.** A contradiction means the concrete path can't run.
- **Summaries.** Every concrete return from a pure function has a
  recorded exit, or the function is marked unknown.
- **Substitution.** A substituted expression has the same value as the
  original.
- **Scope hygiene.** Every entry in the state still refers to the binding
  it was made for. This is the hardest lemma. `forget_name` and the
  arm-local fact filter exist to satisfy it.
- **Mutations.** The obligation checks are strong enough, and the state
  after a mutation still satisfies the invariant.
- **Termination.** There are no loops, and recursion guards cover pure
  and finish functions.

The three false negatives each broke one lemma. The value-filter and
`Some(1)` bugs broke the condition lemma. The nested-return bug broke the
summary lemma.

### Findings from sketching the argument

- **The touched set is sound only together with forgetting.** The design
  doc says the touched-set check only flags keys written identically and
  accepts false negatives. That is true of the check alone, not of the
  analysis. When two keys in one finish block are equal at runtime but
  written differently, the first mutation forgets what the path knew
  about facts it may be, which then meant every other fact of that name,
  so the second can't discharge its own obligation and warns.
  The touched set is needed only for keys written identically where the
  first mutation's postcondition satisfies the second's precondition,
  such as create then delete, update then delete, or delete then create.
  Any fix for the known "distinct keys" limitation must keep knowledge
  only for keys proven distinct, or the rule against touching a key twice
  loses its safety net. The fix made on 2026-10-05 follows this, with one
  exception that is safe: a `create` keeps knowledge about facts that may
  be the created one, since if one was, the `create` itself fails its
  obligation.
- **Substitution depends on the finish rules.** Replacing a `let` by its
  defining query or pure call is valid only because the database can't
  change before the use. That rests on mutations being confined to finish
  contexts and on finish expressions having no calls or queries.

### Other challenges

- **The spec is aspirational.** The runtime doesn't enforce three of the
  five invariants today, so a proof targets the documented semantics.
  Some edge cases need a decision first, such as whether the touched-set
  rule compares runtime values. It should.
- **Language rules live only in the compiler.** Several assumptions are
  compiler behavior rather than documented rules. The guard tests make a
  change loud but can't prevent it.
- **The analysis reads the typed tree, but the VM runs bytecode.**
  Lowering and code generation are in the trusted base.
- **The state holds syntax.** Facts are expressions read in an
  environment that changes as names are rebound and scopes end.
- **Rules depend on each other.** See the findings above. A local change
  can break a distant lemma.
- **Fallbacks need proofs too.** Every opaque, unknown, or
  forget-everything path must over-approximate. The nested-return bug was
  a fallback that didn't fire in every position.
- **The code keeps moving.** A paper proof drifts. Full mechanization
  would fight the closures, caching, and cloning in the current design.
- **The spec itself can be wrong.** It needs checking against real
  execution.

### First recommendation

Superseded in direction by Part 3, but kept for reference.

1. Write the spec and argument into the design doc, with each lemma
   stated in a doc comment on the function it covers.
2. Build an executable oracle. For each corpus policy, enumerate tiny
   databases and inputs and run the command in the VM. The VM rejects
   updates it can't apply, and its test I/O raises errors for creating an
   existing fact and deleting a missing one. Add a touched-set check to
   cover all five invariants. Any exception on a policy the analysis
   calls clean is a bug. Mutating the corpus turns it into a fuzzer.
3. Mechanize only the small operations that combine and compare
   knowledge, if anything.

## Part 3: an SMT-LIB reference semantics

Assessment: this fits well. It makes a better oracle than enumeration,
because it is symbolic and, with the bound below, complete.

### Why it fits

- **The programs are bounded.** Blocks are loop-free, since `map` is only
  allowed in actions, and functions can be inlined because the language
  forbids recursion. The solver handles branching, so paths never need
  enumerating.
- **Opaque operations become uninterpreted functions.** That is exactly
  the "opaque but deterministic" rule from Part 1, with determinism made
  explicit as functional consistency. It tests the analyzer's actual
  claim: soundness for every interpretation of those operations. A
  concrete mode with real arithmetic would answer a different question,
  whether the policy itself is safe, which is useful for measuring false
  positives.
- **Values have direct encodings.** Booleans, integers, options, results,
  structs, and enums map onto standard theories and datatypes.

### The database needs no quantifiers

The database is unbounded, but a single run only observes a bounded
number of facts. Removing facts never breaks an observation that
something is absent, or that a count is at most some limit. Every other
observation needs only its witnesses:

- the fact a lookup found;
- one fact per true `exists`;
- at most n + 1 facts for a count with limit n;
- the fact a failing create or update collides with.

So if any database makes a mutation fail, a database made of just those
witnesses does too. The witness count can be computed from the policy.
Each fact table can then be a fixed set of symbolic slots with distinct
keys. The encoding stays quantifier-free, and an unsat answer covers
every database, not only small ones. Without the bound, bind markers and
negative checks need quantifiers, where solvers can answer "unknown".

If the VM picks the fact a `?` query returns as the least match under
some fixed order, the witness database preserves that choice too. The
chosen fact is still the least match in any subset that contains it.

An untested sketch for the value-filter false negative, which needs one
slot:

```smt2
; check !exists Account[user: this.user]=>{balance: 0} else recall failed()
; finish { create Account[user: this.user]=>{balance: 1} }
(set-option :produce-models true)
(set-logic QF_LIA)
(declare-const this-user Int)
(declare-const a0-present Bool)
(declare-const a0-user Int)
(declare-const a0-balance Int)
; With more slots, present slots must have distinct keys:
; (assert (=> (and a0-present a1-present) (distinct a0-user a1-user)))

; Passing the check is on the path to the finish block.
(assert (not (and a0-present (= a0-user this-user) (= a0-balance 0))))
; The create fails if the key already exists.
(assert (and a0-present (= a0-user this-user)))

(check-sat)   ; expected: sat, with a0-balance not 0
(get-model)
```

### Where it needs care

- **The translator becomes the semantics.** SMT-LIB fixes what the
  formulas mean, but not whether a translation means the same as the
  policy. The encoder is a second implementation of the language, and it
  can be wrong in the same ways the analyzer can. So "proven reference"
  needs that qualification.
- **Model replay closes most of that gap.** Each sat answer comes with a
  model, a concrete database and inputs, which the VM can replay with
  foreign functions stubbed to the model's values, using the test I/O
  plus a touched-set check. Fixing every input also turns the encoding
  into an interpreter, so random concrete runs can be compared against
  the VM.
- **Translate from the typed tree, not bytecode.** The encoder then
  mirrors the language and sees exactly what the analyzer sees. Replay
  still runs the real bytecode, so a disagreement points at either an
  encoder bug or a compiler bug.
- **It gives ground truth per policy, not a general proof.** The
  analyzer's general soundness needs induction over expression trees,
  which solvers don't do. The operations that combine and compare
  knowledge can still be proven in SMT for patterns up to a fixed length.
- **The oracle judges inputs but doesn't invent them.** It would have
  caught all three false negatives once a policy of each shape existed,
  so it needs a mutator over the test corpus.
- **Edges.** The translator must reject recursion, which the compiler
  doesn't yet reject (#607, #751). A count limit of n costs n + 1 slots,
  so a large literal limit needs a cardinality encoding instead.

### Suggested setup

1. **One question per mutation site.** Ask whether any database and
   inputs make the mutation fail, and compare with whether the analyzer
   warned there. A silent analyzer against a sat answer is a soundness
   bug and fails the test. A warning against an unsat answer is a false
   positive, which gives a precision measurement.
2. **Check the analyzer's intermediate claims, not just its verdicts.**
   With a trace hook, each belief the analyzer holds at each statement on
   each path becomes a query: does the path condition imply it? A wrong
   belief then fails at once, even when nothing downstream depends on
   it. This is the strongest payoff. It catches tests that pass only
   because nothing downstream observes the rule, which the test audit
   kept finding, and it turns the Part 2 lemmas into checks on every
   test.
3. **Keep the solver out of the build.** Emit SMT-LIB text and run the
   solver as a subprocess in a separate test job. That keeps Z3 out of
   the Rust dependency graph and out of the cargo-vet and cargo-deny
   checks. Standard SMT-LIB also lets cvc5 cross-check Z3, and cvc5 can
   emit unsat proofs that an independent checker verifies.

## Open items

These came out of the discussion but are not part of the deferred work.
They are small enough to fix during normal development.

1. **Fixed on 2026-10-05.** Two attack tests were mis-premised.
   `attack_return_inside_fact_key_is_an_exit` and
   `attack_return_inside_call_argument_is_an_exit` in
   `crates/aranya-policy-compiler/src/obligation/tests/attacks_helpers.rs`
   put the nested `return true` in the second operand of `&&`, after
   `exists Owner[]`. The compiler lowers `a && b` to
   `if a { b } else { false }`, so the return only runs once `Owner[]` is
   known to exist, and those policies are safe. The tests assert a
   warning on a safe policy, would block a sound precision improvement,
   and don't pin the real bug. The fix is to move the return into the
   first operand:

   ```policy
   check exists Account[user: match u { 1 => 1  _ => return true }] && exists Owner[]
       else return false
   ```

   Throwaway probes confirmed that this shape was accepted without the
   condition-leaf checks, although it is unsafe, and that it warns with
   them. The earlier probe that seemed to confirm the bug used the safe
   order, so it was showing a correct answer.
2. **Fixed on 2026-10-05.** The design doc's touched-set paragraph now
   says that soundness comes from the touched set together with
   forgetting, and notes the distinct-keys trap described under Part 2.
   The trap came up when fixing that limitation: keeping a fact's
   existence after an `update` of a fact that may be the same one would
   have proven a second mutation of it, so an `update` forgets it.

## When resuming

1. Settle the open spec questions. The touched-set rule should compare
   runtime values, and a `?` query should return an unspecified match.
2. Build the encoder for a small fragment first: `let`, `check`,
   `exists` and `query` with full keys, and `finish` with create and
   delete. Run it on the corpus's pass tests.
3. Add model replay in the VM.
4. Grow the fragment: bind markers, counts, value filters, `match`, block
   expressions, helpers, and finish functions.
5. Add the trace hook and intermediate-claim checking.
