//! Static obligation/observation analysis for fact mutations.
//!
//! Walks the typed HIR of command `policy` and `recall` blocks, tracking
//! abstract fact-database state (exists / does not exist / unknown) along
//! each control-flow path. A `create` statement carries the obligation that
//! the path previously observed that the fact does not exist (e.g. via
//! `check !exists Fact[..] else ..`); creating an existing fact is a runtime
//! exception. Unprovable obligations are reported as warnings, along with
//! any fact-touching expressions that were too complex to analyze.
//!
//! See `docs/policy-obligation-analysis.md` for the design.

use std::{borrow::Cow, cell::RefCell, collections::BTreeMap, rc::Rc};

use annotate_snippets::{AnnotationKind, Level, Renderer, Snippet};
use aranya_policy_ast::{
    FactCountType, Ident, Identifier, Span, Spanned as _, TypeKind, VType,
    thir::{
        ExprKind, Expression, FactLiteral, FunctionCall, InternalFunction, LetStatement,
        MatchPattern, Statement, StmtKind,
    },
};

/// A warning produced by the obligation analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObligationWarning {
    /// The location of the statement whose obligation could not be proven.
    pub span: Span,
    /// The primary warning message, used as the title.
    pub message: String,
    /// A short label attached to the statement's span.
    pub label: String,
    /// Additional notes, each pointing at a source location.
    pub notes: Vec<(Span, String)>,
    /// Notes and help text shown after the source snippet.
    pub footnotes: Vec<(Footnote, String)>,
}

/// The kind of a footnote attached to an [`ObligationWarning`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Footnote {
    /// Explains why the warning matters.
    Note,
    /// Suggests how to fix the warning.
    Help,
}

impl ObligationWarning {
    /// Render the warning as an annotated source snippet.
    ///
    /// `input` is the full policy source text.
    pub fn render(&self, input: &str) -> String {
        let title = Level::WARNING.primary_title(self.message.clone());
        let mut annotations = vec![
            AnnotationKind::Primary
                .span(self.span.into())
                .label(self.label.clone())
                .highlight_source(true),
        ];
        for (span, note) in &self.notes {
            annotations.push(
                AnnotationKind::Context
                    .span((*span).into())
                    .label(note.clone()),
            );
        }
        let mut group = title.element(Snippet::source(input).annotations(annotations));
        for (kind, text) in &self.footnotes {
            let level = match kind {
                Footnote::Note => Level::NOTE,
                Footnote::Help => Level::HELP,
            };
            group = group.element(level.message(text.clone()));
        }
        Renderer::plain().render(&[group])
    }
}

/// Abstract knowledge about a fact along the current path.
///
/// A fact pattern not present in the state is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FactState {
    Exists,
    NotExists,
}

/// A canonicalized fact literal: fact name plus key-field values after
/// `let` substitution. Trailing bind markers (`?`) are omitted, as in the
/// typed HIR, so `keys` is a prefix of the schema's key fields.
#[derive(Debug, Clone)]
struct FactPattern {
    name: Ident,
    keys: Vec<(Identifier, Expression)>,
    span: Span,
    /// The fact literal as written in the source (name and key fields),
    /// for diagnostics.
    text: String,
}

/// Fact knowledge.
type Facts = Vec<(FactPattern, FactState)>;

/// What holds when some condition is true (or false), or `None` if that
/// outcome is impossible.
type Know = Option<Facts>;

/// No knowledge, but possible.
fn nothing() -> Know {
    Some(Vec::new())
}

/// Knowledge of a single fact.
fn fact_is(pat: FactPattern, state: FactState) -> Know {
    Some(vec![(pat, state)])
}

/// Would adding `(pat, state)` contradict `facts`?
///
/// A `NotExists` pattern covers every longer pattern it is a prefix of, so
/// `NotExists F[a: x]` contradicts `Exists F[a: x, b: y]`. An `Exists`
/// pattern with fewer keys only says some matching fact exists.
fn contradicts(facts: &Facts, pat: &FactPattern, state: FactState) -> bool {
    facts.iter().any(|(q, s)| match (state, *s) {
        (FactState::Exists, FactState::NotExists) => covers(q, pat),
        (FactState::NotExists, FactState::Exists) => covers(pat, q),
        _ => false,
    })
}

/// Knowledge that holds when both `a` and `b` hold.
fn both(a: Know, b: Know) -> Know {
    let (mut a, b) = (a?, b?);
    for (pat, state) in b {
        if contradicts(&a, &pat, state) {
            return None;
        }
        if !a.iter().any(|(q, s)| *s == state && same_pattern(q, &pat)) {
            a.push((pat, state));
        }
    }
    Some(a)
}

/// Knowledge that holds when at least one of `a` or `b` holds: only what
/// both imply.
fn either(a: Know, b: Know) -> Know {
    let (a, b) = match (a, b) {
        (None, k) | (k, None) => return k,
        (Some(a), Some(b)) => (a, b),
    };
    let mut out: Facts = Vec::new();
    for (pa, sa) in &a {
        for (pb, sb) in &b {
            if sa != sb {
                continue;
            }
            // For `NotExists`, the more specific pattern is implied by both.
            let kept = if same_pattern(pa, pb) {
                Some(pa)
            } else if *sa == FactState::NotExists && covers(pa, pb) {
                Some(pb)
            } else if *sa == FactState::NotExists && covers(pb, pa) {
                Some(pa)
            } else {
                None
            };
            if let Some(p) = kept
                && !out.iter().any(|(q, s)| s == sa && same_pattern(q, p))
            {
                out.push((p.clone(), *sa));
            }
        }
    }
    Some(out)
}

/// [`either`], recording an opaque point at `span` for each fact that one
/// side knew about but the combination doesn't. The expression touches
/// that fact but proves nothing about it on its own, which a warning about
/// the fact should point out.
fn either_noted(st: &mut PathState<'_>, span: Span, a: Know, b: Know) -> Know {
    let mut known: Vec<Ident> = Vec::new();
    for (pat, _) in a.iter().chain(b.iter()).flatten() {
        if !known.contains(&pat.name) {
            known.push(pat.name.clone());
        }
    }
    let result = either(a, b);
    for name in known {
        let kept = result.iter().flatten().any(|(pat, _)| pat.name == name);
        if !kept {
            st.opaque.push((name, span));
        }
    }
    result
}

/// The lowered body of a function.
#[derive(Debug, Clone)]
struct FunctionBody {
    params: Vec<Identifier>,
    statements: Vec<Statement>,
}

/// One way a pure function can return.
#[derive(Debug, Clone)]
struct Exit {
    /// What is known on the path to this `return`, in the function's terms.
    facts: Facts,
    /// The returned value, in the function's terms.
    ret: Expression,
}

/// A pure function's exits, used to evaluate calls to it.
#[derive(Debug)]
struct Summary {
    params: Vec<Identifier>,
    exits: Vec<Exit>,
}

/// The default limit on the number of exits recorded for one pure
/// function. Functions with more are treated as unknown calls.
pub const DEFAULT_MAX_EXIT_PATHS: usize = 64;

/// Runs the obligation analysis for one policy.
///
/// Function bodies are recorded as the compiler lowers them. Pure and
/// finish functions are compiled before commands, so every body is
/// recorded before any command block is analyzed.
#[derive(Debug)]
pub(crate) struct Analyzer {
    /// The full policy source text, for diagnostics.
    src: String,
    /// Global `let` names, which may appear in function bodies.
    globals: Vec<Identifier>,
    /// The key fields of each fact, in schema order.
    fact_keys: BTreeMap<Identifier, Vec<(Identifier, VType)>>,
    finish_functions: BTreeMap<Identifier, FunctionBody>,
    pure_functions: BTreeMap<Identifier, FunctionBody>,
    max_exit_paths: usize,
    /// Pure function summaries, computed on first use. `None` means the
    /// function can't be summarized.
    summaries: RefCell<BTreeMap<Identifier, Option<Rc<Summary>>>>,
    /// Pure functions being summarized, to stop at recursion.
    summarizing: RefCell<Vec<Identifier>>,
}

impl Analyzer {
    pub(crate) fn new(
        src: String,
        globals: Vec<Identifier>,
        fact_keys: BTreeMap<Identifier, Vec<(Identifier, VType)>>,
        max_exit_paths: usize,
    ) -> Self {
        Self {
            src,
            globals,
            fact_keys,
            finish_functions: BTreeMap::new(),
            pure_functions: BTreeMap::new(),
            max_exit_paths,
            summaries: RefCell::new(BTreeMap::new()),
            summarizing: RefCell::new(Vec::new()),
        }
    }

    /// Record a finish function's lowered body.
    pub(crate) fn record_finish_function(
        &mut self,
        name: Identifier,
        params: Vec<Identifier>,
        statements: Vec<Statement>,
    ) {
        self.finish_functions
            .insert(name, FunctionBody { params, statements });
    }

    /// Record a pure function's lowered body.
    pub(crate) fn record_pure_function(
        &mut self,
        name: Identifier,
        params: Vec<Identifier>,
        statements: Vec<Statement>,
    ) {
        self.pure_functions
            .insert(name, FunctionBody { params, statements });
    }

    /// Analyze the lowered statements of a command `policy` or `recall`
    /// block.
    ///
    /// `empty_db` is true for the blocks of an `init` command, which always
    /// runs against an empty fact database: the runtime only accepts an
    /// init command as the root of the graph.
    pub(crate) fn analyze_block(
        &self,
        stmts: &[Statement],
        empty_db: bool,
    ) -> Vec<ObligationWarning> {
        let mut out = Out::new(usize::MAX);
        walk(stmts, &[], PathState::new(self, empty_db, false), &mut out);
        dedup_warnings(out.warnings)
    }

    /// The summary of a pure function, computing it on first use.
    fn summary(&self, name: &Identifier) -> Option<Rc<Summary>> {
        if let Some(s) = self.summaries.borrow().get(name) {
            return s.clone();
        }
        if self.summarizing.borrow().contains(name) {
            // Recursion: the language forbids it, but the compiler does not
            // yet reject it (#607, #751).
            return None;
        }
        let body = self.pure_functions.get(name)?;
        self.summarizing.borrow_mut().push(name.clone());
        let mut out = Out::new(self.max_exit_paths);
        walk(
            &body.statements,
            &[],
            PathState::new(self, false, true),
            &mut out,
        );
        self.summarizing.borrow_mut().pop();
        let summary = (!out.unusable).then(|| {
            Rc::new(Summary {
                params: body.params.clone(),
                exits: out.exits,
            })
        });
        self.summaries
            .borrow_mut()
            .insert(name.clone(), summary.clone());
        summary
    }
}

/// What a walk produces.
struct Out<'a> {
    warnings: Vec<ObligationWarning>,
    /// Exits, when summarizing a pure function.
    exits: Vec<Exit>,
    max_exits: usize,
    /// The walk can't be summarized: it found more than `max_exits`
    /// exits, or a `return` the walk doesn't model as an exit.
    unusable: bool,
    /// Keep the state of every path that runs off the end of the walked
    /// statements, to evaluate a block expression.
    collect_ends: bool,
    ends: Vec<PathState<'a>>,
}

impl<'a> Out<'a> {
    fn new(max_exits: usize) -> Self {
        Self {
            warnings: Vec::new(),
            exits: Vec::new(),
            max_exits,
            unusable: false,
            collect_ends: false,
            ends: Vec::new(),
        }
    }
}

/// Analysis state along a single control-flow path.
#[derive(Debug, Clone)]
struct PathState<'a> {
    az: &'a Analyzer,
    facts: Facts,
    /// `let`-bound names with substitutable values.
    env: BTreeMap<Identifier, Expression>,
    /// Fact-touching expressions the extractor could not interpret.
    opaque: Vec<(Ident, Span)>,
    /// The fact database is known to be empty at the start of the block
    /// (an `init` command), except for facts named in `dirty`.
    empty_db: bool,
    /// Facts that may have been mutated since the block started.
    dirty: Vec<Identifier>,
    /// Variables holding a fact read by a query, with the fact they hold.
    /// Used to prove an `update`'s stated values match the stored fact.
    query_bindings: Vec<(Identifier, FactPattern)>,
    /// Walking a pure function body to summarize it.
    in_function: bool,
    /// Inside a finish function body, where every name must be a parameter
    /// or a global. Any other name must not be mistaken for a caller's
    /// variable of the same name.
    strict: bool,
    /// Pure function calls being evaluated, to stop at recursion.
    evaluating: Vec<Identifier>,
}

impl<'a> PathState<'a> {
    fn new(az: &'a Analyzer, empty_db: bool, in_function: bool) -> Self {
        Self {
            az,
            facts: Vec::new(),
            env: BTreeMap::new(),
            opaque: Vec::new(),
            empty_db,
            dirty: Vec::new(),
            query_bindings: Vec::new(),
            in_function,
            strict: false,
            evaluating: Vec::new(),
        }
    }

    /// Is every fact named `name` known not to exist?
    fn known_absent(&self, name: &Identifier) -> bool {
        self.empty_db && !self.dirty.contains(name)
    }

    /// Record that facts named `name` may have been mutated. Query results
    /// for that fact no longer reflect the database.
    fn mark_dirty(&mut self, name: &Identifier) {
        if !self.dirty.contains(name) {
            self.dirty.push(name.clone());
        }
        self.query_bindings.retain(|(_, p)| p.name.inner != *name);
    }

    /// Forget everything: an unknown call may have mutated any fact.
    fn forget_all(&mut self) {
        self.facts.clear();
        self.query_bindings.clear();
        self.empty_db = false;
    }

    /// Add knowledge to this path. Returns false if the path is impossible.
    fn assume(&mut self, know: Know) -> bool {
        let Some(facts) = know else {
            return false;
        };
        for (pat, state) in facts {
            if contradicts(&self.facts, &pat, state)
                || (state == FactState::Exists && self.known_absent(&pat.name.inner))
            {
                return false;
            }
            observe(self, pat, state);
        }
        true
    }

    fn bind_query(&mut self, var: Identifier, pat: FactPattern) {
        self.query_bindings.retain(|(v, _)| *v != var);
        self.query_bindings.push((var, pat));
    }

    /// Forget everything that referred to an earlier binding of `v`,
    /// before `v` is bound again.
    ///
    /// A name can be reused once the block that bound it ends, but the
    /// walk carries a branch's state into the statements after it. A fact
    /// or value that mentions the old `v` would silently start meaning
    /// the new one.
    fn forget_name(&mut self, v: &Identifier) {
        self.env.remove(v);
        self.env.retain(|_, e| !mentions(e, v));
        self.facts.retain(|(p, _)| !mentions_pattern(p, v));
        self.query_bindings
            .retain(|(x, p)| x != v && !mentions_pattern(p, v));
    }
}

/// Collapse warnings that differ only in their notes.
///
/// Statements after an `if`/`match` are walked once per path, so a
/// statement reached by several failing paths is reported once per path.
/// Warnings with the same span and message are merged, keeping the first
/// occurrence's position and taking the union of the notes (different
/// paths may have skipped different opaque expressions).
pub(crate) fn dedup_warnings(warnings: Vec<ObligationWarning>) -> Vec<ObligationWarning> {
    let mut out: Vec<ObligationWarning> = Vec::new();
    for w in warnings {
        match out
            .iter_mut()
            .find(|o| o.span == w.span && o.message == w.message)
        {
            Some(existing) => {
                for note in w.notes {
                    if !existing.notes.contains(&note) {
                        existing.notes.push(note);
                    }
                }
            }
            None => out.push(w),
        }
    }
    out
}

/// Walk one path segment. `cont` holds the statement segments that follow
/// this one (innermost first), so branch arms continue into the statements
/// after their enclosing `if`/`match`.
fn walk<'a>(stmts: &[Statement], cont: &[&[Statement]], mut st: PathState<'a>, out: &mut Out<'a>) {
    let mut remaining = stmts;
    while let Some((stmt, rest)) = remaining.split_first() {
        if out.unusable {
            return;
        }
        match &stmt.kind {
            StmtKind::Let(l) => {
                if !observe_let(&mut st, l, out) {
                    return;
                }
            }
            StmtKind::Check(c) => {
                let (when_true, when_false) = cond_of(&mut st, &c.expression, out);
                // In a function, `check c else return v` is an exit where
                // `c` is false.
                if st.in_function
                    && let ExprKind::Return(value) = &c.else_expression.kind
                {
                    let mut failed = st.clone();
                    if failed.assume(when_false) {
                        record_exit(failed, value, out);
                    }
                }
                if !st.assume(when_true) {
                    return;
                }
            }
            StmtKind::If(ifs) => {
                let mut next: Vec<&[Statement]> = Vec::new();
                next.push(rest);
                next.extend_from_slice(cont);
                // Each branch knows its condition is true and every earlier
                // condition was false.
                let mut earlier_false = nothing();
                for (cond, body) in &ifs.branches {
                    let (when_true, when_false) = cond_of(&mut st, cond, out);
                    let mut branch = st.clone();
                    if branch.assume(both(when_true, earlier_false.clone())) {
                        walk(body, &next, branch, out);
                    }
                    earlier_false = both(earlier_false, when_false);
                }
                let mut fallback = st;
                if fallback.assume(earlier_false) {
                    match &ifs.fallback {
                        Some(body) => walk(body, &next, fallback, out),
                        None => walk(rest, cont, fallback, out),
                    }
                }
                return;
            }
            StmtKind::Match(m) => {
                let mut next: Vec<&[Statement]> = Vec::new();
                next.push(rest);
                next.extend_from_slice(cont);
                let scrutinee = resolve(&st, &m.expression);
                let mut earlier_false = nothing();
                for arm in &m.arms {
                    let (when_true, when_false, bound) =
                        arm_cond(&mut st, &scrutinee, &arm.pattern, out);
                    let mut branch = st.clone();
                    for var in &bound.names {
                        branch.forget_name(var);
                    }
                    if branch.assume(both(when_true, earlier_false.clone())) {
                        if let Some((var, pat)) = bound.query {
                            branch.bind_query(var, pat);
                        }
                        walk(&arm.statements, &next, branch, out);
                    }
                    earlier_false = both(earlier_false, when_false);
                }
                return;
            }
            StmtKind::Map(m) => {
                // The map query itself touches the fact.
                st.opaque.push((m.fact.identifier.clone(), m.fact.span()));
                // Knowledge about facts mutated inside the body does not
                // survive from one iteration to the next.
                let mutated = mutated_fact_names(&m.statements);
                st.facts.retain(|(p, _)| !mutated.contains(&p.name.inner));
                for name in &mutated {
                    st.mark_dirty(name);
                }
                // The body's ends are not the ends of an enclosing block.
                let collecting = core::mem::replace(&mut out.collect_ends, false);
                walk(&m.statements, &[], st.clone(), out);
                out.collect_ends = collecting;
            }
            StmtKind::Finish(fstmts) => {
                analyze_finish(fstmts, &mut st, out);
                // A finish block terminates policy execution.
                return;
            }
            StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
                let e = resolve(&st, e);
                collect_opaque(&mut st, &e, out);
            }
            StmtKind::Return(r) => {
                if st.in_function {
                    record_exit(st, &r.expression, out);
                }
                return;
            }
            StmtKind::Recall(_) => return,
            StmtKind::ActionCall(_) | StmtKind::FunctionCall(_) => {}
            // Mutations only appear inside finish contexts, which are
            // handled by `analyze_finish`.
            StmtKind::Create(_) | StmtKind::Update(_) | StmtKind::Delete(_) => {}
        }
        remaining = rest;
    }
    if let Some((first, rest)) = cont.split_first() {
        walk(first, rest, st, out);
    } else if out.collect_ends {
        out.ends.push(st);
    }
}

/// Record a pure function exit returning `value`.
fn record_exit<'a>(st: PathState<'a>, value: &Expression, out: &mut Out<'a>) {
    if out.exits.len() >= out.max_exits {
        out.unusable = true;
        return;
    }
    let ret = resolve(&st, value);
    out.exits.push(Exit {
        facts: st.facts,
        ret,
    });
}

/// The names a `match` arm binds.
#[derive(Debug, Default)]
struct ArmBinding {
    /// Every name bound by the arm's patterns.
    names: Vec<Identifier>,
    /// The name bound by a lone `Some(x)` pattern on a query, with the
    /// fact it holds.
    query: Option<(Identifier, FactPattern)>,
}

/// What a `match` arm's pattern implies about the scrutinee when it
/// matches, and when it doesn't. An arm that is exactly `Some(x)` on a
/// query also binds `x` to the fact it read, whose full key is then known
/// to exist.
fn arm_cond<'a>(
    st: &mut PathState<'a>,
    scrutinee: &Expression,
    pattern: &MatchPattern,
    out: &mut Out<'a>,
) -> (Know, Know, ArmBinding) {
    let mut bound = ArmBinding::default();
    let MatchPattern::Values(values) = pattern else {
        // The default arm: only the earlier arms' failures are known.
        return (nothing(), nothing(), bound);
    };
    let mut when_true = None;
    let mut when_false = nothing();
    for value in values {
        let (t, f) = match &value.kind {
            ExprKind::Optional(None) => cond_is(st, scrutinee, false, out),
            ExprKind::Optional(Some(inner)) => {
                let (mut t, f) = cond_is(st, scrutinee, true, out);
                if let ExprKind::Identifier(var) = &inner.kind {
                    bound.names.push(var.inner.clone());
                    // With other values in the arm, the scrutinee may not
                    // be `Some` at all, so `x` may hold nothing.
                    if values.len() == 1
                        && let Some(fact) = query_of(st, scrutinee)
                    {
                        let full = full_key_pattern(&pattern_raw(&fact, st), &var.inner, st);
                        t = both(t, fact_is(full.clone(), FactState::Exists));
                        bound.query = Some((var.inner.clone(), full));
                    }
                }
                (t, f)
            }
            ExprKind::Ok(inner) | ExprKind::Err(inner) => {
                if let ExprKind::Identifier(var) = &inner.kind {
                    bound.names.push(var.inner.clone());
                }
                (nothing(), nothing())
            }
            _ => (nothing(), nothing()),
        };
        when_true = either(when_true, t);
        when_false = both(when_false, f);
    }
    (when_true, when_false, bound)
}

/// What `expr` implies when it is true, and when it is false.
fn cond_of<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out<'a>) -> (Know, Know) {
    let expr = resolve(st, expr);
    cond_resolved(st, &expr, out)
}

/// [`cond_of`] for an expression already in the path's terms.
fn cond_resolved<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out<'a>) -> (Know, Know) {
    if let Some(known) = branch_cond(st, expr, out, &mut |st, e, out| cond_resolved(st, e, out)) {
        return known;
    }
    match &expr.kind {
        ExprKind::Bool(true) => (nothing(), None),
        ExprKind::Bool(false) => (None, nothing()),
        ExprKind::Not(inner) => {
            let (t, f) = cond_resolved(st, inner, out);
            (f, t)
        }
        ExprKind::And(a, b) => {
            let (ta, fa) = cond_resolved(st, a, out);
            let (tb, fb) = cond_resolved(st, b, out);
            (both(ta, tb), either_noted(st, expr.span, fa, fb))
        }
        ExprKind::Or(a, b) => {
            let (ta, fa) = cond_resolved(st, a, out);
            let (tb, fb) = cond_resolved(st, b, out);
            (either_noted(st, expr.span, ta, tb), both(fa, fb))
        }
        ExprKind::InternalFunction(InternalFunction::Exists(fact)) => {
            let pat = pattern_raw(fact, st);
            (
                fact_is(pat.clone(), FactState::Exists),
                fact_is(pat, FactState::NotExists),
            )
        }
        ExprKind::InternalFunction(InternalFunction::FactCount(ty, n, fact)) => {
            count_cond(st, expr, ty, n.inner, fact, out)
        }
        ExprKind::Is(inner, some) => cond_is(st, inner, *some, out),
        ExprKind::FunctionCall(fc) => through_call(st, fc, expr.span, out, &mut |st, ret, out| {
            cond_resolved(st, ret, out)
        }),
        _ => {
            collect_opaque(st, expr, out);
            (nothing(), nothing())
        }
    }
}

/// What a counting query implies. `exists` is `at_least 1`.
fn count_cond<'a>(
    st: &mut PathState<'a>,
    expr: &Expression,
    ty: &FactCountType,
    n: i64,
    fact: &FactLiteral,
    out: &mut Out<'a>,
) -> (Know, Know) {
    let pat = pattern_raw(fact, st);
    let exists = fact_is(pat.clone(), FactState::Exists);
    let absent = fact_is(pat, FactState::NotExists);
    match ty {
        FactCountType::AtLeast(_) => match n {
            ..=0 => (nothing(), None),
            1 => (exists, absent),
            _ => (exists, nothing()),
        },
        FactCountType::AtMost(_) => match n {
            ..=-1 => (None, nothing()),
            0 => (absent, exists),
            _ => (nothing(), exists),
        },
        FactCountType::Exactly(_) => match n {
            ..=-1 => (None, nothing()),
            0 => (absent, exists),
            _ => (exists, nothing()),
        },
        // `count_up_to` is a number, not a condition.
        FactCountType::UpTo(_) => {
            collect_opaque(st, expr, out);
            (nothing(), nothing())
        }
    }
}

/// What `expr is Some` (or `is None`, when `some` is false) implies.
fn cond_is<'a>(
    st: &mut PathState<'a>,
    expr: &Expression,
    some: bool,
    out: &mut Out<'a>,
) -> (Know, Know) {
    if let Some((when_some, when_none)) =
        branch_cond(st, expr, out, &mut |st, e, out| cond_is(st, e, true, out))
    {
        return if some {
            (when_some, when_none)
        } else {
            (when_none, when_some)
        };
    }
    let (when_some, when_none) = match &expr.kind {
        ExprKind::InternalFunction(InternalFunction::Query(fact)) => {
            let pat = pattern_raw(fact, st);
            (
                fact_is(pat.clone(), FactState::Exists),
                fact_is(pat, FactState::NotExists),
            )
        }
        ExprKind::Optional(None) => (None, nothing()),
        ExprKind::Optional(Some(_)) => (nothing(), None),
        ExprKind::FunctionCall(fc) => through_call(st, fc, expr.span, out, &mut |st, ret, out| {
            cond_is(st, ret, true, out)
        }),
        _ => {
            collect_opaque(st, expr, out);
            (nothing(), nothing())
        }
    };
    if some {
        (when_some, when_none)
    } else {
        (when_none, when_some)
    }
}

/// Evaluate a call to a pure function through its summary. `eval` gives
/// what one exit's return value implies; the result holds what every
/// possible exit implies.
fn through_call<'a>(
    st: &mut PathState<'a>,
    fc: &FunctionCall,
    span: Span,
    out: &mut Out<'a>,
    eval: &mut Eval<'_, 'a>,
) -> (Know, Know) {
    let name = &fc.identifier.inner;
    let summary = if st.evaluating.contains(name) {
        None
    } else {
        st.az.summary(name)
    };
    let Some(summary) = summary.filter(|s| s.params.len() == fc.arguments.len()) else {
        record_call_opaque(st, name, span);
        return (nothing(), nothing());
    };
    // The arguments are already in the caller's terms.
    let map: BTreeMap<Identifier, Expression> = summary
        .params
        .iter()
        .cloned()
        .zip(fc.arguments.iter().cloned())
        .collect();
    st.evaluating.push(name.clone());
    let mut when_true = None;
    let mut when_false = None;
    for exit in &summary.exits {
        // Anything that mentions one of the function's local variables
        // can't be expressed in the caller's terms, so it is dropped.
        let facts: Facts = exit
            .facts
            .iter()
            .filter_map(|(p, s)| Some((subst_pattern(p, &map, &st.az.globals)?, *s)))
            .collect();
        let (t, f) = match subst(&exit.ret, &map, Some(&st.az.globals)) {
            Some(ret) => eval(st, &ret, out),
            None => (nothing(), nothing()),
        };
        when_true = either_noted(st, span, when_true, both(Some(facts.clone()), t));
        when_false = either_noted(st, span, when_false, both(Some(facts), f));
    }
    st.evaluating.pop();
    (when_true, when_false)
}

/// Gives what one arm's or exit's value implies when true and when false.
type Eval<'e, 'a> = dyn FnMut(&mut PathState<'a>, &Expression, &mut Out<'a>) -> (Know, Know) + 'e;

/// What an `if`, `match`, or block expression implies, or `None` if
/// `expr` is another form. `eval` gives what one arm's value implies;
/// the result holds what every arm that can produce a value implies.
fn branch_cond<'a>(
    st: &mut PathState<'a>,
    expr: &Expression,
    out: &mut Out<'a>,
    eval: &mut Eval<'_, 'a>,
) -> Option<(Know, Know)> {
    debug_assert!(
        !st.strict,
        "conditions are not evaluated in finish contexts"
    );
    let mut when_true = None;
    let mut when_false = None;
    match &expr.kind {
        ExprKind::InternalFunction(InternalFunction::If(c, t, e)) => {
            let (ct, cf) = cond_resolved(st, c, out);
            let none = ArmBinding::default();
            for (know, arm) in [(ct, t), (cf, e)] {
                let (t, f) = under(st, know, &none, arm, out, eval);
                when_true = either_noted(st, expr.span, when_true, t);
                when_false = either_noted(st, expr.span, when_false, f);
            }
        }
        ExprKind::Match(m) => {
            let mut earlier_false = nothing();
            for arm in &m.arms {
                let (at, af, bound) = arm_cond(st, &m.scrutinee, &arm.pattern, out);
                let know = both(at, earlier_false.clone());
                let (t, f) = under(st, know, &bound, &arm.expression, out, eval);
                when_true = either_noted(st, expr.span, when_true, t);
                when_false = either_noted(st, expr.span, when_false, f);
                earlier_false = both(earlier_false, af);
            }
        }
        ExprKind::Block(stmts, e) => {
            let base = st.opaque.len();
            let Some(ends) = block_ends(st, stmts, out) else {
                collect_opaque(st, expr, out);
                return Some((nothing(), nothing()));
            };
            let bound = bound_names(stmts);
            for end in ends {
                let (t, f) = contribution(st, end, base, &bound, e, out, eval);
                when_true = either_noted(st, expr.span, when_true, t);
                when_false = either_noted(st, expr.span, when_false, f);
            }
        }
        _ => return None,
    }
    Some((when_true, when_false))
}

/// What arm expression `e` implies on a copy of the path that knows
/// `know`, with the arm's `bound` names freshly bound.
fn under<'a>(
    st: &mut PathState<'a>,
    know: Know,
    bound: &ArmBinding,
    e: &Expression,
    out: &mut Out<'a>,
    eval: &mut Eval<'_, 'a>,
) -> (Know, Know) {
    let base = st.opaque.len();
    let mut end = st.clone();
    for var in &bound.names {
        end.forget_name(var);
    }
    if !end.assume(know) {
        return (None, None);
    }
    if let Some((var, pat)) = &bound.query {
        end.bind_query(var.clone(), pat.clone());
    }
    contribution(st, end, base, &bound.names, e, out, eval)
}

/// What one way through an `if`, `match`, or block expression implies,
/// in the enclosing path's terms. `end` is the path's state at the arm's
/// expression `e`, and `bound` are the names local to the arm, which
/// nothing outside it can refer to. `base` is how many opaque points
/// the enclosing path had when `end` was split off.
///
/// An arm whose expression can't produce a value implies nothing. In a
/// pure function, `return v` there is an exit.
fn contribution<'a>(
    st: &mut PathState<'a>,
    mut end: PathState<'a>,
    base: usize,
    bound: &[Identifier],
    e: &Expression,
    out: &mut Out<'a>,
    eval: &mut Eval<'_, 'a>,
) -> (Know, Know) {
    let e = resolve(&end, e);
    let mut result = (None, None);
    if matches!(e.vtype.inner, TypeKind::Never) {
        if end.in_function
            && let ExprKind::Return(value) = &e.kind
        {
            record_exit(end.clone(), value, out);
        }
    } else {
        // The arm may itself be an `if`, `match`, or block.
        let (t, f) =
            branch_cond(&mut end, &e, out, eval).unwrap_or_else(|| eval(&mut end, &e, out));
        let facts: Facts = end
            .facts
            .iter()
            .filter(|(p, _)| !bound.iter().any(|v| mentions_pattern(p, v)))
            .cloned()
            .collect();
        result = (both(Some(facts.clone()), t), both(Some(facts), f));
    }
    // What the arm touched, and what it may have changed, carries over.
    if let Some(new) = end.opaque.get(base..) {
        st.opaque.extend_from_slice(new);
    }
    for name in &end.dirty {
        if !st.dirty.contains(name) {
            st.facts.retain(|(p, _)| p.name.inner != *name);
            st.mark_dirty(name);
        }
    }
    st.empty_db &= end.empty_db;
    result
}

/// The states of every path through a block expression's statements
/// that reaches its final expression, or `None` if there are more than
/// the exit cap.
fn block_ends<'a>(
    st: &PathState<'a>,
    stmts: &[Statement],
    out: &mut Out<'a>,
) -> Option<Vec<PathState<'a>>> {
    let saved = core::mem::take(&mut out.ends);
    let collecting = core::mem::replace(&mut out.collect_ends, true);
    walk(stmts, &[], st.clone(), out);
    let ends = core::mem::replace(&mut out.ends, saved);
    out.collect_ends = collecting;
    (ends.len() <= st.az.max_exit_paths).then_some(ends)
}

/// The names bound anywhere in these statements.
fn bound_names(stmts: &[Statement]) -> Vec<Identifier> {
    let mut names = Vec::new();
    collect_bound(stmts, &mut names);
    names
}

fn collect_bound(stmts: &[Statement], names: &mut Vec<Identifier>) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Let(l) => names.push(l.identifier.inner.clone()),
            StmtKind::If(ifs) => {
                for (_, body) in &ifs.branches {
                    collect_bound(body, names);
                }
                if let Some(body) = &ifs.fallback {
                    collect_bound(body, names);
                }
            }
            StmtKind::Match(m) => {
                for arm in &m.arms {
                    names.extend(arm_names(&arm.pattern));
                    collect_bound(&arm.statements, names);
                }
            }
            StmtKind::Map(m) => {
                names.push(m.identifier.inner.clone());
                collect_bound(&m.statements, names);
            }
            StmtKind::Finish(body) => collect_bound(body, names),
            _ => {}
        }
    }
}

/// The names a `match` pattern binds.
fn arm_names(pattern: &MatchPattern) -> Vec<Identifier> {
    let MatchPattern::Values(values) = pattern else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|value| match &value.kind {
            ExprKind::Optional(Some(inner)) | ExprKind::Ok(inner) | ExprKind::Err(inner) => {
                match &inner.kind {
                    ExprKind::Identifier(var) => Some(var.inner.clone()),
                    _ => None,
                }
            }
            _ => None,
        })
        .collect()
}

/// Record a call that couldn't be followed as touching every fact its
/// function's body mentions, so warnings about those facts point at it.
fn record_call_opaque(st: &mut PathState<'_>, name: &Identifier, span: Span) {
    let Some(body) = st.az.pure_functions.get(name) else {
        return;
    };
    let mut names: Vec<Ident> = Vec::new();
    stmt_exprs(&body.statements, &mut |e| {
        visit_facts(e, &mut |fact, _| names.push(fact.identifier.clone()));
    });
    for fact in names {
        st.opaque.push((fact, span));
    }
}

/// Call `f` on every expression directly in these statements, recursing
/// into nested statement blocks.
fn stmt_exprs(stmts: &[Statement], f: &mut impl FnMut(&Expression)) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Let(l) => f(&l.expression),
            StmtKind::Check(c) => {
                f(&c.expression);
                f(&c.else_expression);
            }
            StmtKind::If(ifs) => {
                for (cond, body) in &ifs.branches {
                    f(cond);
                    stmt_exprs(body, f);
                }
                if let Some(body) = &ifs.fallback {
                    stmt_exprs(body, f);
                }
            }
            StmtKind::Match(m) => {
                f(&m.expression);
                for arm in &m.arms {
                    stmt_exprs(&arm.statements, f);
                }
            }
            StmtKind::Map(m) => stmt_exprs(&m.statements, f),
            StmtKind::Return(r) => f(&r.expression),
            StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => f(e),
            _ => {}
        }
    }
}

/// Check obligations for the mutations in a finish block.
fn analyze_finish<'a>(stmts: &[Statement], st: &mut PathState<'a>, out: &mut Out<'a>) {
    let mut touched: Vec<FactPattern> = Vec::new();
    let mut calls: Vec<(Identifier, Span)> = Vec::new();
    finish_statements(stmts, st, &mut touched, &mut calls, out);
}

/// Check the mutations in a finish block or in a finish function called
/// from one. `touched` is shared by the whole finish block, including the
/// functions it calls. `calls` is the stack of finish function calls that
/// led here, innermost last.
fn finish_statements<'a>(
    stmts: &[Statement],
    st: &mut PathState<'a>,
    touched: &mut Vec<FactPattern>,
    calls: &mut Vec<(Identifier, Span)>,
    out: &mut Out<'a>,
) {
    for stmt in stmts {
        let mut found = Vec::new();
        match &stmt.kind {
            StmtKind::Create(c) => {
                let pat = pattern_of(&c.fact, st);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if !proven_absent(st, &pat) {
                    found.push(unproven_create(stmt.span, &pat, &st.opaque));
                }
                set_state(st, pat.clone(), FactState::Exists);
                touched.push(pat);
            }
            StmtKind::Update(u) => {
                let pat = pattern_of(&u.fact, st);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if !proven_exists(st, &pat) {
                    found.push(unproven_exists(stmt.span, &pat, Mutation::Update, st));
                } else if !values_proven(st, &u.fact, &pat) {
                    found.push(unproven_values(stmt.span, &pat, st));
                }
                set_state(st, pat.clone(), FactState::Exists);
                touched.push(pat);
            }
            StmtKind::Delete(d) => {
                let pat = pattern_of(&d.fact, st);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if !proven_exists(st, &pat) {
                    found.push(unproven_exists(stmt.span, &pat, Mutation::Delete, st));
                }
                set_state(st, pat.clone(), FactState::NotExists);
                touched.push(pat);
            }
            StmtKind::FunctionCall(fc) => {
                let name = &fc.identifier.inner;
                let recursive = calls.iter().any(|(n, _)| n == name);
                let az = st.az;
                match az.finish_functions.get(name) {
                    Some(body) if !recursive && body.params.len() == fc.arguments.len() => {
                        // Bind the parameters to the caller's arguments,
                        // so the function's fact keys are expressed in the
                        // caller's terms.
                        let env = body
                            .params
                            .iter()
                            .zip(&fc.arguments)
                            .map(|(p, a)| (p.clone(), resolve(st, a)))
                            .collect();
                        let caller_env = core::mem::replace(&mut st.env, env);
                        let caller_strict = core::mem::replace(&mut st.strict, true);
                        calls.push((name.clone(), stmt.span));
                        finish_statements(&body.statements, st, touched, calls, out);
                        calls.pop();
                        st.env = caller_env;
                        st.strict = caller_strict;
                    }
                    // Not a known finish function, or a recursive call:
                    // it may mutate any fact.
                    _ => {
                        if recursive {
                            found.push(recursive_call(stmt.span, name));
                        }
                        st.forget_all();
                    }
                }
            }
            _ => {}
        }
        for mut w in found {
            // Point from a warning inside a finish function back to the
            // calls that reached it, innermost first.
            for (name, span) in calls.iter().rev() {
                w.notes.push((*span, format!("in this call to `{name}`")));
            }
            out.warnings.push(w);
        }
    }
}

/// Is `pat` known not to exist on this path?
fn proven_absent(st: &PathState<'_>, pat: &FactPattern) -> bool {
    st.known_absent(&pat.name.inner)
        || st
            .facts
            .iter()
            .any(|(p, s)| *s == FactState::NotExists && covers(p, pat))
}

/// Is `pat` known to exist on this path?
///
/// Unlike [`proven_absent`], a bind marker does not help: `F[a: x, b: ?]`
/// existing says nothing about any particular `b`. So the observation must
/// name exactly the same key.
fn proven_exists(st: &PathState<'_>, pat: &FactPattern) -> bool {
    st.facts
        .iter()
        .any(|(p, s)| *s == FactState::Exists && same_pattern(p, pat))
}

/// Does every value field an `update` states come from a query of the
/// same fact? The VM requires the stated values to match the stored fact.
///
/// The accepted form is `x.field` for the same `field`, where `x` holds a
/// fact read by a query with the same key, and `F` has not been mutated
/// since.
fn values_proven(st: &PathState<'_>, fact: &FactLiteral, pat: &FactPattern) -> bool {
    let Some(values) = &fact.value_fields else {
        return true;
    };
    values.iter().all(|(field, expr)| {
        let expr = resolve(st, expr);
        let ExprKind::Dot(base, read) = &expr.kind else {
            return false;
        };
        let ExprKind::Identifier(var) = &base.kind else {
            return false;
        };
        read.inner == field.inner
            && st
                .query_bindings
                .iter()
                .any(|(v, p)| *v == var.inner && same_pattern(p, pat))
    })
}

/// A mutation that requires its fact to exist.
#[derive(Debug, Clone, Copy)]
enum Mutation {
    Update,
    Delete,
}

impl Mutation {
    fn keyword(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    fn gerund(self) -> &'static str {
        match self {
            Self::Update => "updating",
            Self::Delete => "deleting",
        }
    }
}

/// Notes for the opaque expressions that touched the same fact.
fn opaque_notes(pat: &FactPattern, opaque: &[(Ident, Span)]) -> Vec<(Span, String)> {
    opaque
        .iter()
        .filter(|(name, _)| *name == pat.name)
        .map(|(name, span)| {
            (
                *span,
                format!("touches `{name}` but is too complex to analyze"),
            )
        })
        .collect()
}

fn unproven_create(span: Span, pat: &FactPattern, opaque: &[(Ident, Span)]) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!("cannot prove `{}` does not exist before `create`", pat.text),
        label: "this fact may already exist".to_owned(),
        notes: opaque_notes(pat, opaque),
        footnotes: vec![
            (
                Footnote::Note,
                "creating a fact that already exists is a runtime exception".to_owned(),
            ),
            (
                Footnote::Help,
                format!(
                    "check that it does not exist first: `check !exists {} else ...`",
                    pat.text
                ),
            ),
        ],
    }
}

fn unproven_exists(
    span: Span,
    pat: &FactPattern,
    kind: Mutation,
    st: &PathState<'_>,
) -> ObligationWarning {
    let mut footnotes = vec![(
        Footnote::Note,
        format!(
            "{} a fact that does not exist is a runtime exception",
            kind.gerund()
        ),
    )];
    if st.known_absent(&pat.name.inner) {
        footnotes.push((
            Footnote::Note,
            "no facts exist when an `init` command runs, so this always fails".to_owned(),
        ));
    } else {
        footnotes.push((
            Footnote::Help,
            format!(
                "check that it exists first: `check exists {} else ...`",
                pat.text
            ),
        ));
    }
    ObligationWarning {
        span,
        message: format!(
            "cannot prove `{}` exists before `{}`",
            pat.text,
            kind.keyword()
        ),
        label: "this fact may not exist".to_owned(),
        notes: opaque_notes(pat, &st.opaque),
        footnotes,
    }
}

fn unproven_values(span: Span, pat: &FactPattern, st: &PathState<'_>) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!(
            "cannot prove the stated values of `{}` match the stored fact before `update`",
            pat.text
        ),
        label: "the stored values may differ".to_owned(),
        notes: opaque_notes(pat, &st.opaque),
        footnotes: vec![
            (
                Footnote::Note,
                "updating from values that don't match the stored fact is a runtime exception"
                    .to_owned(),
            ),
            (
                Footnote::Help,
                format!(
                    "read the values from a query of the same fact: \
                     `let x = query {} or ...`, then `=>{{field: x.field}}`",
                    pat.text
                ),
            ),
        ],
    }
}

fn recursive_call(span: Span, name: &Identifier) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!("cannot check fact mutations through recursive call to `{name}`"),
        label: "recursive call".to_owned(),
        notes: Vec::new(),
        footnotes: vec![(
            Footnote::Note,
            "the analysis stops following calls here, so mutations reached \
             through this call are not checked"
                .to_owned(),
        )],
    }
}

fn double_manipulation(span: Span, pat: &FactPattern, prev: &FactPattern) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!(
            "`{}` is manipulated more than once in this finish block",
            pat.text
        ),
        label: "manipulated again here".to_owned(),
        notes: vec![(prev.span, "first manipulated here".to_owned())],
        footnotes: vec![(
            Footnote::Note,
            "manipulating the same fact twice in one finish block is a runtime exception"
                .to_owned(),
        )],
    }
}

/// Apply a `let`. Returns false if the path ends here.
///
/// `let x = e or <terminal>` continues only when `e` is `Some`. When `e`
/// is a query, `x` holds the fact it read, so that fact's full key is
/// known to exist. `let x = match ..` with arms that can't produce a
/// value continues only through the arms that can. Other substitutable
/// values are remembered so later uses of `x` are compared by what it
/// holds.
fn observe_let<'a>(st: &mut PathState<'a>, stmt: &LetStatement, out: &mut Out<'a>) -> bool {
    let var = stmt.identifier.inner.clone();
    if let ExprKind::Coalesce(lhs, rhs) = &stmt.expression.kind
        && matches!(rhs.vtype.inner, TypeKind::Never)
    {
        let lhs = resolve(st, lhs);
        let (mut when_some, when_none) = cond_is(st, &lhs, true, out);
        // In a function, `e or return v` is an exit where `e` is `None`.
        if st.in_function
            && let ExprKind::Return(value) = &rhs.kind
        {
            let mut failed = st.clone();
            if failed.assume(when_none) {
                record_exit(failed, value, out);
            }
        }
        // The compiler forbids shadowing, so `lhs` can't mention `var`.
        st.forget_name(&var);
        if let Some(fact) = query_of(st, &lhs) {
            let full = full_key_pattern(&pattern_raw(&fact, st), &var, st);
            when_some = both(when_some, fact_is(full.clone(), FactState::Exists));
            st.bind_query(var, full);
        }
        return st.assume(when_some);
    }
    st.forget_name(&var);
    let value = resolve(st, &stmt.expression);
    if is_substitutable(&stmt.expression) {
        st.env.insert(var, value);
        return true;
    }
    // The value of an `if`, `match`, or block is unknown, but the path
    // knows what holds when some arm produced it.
    if let Some((produced, _)) = branch_cond(st, &value, out, &mut |st, e, out| {
        collect_opaque(st, e, out);
        (nothing(), nothing())
    }) {
        let mut know = produced;
        if let Some(fact) = match_returns_query(st, &value) {
            let full = full_key_pattern(&pattern_raw(&fact, st), &var, st);
            know = both(know, fact_is(full.clone(), FactState::Exists));
            st.bind_query(var, full);
        }
        return st.assume(know);
    }
    collect_opaque(st, &value, out);
    true
}

/// The query a `match` on a query returns, if every arm that produces a
/// value is exactly `Some(x) => x`: the `let` it is bound to holds the
/// fact the query read.
fn match_returns_query(st: &mut PathState<'_>, expr: &Expression) -> Option<FactLiteral> {
    let ExprKind::Match(m) = &expr.kind else {
        return None;
    };
    let fact = query_of(st, &m.scrutinee)?;
    let passes_through = m.arms.iter().all(|arm| {
        if matches!(arm.expression.vtype.inner, TypeKind::Never) {
            return true;
        }
        let MatchPattern::Values(values) = &arm.pattern else {
            return false;
        };
        let [value] = values.as_slice() else {
            return false;
        };
        let ExprKind::Optional(Some(inner)) = &value.kind else {
            return false;
        };
        match (&inner.kind, &arm.expression.kind) {
            (ExprKind::Identifier(x), ExprKind::Identifier(y)) => x.inner == y.inner,
            _ => false,
        }
    });
    passes_through.then_some(fact)
}

/// The pattern for a fact literal as written, in the path's terms.
fn pattern_of(fact: &FactLiteral, st: &PathState<'_>) -> FactPattern {
    FactPattern {
        name: fact.identifier.clone(),
        keys: fact
            .key_fields
            .iter()
            .map(|(name, expr)| (name.inner.clone(), resolve(st, expr)))
            .collect(),
        span: fact.span(),
        text: fact_text(fact, &st.az.src),
    }
}

/// The pattern for a fact literal already in the path's terms.
fn pattern_raw(fact: &FactLiteral, st: &PathState<'_>) -> FactPattern {
    FactPattern {
        name: fact.identifier.clone(),
        keys: fact
            .key_fields
            .iter()
            .map(|(name, expr)| (name.inner.clone(), expr.clone()))
            .collect(),
        span: fact.span(),
        text: fact_text(fact, &st.az.src),
    }
}

/// The pattern of the one fact `var` holds after it is bound to the
/// result of a query with `prefix`'s keys: those keys, followed by
/// `var.<key>` for each remaining key field of the schema.
fn full_key_pattern(prefix: &FactPattern, var: &Identifier, st: &PathState<'_>) -> FactPattern {
    let mut keys = prefix.keys.clone();
    if let Some(schema) = st.az.fact_keys.get(&prefix.name.inner) {
        for (key, ty) in schema.iter().skip(keys.len()) {
            let base = Expression {
                kind: ExprKind::Identifier(Ident::new(var.clone(), prefix.span)),
                vtype: VType::new(TypeKind::Struct(prefix.name.clone()), prefix.span),
                span: prefix.span,
            };
            let read = Expression {
                kind: ExprKind::Dot(Box::new(base), Ident::new(key.clone(), prefix.span)),
                vtype: ty.clone(),
                span: prefix.span,
            };
            keys.push((key.clone(), read));
        }
    }
    FactPattern {
        keys,
        ..prefix.clone()
    }
}

/// The query `expr` evaluates to, if it is one: a `query` itself, or a
/// call to a pure function that returns one.
fn query_of(st: &mut PathState<'_>, expr: &Expression) -> Option<FactLiteral> {
    match &expr.kind {
        ExprKind::InternalFunction(InternalFunction::Query(fact)) => Some(fact.clone()),
        ExprKind::FunctionCall(fc) => call_returns_query(st, fc),
        _ => None,
    }
}

/// The query a pure function returns, in the caller's terms, when every
/// exit that can return `Some` returns a query of the same fact with the
/// same keys. Exits returning the literal `None` are ignored.
fn call_returns_query(st: &mut PathState<'_>, fc: &FunctionCall) -> Option<FactLiteral> {
    let name = &fc.identifier.inner;
    if st.evaluating.contains(name) {
        return None;
    }
    let summary = st
        .az
        .summary(name)
        .filter(|s| s.params.len() == fc.arguments.len())?;
    let map: BTreeMap<Identifier, Expression> = summary
        .params
        .iter()
        .cloned()
        .zip(fc.arguments.iter().cloned())
        .collect();
    st.evaluating.push(name.clone());
    let mut found: Option<FactLiteral> = None;
    let mut agree = true;
    for exit in &summary.exits {
        if matches!(exit.ret.kind, ExprKind::Optional(None)) {
            continue;
        }
        let fact = subst(&exit.ret, &map, Some(&st.az.globals)).and_then(|ret| query_of(st, &ret));
        match (fact, &found) {
            (Some(fact), None) => found = Some(fact),
            (Some(fact), Some(prev))
                if same_pattern(&pattern_raw(&fact, st), &pattern_raw(prev, st)) => {}
            _ => {
                agree = false;
                break;
            }
        }
    }
    st.evaluating.pop();
    agree.then_some(found).flatten()
}

/// Does `expr` name `v`?
fn mentions(expr: &Expression, v: &Identifier) -> bool {
    any_sub(expr, &mut |e| match &e.kind {
        ExprKind::Identifier(id) => id.inner == *v,
        ExprKind::NamedStruct(s) => s.sources.iter().any(|src| src.inner == *v),
        _ => false,
    })
}

/// Does `pred` hold for `expr` or any expression inside it?
fn any_sub(expr: &Expression, pred: &mut impl FnMut(&Expression) -> bool) -> bool {
    if pred(expr) {
        return true;
    }
    match &expr.kind {
        ExprKind::Identifier(_)
        | ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::EnumReference(_) => false,
        ExprKind::Optional(inner) => inner.as_ref().is_some_and(|e| any_sub(e, pred)),
        ExprKind::NamedStruct(s) => s.fields.iter().any(|(_, e)| any_sub(e, pred)),
        ExprKind::InternalFunction(func) => match func {
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact) => any_sub_fact(fact, pred),
            InternalFunction::If(c, t, e) => {
                any_sub(c, pred) || any_sub(t, pred) || any_sub(e, pred)
            }
            InternalFunction::Todo(_) | InternalFunction::TestFail(..) => false,
        },
        ExprKind::FunctionCall(c) => c.arguments.iter().any(|e| any_sub(e, pred)),
        ExprKind::ForeignFunctionCall(c) => c.arguments.iter().any(|e| any_sub(e, pred)),
        ExprKind::Recall(c) => c.arguments.iter().any(|e| any_sub(e, pred)),
        ExprKind::Return(e)
        | ExprKind::Not(e)
        | ExprKind::Is(e, _)
        | ExprKind::Dot(e, _)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e) => any_sub(e, pred),
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Coalesce(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => any_sub(a, pred) || any_sub(b, pred),
        ExprKind::Block(stmts, e) => {
            let mut found = any_sub(e, pred);
            stmt_exprs(stmts, &mut |e| found = found || any_sub(e, pred));
            found
        }
        ExprKind::Match(m) => {
            any_sub(&m.scrutinee, pred) || m.arms.iter().any(|arm| any_sub(&arm.expression, pred))
        }
    }
}

/// [`any_sub`] over the key and value fields of `fact`.
fn any_sub_fact(fact: &FactLiteral, pred: &mut impl FnMut(&Expression) -> bool) -> bool {
    fact.key_fields.iter().any(|(_, e)| any_sub(e, pred))
        || fact
            .value_fields
            .as_ref()
            .is_some_and(|values| values.iter().any(|(_, e)| any_sub(e, pred)))
}

/// Does any key of `pat` name `v`?
fn mentions_pattern(pat: &FactPattern, v: &Identifier) -> bool {
    pat.keys.iter().any(|(_, e)| mentions(e, v))
}

/// Express a pattern from a function's terms in the caller's, or `None`
/// if it mentions something other than a parameter or a global.
fn subst_pattern(
    pat: &FactPattern,
    map: &BTreeMap<Identifier, Expression>,
    globals: &[Identifier],
) -> Option<FactPattern> {
    let keys = pat
        .keys
        .iter()
        .map(|(name, expr)| Some((name.clone(), subst(expr, map, Some(globals))?)))
        .collect::<Option<Vec<_>>>()?;
    Some(FactPattern {
        keys,
        ..pat.clone()
    })
}

/// Express `expr` in the path's terms by substituting `let`-bound names.
///
/// Inside a finish function (`strict`), a name that is not a parameter or
/// a global can't be expressed in the caller's terms. The result is then
/// wrapped so it never compares equal to anything.
fn resolve(st: &PathState<'_>, expr: &Expression) -> Expression {
    let globals = st.strict.then_some(st.az.globals.as_slice());
    subst(expr, &st.env, globals).unwrap_or_else(|| Expression {
        kind: ExprKind::Block(Vec::new(), Box::new(expr.clone())),
        vtype: expr.vtype.clone(),
        span: expr.span,
    })
}

/// Substitute the names in `env` throughout `expr`.
///
/// With `strict`, every other name must be one of the given globals, or
/// be bound by an enclosing block or `match` arm; struct composition is
/// rejected. Returns `None` if that fails. Without `strict`, other names
/// are kept as they are.
fn subst(
    expr: &Expression,
    env: &BTreeMap<Identifier, Expression>,
    strict: Option<&[Identifier]>,
) -> Option<Expression> {
    let mut expr = expr.clone();
    rewrite(&mut expr, env, strict).then_some(expr)
}

fn rewrite(
    expr: &mut Expression,
    env: &BTreeMap<Identifier, Expression>,
    strict: Option<&[Identifier]>,
) -> bool {
    if let ExprKind::Identifier(id) = &expr.kind {
        if let Some(value) = env.get(&id.inner) {
            *expr = value.clone();
            return true;
        }
        return strict.is_none_or(|globals| globals.contains(&id.inner));
    }
    match &mut expr.kind {
        ExprKind::Identifier(_)
        | ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::EnumReference(_) => true,
        ExprKind::Optional(inner) => inner.as_mut().is_none_or(|e| rewrite(e, env, strict)),
        ExprKind::NamedStruct(s) => {
            (strict.is_none() || s.sources.is_empty())
                && s.fields.iter_mut().all(|(_, e)| rewrite(e, env, strict))
        }
        ExprKind::InternalFunction(func) => match func {
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact) => rewrite_fact(fact, env, strict),
            InternalFunction::If(c, t, e) => {
                rewrite(c, env, strict) && rewrite(t, env, strict) && rewrite(e, env, strict)
            }
            InternalFunction::Todo(_) | InternalFunction::TestFail(..) => true,
        },
        ExprKind::FunctionCall(c) => c.arguments.iter_mut().all(|e| rewrite(e, env, strict)),
        ExprKind::ForeignFunctionCall(c) => c.arguments.iter_mut().all(|e| rewrite(e, env, strict)),
        ExprKind::Recall(c) => c.arguments.iter_mut().all(|e| rewrite(e, env, strict)),
        ExprKind::Return(e)
        | ExprKind::Not(e)
        | ExprKind::Is(e, _)
        | ExprKind::Dot(e, _)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e) => rewrite(e, env, strict),
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Coalesce(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => rewrite(a, env, strict) && rewrite(b, env, strict),
        ExprKind::Block(stmts, e) => {
            let names = bound_names(stmts);
            let env = scoped_env(env, &names);
            let allowed = strict.map(|g| [g, names.as_slice()].concat());
            rewrite_stmts(stmts, &env, allowed.as_deref()) && rewrite(e, &env, allowed.as_deref())
        }
        ExprKind::Match(m) => {
            rewrite(&mut m.scrutinee, env, strict)
                && m.arms.iter_mut().all(|arm| {
                    let names = arm_names(&arm.pattern);
                    let env = scoped_env(env, &names);
                    let allowed = strict.map(|g| [g, names.as_slice()].concat());
                    rewrite(&mut arm.expression, &env, allowed.as_deref())
                })
        }
    }
}

/// `env` without the names a nested scope binds, which refer to that
/// scope's own bindings.
fn scoped_env<'e>(
    env: &'e BTreeMap<Identifier, Expression>,
    names: &[Identifier],
) -> Cow<'e, BTreeMap<Identifier, Expression>> {
    if names.iter().any(|n| env.contains_key(n)) {
        let mut env = env.clone();
        for n in names {
            env.remove(n);
        }
        Cow::Owned(env)
    } else {
        Cow::Borrowed(env)
    }
}

/// [`rewrite`] for the expressions in the statements of a block
/// expression.
fn rewrite_stmts(
    stmts: &mut [Statement],
    env: &BTreeMap<Identifier, Expression>,
    strict: Option<&[Identifier]>,
) -> bool {
    stmts.iter_mut().all(|stmt| match &mut stmt.kind {
        StmtKind::Let(l) => rewrite(&mut l.expression, env, strict),
        StmtKind::Check(c) => {
            rewrite(&mut c.expression, env, strict) && rewrite(&mut c.else_expression, env, strict)
        }
        StmtKind::If(ifs) => {
            ifs.branches
                .iter_mut()
                .all(|(c, body)| rewrite(c, env, strict) && rewrite_stmts(body, env, strict))
                && ifs
                    .fallback
                    .as_mut()
                    .is_none_or(|body| rewrite_stmts(body, env, strict))
        }
        StmtKind::Match(m) => {
            rewrite(&mut m.expression, env, strict)
                && m.arms
                    .iter_mut()
                    .all(|arm| rewrite_stmts(&mut arm.statements, env, strict))
        }
        StmtKind::Map(m) => {
            rewrite_fact(&mut m.fact, env, strict) && rewrite_stmts(&mut m.statements, env, strict)
        }
        StmtKind::Finish(body) => rewrite_stmts(body, env, strict),
        StmtKind::Return(r) => rewrite(&mut r.expression, env, strict),
        StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
            rewrite(e, env, strict)
        }
        StmtKind::ActionCall(c) | StmtKind::FunctionCall(c) => {
            c.arguments.iter_mut().all(|e| rewrite(e, env, strict))
        }
        StmtKind::Create(c) => rewrite_fact(&mut c.fact, env, strict),
        StmtKind::Update(u) => {
            rewrite_fact(&mut u.fact, env, strict)
                && u.to.iter_mut().all(|(_, e)| rewrite(e, env, strict))
        }
        StmtKind::Delete(d) => rewrite_fact(&mut d.fact, env, strict),
        StmtKind::Recall(r) => r.arguments.iter_mut().all(|e| rewrite(e, env, strict)),
    })
}

fn rewrite_fact(
    fact: &mut FactLiteral,
    env: &BTreeMap<Identifier, Expression>,
    strict: Option<&[Identifier]>,
) -> bool {
    fact.key_fields
        .iter_mut()
        .all(|(_, e)| rewrite(e, env, strict))
        && fact
            .value_fields
            .as_mut()
            .is_none_or(|values| values.iter_mut().all(|(_, e)| rewrite(e, env, strict)))
}

/// Can a `let` value be substituted for its name? Pure functions and fact
/// reads qualify: the fact database cannot change during a policy block,
/// so the same expression gives the same value wherever it appears.
fn is_substitutable(expr: &Expression) -> bool {
    match &expr.kind {
        ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::Identifier(_)
        | ExprKind::EnumReference(_) => true,
        ExprKind::Dot(e, _) | ExprKind::Not(e) | ExprKind::Is(e, _) => is_substitutable(e),
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => is_substitutable(a) && is_substitutable(b),
        ExprKind::Optional(inner) => inner.as_deref().is_none_or(is_substitutable),
        ExprKind::InternalFunction(
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact),
        ) => {
            fact.key_fields.iter().all(|(_, e)| is_substitutable(e))
                && fact
                    .value_fields
                    .as_ref()
                    .is_none_or(|values| values.iter().all(|(_, e)| is_substitutable(e)))
        }
        ExprKind::FunctionCall(c) => c.arguments.iter().all(is_substitutable),
        _ => false,
    }
}

/// Record an observation, replacing prior knowledge of the same pattern.
fn observe(st: &mut PathState<'_>, pat: FactPattern, state: FactState) {
    st.facts.retain(|(p, _)| !same_pattern(p, &pat));
    st.facts.push((pat, state));
}

/// Record a mutation's postcondition. A mutation invalidates all other
/// knowledge about the same fact name, since other patterns may alias
/// the mutated key.
fn set_state(st: &mut PathState<'_>, pat: FactPattern, state: FactState) {
    st.mark_dirty(&pat.name.inner);
    st.facts.retain(|(p, _)| p.name != pat.name);
    st.facts.push((pat, state));
}

/// Render a fact literal's name and key fields as written in the source.
fn fact_text(fact: &FactLiteral, src: &str) -> String {
    let keys: Vec<String> = fact
        .key_fields
        .iter()
        .map(|(name, expr)| {
            let range: core::ops::Range<usize> = expr.span.into();
            let value = src.get(range).unwrap_or("..");
            format!("{name}: {value}")
        })
        .collect();
    format!("{}[{}]", fact.identifier, keys.join(", "))
}

/// Does a `NotExists` observation of `obs` prove `NotExists` for `obl`?
///
/// True when `obs`'s concrete keys are a prefix of `obl`'s: a trailing
/// bind marker makes a negative observation stronger (no fact with that
/// key prefix exists at all).
fn covers(obs: &FactPattern, obl: &FactPattern) -> bool {
    obs.name == obl.name
        && obs.keys.len() <= obl.keys.len()
        && obs
            .keys
            .iter()
            .zip(&obl.keys)
            .all(|((n1, e1), (n2, e2))| n1 == n2 && matches_expr(e1, e2))
}

fn same_pattern(a: &FactPattern, b: &FactPattern) -> bool {
    a.keys.len() == b.keys.len() && covers(a, b)
}

/// Span- and type-insensitive structural comparison of the expression
/// forms that can appear in fact keys. Unknown forms compare unequal,
/// which is the conservative direction for discharging obligations.
fn matches_expr(a: &Expression, b: &Expression) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Unit, ExprKind::Unit) => true,
        (ExprKind::Int(x), ExprKind::Int(y)) => x == y,
        (ExprKind::String(x), ExprKind::String(y)) => x == y,
        (ExprKind::Bool(x), ExprKind::Bool(y)) => x == y,
        (ExprKind::Identifier(x), ExprKind::Identifier(y)) => x == y,
        (ExprKind::EnumReference(x), ExprKind::EnumReference(y)) => {
            x.identifier == y.identifier && x.value == y.value
        }
        (ExprKind::Dot(b1, f1), ExprKind::Dot(b2, f2)) => f1 == f2 && matches_expr(b1, b2),
        // Pure functions are deterministic and fact state cannot change
        // between policy statements, so equal calls yield equal values.
        (ExprKind::FunctionCall(f1), ExprKind::FunctionCall(f2)) => {
            f1.identifier == f2.identifier
                && f1.arguments.len() == f2.arguments.len()
                && f1
                    .arguments
                    .iter()
                    .zip(&f2.arguments)
                    .all(|(x, y)| matches_expr(x, y))
        }
        _ => false,
    }
}

/// Record every fact-touching subexpression as an opaque observation point.
///
/// In a pure function, a `return` inside such an expression is an exit
/// the walk did not record, so the function can't be summarized.
fn collect_opaque<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out<'a>) {
    visit_facts(expr, &mut |fact, span| {
        st.opaque.push((fact.identifier.clone(), span));
    });
    if st.in_function && any_sub(expr, &mut |e| matches!(e.kind, ExprKind::Return(_))) {
        out.unusable = true;
    }
}

/// Fact names mutated anywhere in these statements (recursively).
fn mutated_fact_names(stmts: &[Statement]) -> Vec<Identifier> {
    let mut names = Vec::new();
    collect_mutated(stmts, &mut names);
    names
}

fn collect_mutated(stmts: &[Statement], names: &mut Vec<Identifier>) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Create(c) => names.push(c.fact.identifier.inner.clone()),
            StmtKind::Update(u) => names.push(u.fact.identifier.inner.clone()),
            StmtKind::Delete(d) => names.push(d.fact.identifier.inner.clone()),
            StmtKind::If(ifs) => {
                for (_, body) in &ifs.branches {
                    collect_mutated(body, names);
                }
                if let Some(body) = &ifs.fallback {
                    collect_mutated(body, names);
                }
            }
            StmtKind::Match(m) => {
                for arm in &m.arms {
                    collect_mutated(&arm.statements, names);
                }
            }
            StmtKind::Map(m) => collect_mutated(&m.statements, names),
            StmtKind::Finish(body) => collect_mutated(body, names),
            _ => {}
        }
    }
}

/// Visit every fact literal referenced by query-like functions in `expr`.
fn visit_facts(expr: &Expression, f: &mut impl FnMut(&FactLiteral, Span)) {
    match &expr.kind {
        ExprKind::InternalFunction(func) => match func {
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact) => f(fact, expr.span),
            InternalFunction::If(c, t, e) => {
                visit_facts(c, f);
                visit_facts(t, f);
                visit_facts(e, f);
            }
            InternalFunction::Todo(_) | InternalFunction::TestFail(..) => {}
        },
        ExprKind::Not(e)
        | ExprKind::Return(e)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Dot(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e)
        | ExprKind::Is(e, _) => visit_facts(e, f),
        ExprKind::Optional(o) => {
            if let Some(e) = o {
                visit_facts(e, f);
            }
        }
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Coalesce(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => {
            visit_facts(a, f);
            visit_facts(b, f);
        }
        ExprKind::NamedStruct(s) => {
            for (_, e) in &s.fields {
                visit_facts(e, f);
            }
        }
        ExprKind::FunctionCall(c) => {
            for e in &c.arguments {
                visit_facts(e, f);
            }
        }
        ExprKind::ForeignFunctionCall(c) => {
            for e in &c.arguments {
                visit_facts(e, f);
            }
        }
        ExprKind::Recall(c) => {
            for e in &c.arguments {
                visit_facts(e, f);
            }
        }
        ExprKind::Block(stmts, e) => {
            for stmt in stmts {
                match &stmt.kind {
                    StmtKind::Let(l) => visit_facts(&l.expression, f),
                    StmtKind::Check(c) => {
                        visit_facts(&c.expression, f);
                        visit_facts(&c.else_expression, f);
                    }
                    _ => {}
                }
            }
            visit_facts(e, f);
        }
        ExprKind::Match(m) => {
            visit_facts(&m.scrutinee, f);
            for arm in &m.arms {
                visit_facts(&arm.expression, f);
            }
        }
        ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::Identifier(_)
        | ExprKind::EnumReference(_) => {}
    }
}

#[cfg(test)]
mod tests;
