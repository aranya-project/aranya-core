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

use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use annotate_snippets::{AnnotationKind, Level, Renderer, Snippet};
use aranya_policy_ast::{
    FactCountType, Ident, Identifier, Span, Spanned as _, TypeKind, VType, ident,
    thir::{
        ExprKind, Expression, FactLiteral, FunctionCall, IfStatement, InternalFunction,
        LetStatement, MatchPattern, MatchStatement, Statement, StmtKind,
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
    /// Not the state of a fact: the entry's two keys hold different
    /// values. See [`unequal`].
    Differ,
    /// Not the state of a fact: the entry's two keys hold the same value,
    /// and the path writes the first as the second. See
    /// [`PathState::equate`].
    Same,
}

/// A canonicalized fact literal: fact name plus key-field values after
/// `let` substitution. Trailing bind markers (`?`) are omitted, as in the
/// typed HIR, so `keys` is a prefix of the schema's key fields.
///
/// An `Exists` entry may also name one value field, after the whole key.
/// This *value entry* says the fact exists and its stored value for that
/// field equals the expression. See [`value_entry`].
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

/// The keys of query results: for a variable and one of its key fields,
/// the key the query that bound the variable gave.
type KeyLinks = BTreeMap<(Identifier, Identifier), Expression>;

/// Why the analysis lost track of a fact at some point, for the notes of
/// a warning about that fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// An expression touched the fact but was too complex to analyze.
    TooComplex,
    /// Paths that knew different things about the fact were joined.
    Joined,
}

/// A point where the analysis lost track of a fact: the fact's name, the
/// source location, and why.
type OpaquePoint = (Ident, Span, Why);

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

/// Is `state` about values rather than a fact?
fn relates_values(state: FactState) -> bool {
    matches!(state, FactState::Differ | FactState::Same)
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
    let facts = a.iter().chain(b.iter()).flatten();
    for (pat, _) in facts.filter(|(_, s)| !relates_values(*s)) {
        if !known.contains(&pat.name) {
            known.push(pat.name.clone());
        }
    }
    let result = either(a, b);
    for name in known {
        let kept = result.iter().flatten().any(|(pat, _)| pat.name == name);
        if !kept {
            st.lose_track(name, span, Why::TooComplex);
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
    /// The stored value the exit returns, if it returns one: the fact
    /// the function read it from, in its terms, and the value field.
    value: Option<(FactPattern, Identifier)>,
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

/// The default limit on the number of distinct paths the analysis keeps
/// at one point of a walk. Past it, the paths are joined into one, which
/// keeps only what all of them know.
pub const DEFAULT_MAX_PATHS: usize = 64;

/// The parts of a fact's schema the analysis needs.
#[derive(Debug)]
pub(crate) struct FactSchema {
    /// The key fields, in schema order.
    pub(crate) keys: Vec<(Identifier, VType)>,
    /// How many value fields the fact has.
    pub(crate) values: usize,
}

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
    /// The schema of each fact.
    facts: BTreeMap<Identifier, FactSchema>,
    finish_functions: BTreeMap<Identifier, FunctionBody>,
    pure_functions: BTreeMap<Identifier, FunctionBody>,
    max_exit_paths: usize,
    /// The most distinct paths kept at one point of a walk.
    max_paths: usize,
    /// Pure function summaries, computed on first use. `None` means the
    /// function can't be summarized.
    summaries: RefCell<BTreeMap<Identifier, Option<Rc<Summary>>>>,
    /// Pure functions being summarized, to stop at recursion.
    summarizing: RefCell<Vec<Identifier>>,
    /// Warnings from summarizing pure functions, such as joins inside
    /// them, reported with the block being analyzed.
    pending: RefCell<Vec<ObligationWarning>>,
}

impl Analyzer {
    pub(crate) fn new(
        src: String,
        globals: Vec<Identifier>,
        facts: BTreeMap<Identifier, FactSchema>,
        max_exit_paths: usize,
        max_paths: usize,
    ) -> Self {
        Self {
            src,
            globals,
            facts,
            finish_functions: BTreeMap::new(),
            pure_functions: BTreeMap::new(),
            max_exit_paths,
            max_paths,
            summaries: RefCell::new(BTreeMap::new()),
            summarizing: RefCell::new(Vec::new()),
            pending: RefCell::new(Vec::new()),
        }
    }

    /// How many key fields `fact` has.
    fn key_count(&self, fact: &Identifier) -> usize {
        self.facts.get(fact).map_or(0, |schema| schema.keys.len())
    }

    /// Is `field` one of `fact`'s key fields?
    fn is_key(&self, fact: &Identifier, field: &Identifier) -> bool {
        self.facts
            .get(fact)
            .is_some_and(|schema| schema.keys.iter().any(|(key, _)| key == field))
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
        walk(stmts, vec![PathState::new(self, empty_db)], &mut out);
        let mut warnings = out.warnings;
        for w in self.pending.take() {
            add_warning(&mut warnings, w);
        }
        warnings
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
            vec![PathState::new(self, false)],
            &mut out,
        );
        self.summarizing.borrow_mut().pop();
        self.pending
            .borrow_mut()
            .extend(core::mem::take(&mut out.warnings));
        // Every `return` must be one the walk records as an exit. A
        // statement-level one it never reached is on no path that can run.
        // Any other is an exit the summary would miss.
        let mut recorded = core::mem::take(&mut out.modeled_returns);
        statement_exits(&body.statements, &mut recorded);
        let complete = return_sites(&body.statements).is_subset(&recorded);
        let summary = (!out.unusable && complete).then(|| {
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
struct Out {
    warnings: Vec<ObligationWarning>,
    /// Exits, when summarizing a pure function.
    exits: Vec<Exit>,
    max_exits: usize,
    /// The walk can't be summarized: it found more than `max_exits`
    /// exits.
    unusable: bool,
    /// The `return`s the walk recognized as exits, whether or not a path
    /// could reach them.
    modeled_returns: BTreeSet<Span>,
}

impl Out {
    fn new(max_exits: usize) -> Self {
        Self {
            warnings: Vec::new(),
            exits: Vec::new(),
            max_exits,
            unusable: false,
            modeled_returns: BTreeSet::new(),
        }
    }
}

/// How a path writes values for comparing them: each value it knows
/// equal to another is written as that one. Facts stay stored as
/// written, so they match what other paths know, and comparisons go
/// through a view, so keys written with either of two equal values match.
struct View {
    /// Each value known equal to another, with what it is written as.
    aliases: Vec<(Expression, Expression)>,
}

impl View {
    /// The facts in `facts` that can match a pattern named `name`, written
    /// as the view writes values. With nothing to rewrite, that is all of
    /// them, unchanged.
    fn named<'f>(&self, facts: &'f Facts, name: &Ident) -> Cow<'f, Facts> {
        if self.aliases.is_empty() {
            return Cow::Borrowed(facts);
        }
        Cow::Owned(
            facts
                .iter()
                .filter(|(p, _)| p.name == *name)
                .map(|(p, s)| (self.pattern(p).into_owned(), *s))
                .collect(),
        )
    }

    /// What `facts` says about which values differ, written as the view
    /// writes values.
    fn differing<'f>(&self, facts: &'f Facts) -> Cow<'f, Facts> {
        self.named(facts, &pair_name())
    }

    /// `e`, written as the view writes values.
    fn expr<'e>(&self, e: &'e Expression) -> Cow<'e, Expression> {
        if self.aliases.is_empty() {
            return Cow::Borrowed(e);
        }
        let env = BTreeMap::new();
        let sub = Subst {
            env: &env,
            strict: None,
            aliases: &self.aliases,
        };
        let mut out = e.clone();
        rewrite(&mut out, &sub, &mut Vec::new());
        Cow::Owned(out)
    }

    /// `p`, with its keys written as the view writes values.
    fn pattern<'p>(&self, p: &'p FactPattern) -> Cow<'p, FactPattern> {
        if self.aliases.is_empty() {
            return Cow::Borrowed(p);
        }
        Cow::Owned(FactPattern {
            keys: p
                .keys
                .iter()
                .map(|(name, e)| (name.clone(), self.expr(e).into_owned()))
                .collect(),
            ..p.clone()
        })
    }
}

/// Analysis state along a single control-flow path.
#[derive(Debug, Clone)]
struct PathState<'a> {
    az: &'a Analyzer,
    facts: Facts,
    /// `let`-bound names with substitutable values.
    env: BTreeMap<Identifier, Expression>,
    /// Points where the analysis lost track of a fact: expressions it
    /// could not interpret, and joins that dropped what it knew.
    opaque: Vec<OpaquePoint>,
    /// The fact database is known to be empty at the start of the block
    /// (an `init` command), except for the facts in `mutated`.
    empty_db: bool,
    /// The facts created or updated since the block started. Each may
    /// exist now, wherever the path knew it absent, so absence holds only
    /// for facts that provably differ from all of them.
    mutated: Vec<FactPattern>,
    /// Variables holding a fact read by a query, with the fact they hold.
    /// Used to prove an `update`'s stated values match the stored fact.
    query_bindings: Vec<(Identifier, FactPattern)>,
    /// What each key field of a query result holds: the key the query
    /// gave. Unlike the result's values, this stays true after any
    /// mutation, since a variable never changes.
    key_links: KeyLinks,
    /// Inside a finish function body, where every name must be a parameter
    /// or a global. Any other name must not be mistaken for a caller's
    /// variable of the same name.
    strict: bool,
    /// Pure function calls being evaluated, to stop at recursion.
    evaluating: Vec<Identifier>,
}

impl<'a> PathState<'a> {
    fn new(az: &'a Analyzer, empty_db: bool) -> Self {
        Self {
            az,
            facts: Vec::new(),
            env: BTreeMap::new(),
            opaque: Vec::new(),
            empty_db,
            mutated: Vec::new(),
            query_bindings: Vec::new(),
            key_links: BTreeMap::new(),
            strict: false,
            evaluating: Vec::new(),
        }
    }

    /// Does `pat` provably differ from every fact created or updated since
    /// the block started?
    fn untouched(&self, pat: &FactPattern) -> bool {
        let view = self.view();
        let pat = view.pattern(pat);
        let differing = view.differing(&self.facts);
        self.mutated
            .iter()
            .all(|m| differ(&differing, &view.pattern(m), &pat))
    }

    /// Is `pat` known not to exist because the database started empty?
    fn known_absent(&self, pat: &FactPattern) -> bool {
        self.empty_db && self.untouched(pat)
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
        // Equalities first: they decide which facts are the same.
        let (equal, rest): (Facts, Facts) =
            facts.into_iter().partition(|(_, s)| *s == FactState::Same);
        for (pat, _) in &equal {
            for (a, b) in pair_values(pat) {
                if !self.equate(a, b) {
                    return false;
                }
            }
        }
        let view = self.view();
        for (pat, state) in rest {
            let written = view.pattern(&pat);
            let differs_from_itself = (state == FactState::Differ)
                & pair_values(&written).any(|(a, b)| matches_expr(a, b));
            if differs_from_itself
                || contradicts(&view.named(&self.facts, &pat.name), &written, state)
                || (state == FactState::Exists && self.known_absent(&pat))
            {
                return false;
            }
            observe(self, pat, state);
        }
        true
    }

    /// How the path writes values for comparing them. See [`View`].
    fn view(&self) -> View {
        View {
            aliases: self
                .facts
                .iter()
                .filter(|(_, s)| *s == FactState::Same)
                .flat_map(|(p, _)| pair_values(p))
                .map(|(from, to)| (from.clone(), to.clone()))
                .collect(),
        }
    }

    /// Learn that `a` and `b` hold the same value. From now on, whenever
    /// the path compares values, it writes the more transient of the two
    /// as the other, so keys written with either match. What the path
    /// knows stays as written, so it still matches what other paths
    /// know. Returns false if the path is impossible: two different
    /// literals, or facts that contradict each other once their keys are
    /// the same, including values known to differ.
    fn equate(&mut self, a: &Expression, b: &Expression) -> bool {
        let view = self.view();
        let (a, b) = (view.expr(a).into_owned(), view.expr(b).into_owned());
        if matches_expr(&a, &b) {
            return true;
        }
        if literals_differ(&a, &b) {
            return false;
        }
        // Keep the less transient side, or else the smaller one. A side
        // containing the other is larger, so it is never kept, and writing
        // it as the other can't loop.
        let globals = &self.az.globals;
        let rank = |e: &Expression| (transience(e, globals), size(e));
        let (from, to) = if rank(&a) < rank(&b) { (b, a) } else { (a, b) };
        // Keep every equality written in terms of the others.
        let alias = [(from.clone(), to.clone())];
        let env = BTreeMap::new();
        let sub = Subst {
            env: &env,
            strict: None,
            aliases: &alias,
        };
        self.facts
            .iter_mut()
            .filter(|(_, s)| *s == FactState::Same)
            .flat_map(|(p, _)| p.keys.iter_mut())
            .for_each(|(_, e)| {
                rewrite(e, &sub, &mut Vec::new());
            });
        self.facts.push((pair_entry(&from, &to), FactState::Same));
        // Facts written differently that now name the same fact must agree.
        let view = self.view();
        let mut seen: Facts = Vec::new();
        for (p, state) in self
            .facts
            .iter()
            .map(|(p, s)| (view.pattern(p).into_owned(), *s))
        {
            let differs_from_itself =
                (state == FactState::Differ) & pair_values(&p).any(|(a, b)| matches_expr(a, b));
            if differs_from_itself || contradicts(&seen, &p, state) {
                return false;
            }
            seen.push((p, state));
        }
        true
    }

    /// Note that the path lost track of facts named `name` at `span`, once
    /// for each place and reason.
    fn lose_track(&mut self, name: Ident, span: Span, why: Why) {
        merge_opaque(&mut self.opaque, vec![(name, span, why)]);
    }

    fn bind_query(&mut self, var: Identifier, pat: FactPattern) {
        // `var` holds what the query gave for each key. A key it bound is
        // read from `var` itself, which says nothing.
        self.key_links.retain(|(v, _), _| *v != var);
        for (key, given) in &pat.keys {
            if !mentions(given, &var) {
                self.key_links
                    .insert((var.clone(), key.clone()), given.clone());
            }
        }
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
        self.key_links
            .retain(|(x, _), given| (x != v) & !mentions(given, v));
    }
}

/// Add `w` to `warnings`, merging it into an earlier warning with the
/// same span and message. A statement reached on several paths, or a
/// finish function reached from several commands, can fail the same way
/// on each, and the paths may have skipped different opaque expressions,
/// so the merged warning takes the union of the notes.
fn add_warning(warnings: &mut Vec<ObligationWarning>, w: ObligationWarning) {
    match warnings
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
        None => warnings.push(w),
    }
}

/// Collapse warnings that differ only in their notes, as [`add_warning`]
/// does.
pub(crate) fn dedup_warnings(warnings: Vec<ObligationWarning>) -> Vec<ObligationWarning> {
    let mut out = Vec::new();
    for w in warnings {
        add_warning(&mut out, w);
    }
    out
}

/// The states of the paths that reach one point of a walk.
type Paths<'a> = Vec<PathState<'a>>;

/// Walk `stmts` from every path in `paths`, and return the paths that
/// run off the end. A path that ends inside, at a `finish`, a `return`, a
/// `recall`, or a check that fails, records what it must and drops out.
///
/// After an `if` or `match`, the paths out of its branches are merged by
/// [`merge`] and [`limit`], so what follows runs once per distinct state rather
/// than once per way through the branches.
fn walk<'a>(stmts: &[Statement], mut paths: Paths<'a>, out: &mut Out) -> Paths<'a> {
    for stmt in stmts {
        if paths.is_empty() {
            return paths;
        }
        paths = match &stmt.kind {
            StmtKind::Let(l) => paths
                .into_iter()
                .filter_map(|mut st| observe_let(&mut st, l, out).then_some(st))
                .collect(),
            StmtKind::Check(c) => paths
                .into_iter()
                .filter_map(|mut st| {
                    let (when_true, when_false) = cond_of(&mut st, &c.expression, out);
                    terminal_branch(&st, when_false, &c.else_expression, out);
                    st.assume(when_true).then_some(st)
                })
                .collect(),
            StmtKind::If(ifs) => walk_if(ifs, stmt.span, paths, out),
            StmtKind::Match(m) => walk_match(m, paths, out),
            StmtKind::Map(_) => {
                // `map` is only allowed in actions, which the analysis does
                // not walk. Should that change, its body may mutate any
                // fact any number of times.
                for st in &mut paths {
                    st.forget_all();
                }
                paths
            }
            StmtKind::Finish(fstmts) => {
                for mut st in paths {
                    analyze_finish(fstmts, &mut st, out);
                }
                // A finish block terminates policy execution.
                Vec::new()
            }
            StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
                for st in &mut paths {
                    let e = resolve(st, e);
                    collect_opaque(st, &e);
                }
                paths
            }
            StmtKind::Return(r) => {
                // Only functions have `return` statements. Exits recorded
                // for a command block are never read.
                out.modeled_returns.insert(stmt.span);
                for st in paths {
                    record_exit(st, &r.expression, out);
                }
                Vec::new()
            }
            StmtKind::Recall(_) => Vec::new(),
            StmtKind::ActionCall(_) | StmtKind::FunctionCall(_) => paths,
            // Mutations only appear inside finish contexts, which are
            // handled by `analyze_finish`.
            StmtKind::Create(_) | StmtKind::Update(_) | StmtKind::Delete(_) => paths,
        };
    }
    paths
}

/// Walk an `if` statement. Each branch runs on the paths where its
/// condition is true and every earlier one false, and the paths where
/// all are false take the `else`, if there is one.
fn walk_if<'a>(ifs: &IfStatement, span: Span, paths: Paths<'a>, out: &mut Out) -> Paths<'a> {
    let mut entering: Vec<Paths<'a>> = ifs.branches.iter().map(|_| Vec::new()).collect();
    let mut fallback = Vec::new();
    for mut st in paths {
        let mut earlier_false = nothing();
        for ((cond, _), branch_paths) in ifs.branches.iter().zip(&mut entering) {
            let (when_true, when_false) = cond_of(&mut st, cond, out);
            let mut branch = st.clone();
            if branch.assume(both(when_true, earlier_false.clone())) {
                branch_paths.push(branch);
            }
            earlier_false = both(earlier_false, when_false);
        }
        if st.assume(earlier_false) {
            fallback.push(st);
        }
    }
    let mut next = Vec::new();
    for ((_, body), branch_paths) in ifs.branches.iter().zip(entering) {
        next.extend(walk_scope(body, &[], branch_paths, out));
    }
    match &ifs.fallback {
        Some(body) => next.extend(walk_scope(body, &[], fallback, out)),
        None => next.extend(fallback),
    }
    let site = ifs.branches.first().map_or(span, |(cond, _)| cond.span);
    limit(merge(next), site, out)
}

/// Walk a `match` statement. Each arm runs on the paths where its
/// pattern matches and every earlier one doesn't.
fn walk_match<'a>(m: &MatchStatement, paths: Paths<'a>, out: &mut Out) -> Paths<'a> {
    let mut entering: Vec<Paths<'a>> = m.arms.iter().map(|_| Vec::new()).collect();
    for mut st in paths {
        let scrutinee = resolve(&st, &m.expression);
        // The scrutinee runs before any arm.
        let mut earlier_false = call_facts(&mut st, &scrutinee, out);
        for (arm, arm_paths) in m.arms.iter().zip(&mut entering) {
            let (when_true, when_false, bound) = arm_cond(&mut st, &scrutinee, &arm.pattern, out);
            let mut branch = st.clone();
            for var in &bound.names {
                branch.forget_name(var);
            }
            if branch.assume(both(when_true, earlier_false.clone())) {
                if let Some((var, pat)) = bound.query {
                    branch.bind_query(var, pat);
                }
                arm_paths.push(branch);
            }
            earlier_false = both(earlier_false, when_false);
        }
    }
    let mut next = Vec::new();
    for (arm, arm_paths) in m.arms.iter().zip(entering) {
        next.extend(walk_scope(
            &arm.statements,
            &arm_names(&arm.pattern),
            arm_paths,
            out,
        ));
    }
    limit(merge(next), m.expression.span, out)
}

/// Walk `body`, a scope of its own, from `paths`. On each path out of it,
/// forget the names it binds, and `names` bound with it by a `match`
/// pattern: nothing after the scope can refer to them, and paths that
/// differ only in them can then merge.
fn walk_scope<'a>(
    body: &[Statement],
    names: &[Identifier],
    paths: Paths<'a>,
    out: &mut Out,
) -> Paths<'a> {
    let mut ends = walk(body, merge(paths), out);
    let mut bound = bound_names(body);
    bound.extend_from_slice(names);
    for end in &mut ends {
        for name in &bound {
            end.forget_name(name);
        }
    }
    ends
}

/// Keep one copy of each distinct state in `paths`, merging the opaque
/// points of the copies, so the rest of the walk runs once per state.
/// This loses nothing: the copies knew the same things.
fn merge(paths: Paths<'_>) -> Paths<'_> {
    let mut kept: Paths<'_> = Vec::new();
    for st in paths {
        match kept.iter_mut().find(|k| same_state(k, &st)) {
            Some(k) => {
                // Only what both paths know about values still holds.
                k.facts.retain(|(p, s)| {
                    !relates_values(*s)
                        | st.facts.iter().any(|(q, t)| (t == s) & same_pattern(p, q))
                });
                merge_opaque(&mut k.opaque, st.opaque);
            }
            None => kept.push(st),
        }
    }
    kept
}

/// Past the path limit, join `paths` into one state that keeps only what
/// every path knows. The join is reported at `site`, the branch whose
/// paths were joined, naming the facts it dropped. Each of those facts
/// also gets a note pointing here on the joined path, so a later warning
/// about it says it may come from the join.
fn limit<'a>(mut paths: Paths<'a>, site: Span, out: &mut Out) -> Paths<'a> {
    let max = paths.first().map_or(usize::MAX, |st| st.az.max_paths);
    if paths.len() <= max {
        return paths;
    }
    let first = paths.swap_remove(0);
    let (mut joined, dropped) = join(first, paths);
    for name in &dropped {
        joined.lose_track(name.clone(), site, Why::Joined);
    }
    add_warning(&mut out.warnings, paths_joined(site, max, &dropped));
    vec![joined]
}

/// Do two path states know the same things? Opaque points, which only
/// feed diagnostics, don't count.
fn same_state(a: &PathState<'_>, b: &PathState<'_>) -> bool {
    // Within one walk, once each branch forgets the names it bound, paths
    // differ only in their facts. The rest is compared anyway, since
    // merging paths that differ would be unsound.
    // Which values are equal or differ doesn't count: paths that differ
    // only there merge, keeping what all of them know. Otherwise each `==`
    // or `!=` on a branch would double the paths after it.
    let facts_in = |x: &Facts, y: &Facts| {
        x.iter()
            .filter(|(_, s)| !relates_values(*s))
            .all(|(p, s)| y.iter().any(|(q, t)| (s == t) & same_pattern(p, q)))
    };
    let mutated = |st: &PathState<'_>| -> Facts {
        st.mutated
            .iter()
            .map(|p| (p.clone(), FactState::Exists))
            .collect()
    };
    let bindings_in = |x: &[(Identifier, FactPattern)], y: &[(Identifier, FactPattern)]| {
        x.iter()
            .all(|(v, p)| y.iter().any(|(w, q)| (v == w) & same_pattern(p, q)))
    };
    [
        facts_in(&a.facts, &b.facts),
        facts_in(&b.facts, &a.facts),
        bindings_in(&a.query_bindings, &b.query_bindings),
        bindings_in(&b.query_bindings, &a.query_bindings),
        a.env == b.env,
        a.key_links == b.key_links,
        facts_in(&mutated(a), &mutated(b)),
        facts_in(&mutated(b), &mutated(a)),
        a.empty_db == b.empty_db,
    ]
    .into_iter()
    .all(|same| same)
}

/// Join `rest` into `joined`, keeping only what every path knows: the
/// facts all of them imply, and the substitutions and query bindings they
/// all share. Returns the joined state and the names of the facts some
/// path knew that the joined state doesn't.
fn join<'a>(mut joined: PathState<'a>, rest: Paths<'a>) -> (PathState<'a>, Vec<Ident>) {
    let mut known = joined.facts.clone();
    for st in rest {
        known.extend(st.facts.iter().cloned());
        let facts = core::mem::take(&mut joined.facts);
        joined.facts = either(Some(facts), Some(st.facts)).unwrap_or_default();
        joined
            .env
            .retain(|name, value| st.env.get(name) == Some(value));
        joined
            .key_links
            .retain(|link, given| st.key_links.get(link) == Some(given));
        joined.query_bindings.retain(|(v, p)| {
            st.query_bindings
                .iter()
                .any(|(w, q)| (v == w) & same_pattern(p, q))
        });
        joined.mutated.extend(st.mutated);
        joined.empty_db &= st.empty_db;
        merge_opaque(&mut joined.opaque, st.opaque);
    }
    // Paths that weren't merged differ in their facts, since everything
    // else is the same within one walk, so a join always drops some.
    let mut dropped: Vec<Ident> = Vec::new();
    for (p, s) in known.iter().filter(|(_, s)| !relates_values(*s)) {
        let kept = joined
            .facts
            .iter()
            .any(|(q, t)| (s == t) & same_pattern(p, q));
        if !kept && !dropped.contains(&p.name) {
            dropped.push(p.name.clone());
        }
    }
    (joined, dropped)
}

/// Add the opaque points of `from` that `into` lacks.
fn merge_opaque(into: &mut Vec<OpaquePoint>, from: Vec<OpaquePoint>) {
    for point in from {
        if !into.contains(&point) {
            into.push(point);
        }
    }
}

/// Record a pure function exit returning `value`. The exit knows what
/// returning `value` implies: the calls in it returned, and when it is
/// `x or ..` with a right side that never produces a value, `x` is
/// `Some`. On a path where that can't hold, there is no exit.
fn record_exit<'a>(mut st: PathState<'a>, value: &Expression, out: &mut Out) {
    if out.exits.len() >= out.max_exits {
        out.unusable = true;
        return;
    }
    let ret = resolve(&st, value);
    let returned = match &ret.kind {
        ExprKind::Coalesce(lhs, rhs) if matches!(rhs.vtype.inner, TypeKind::Never) => {
            cond_is(&mut st, lhs, true, out).0
        }
        _ => call_facts(&mut st, &ret, out),
    };
    if !st.assume(returned) {
        return;
    }
    let value = stored_refs(&mut st, &ret).into_iter().next();
    out.exits.push(Exit {
        facts: st.facts,
        ret,
        value,
    });
}

/// Add to `sites` the `return`s the walk records inside `e` whenever it
/// evaluates `e` as an arm or a terminal: `e` itself if it is a `return`,
/// the statement-level exits and final expression of a block, and the
/// arms of an `if` or `match`. Called before checking whether the path
/// can run, so a `return` on a path that can't run still counts.
fn mark_arm_exits(e: &Expression, sites: &mut BTreeSet<Span>) {
    match &e.kind {
        ExprKind::Return(_) => {
            sites.insert(e.span);
        }
        ExprKind::Block(stmts, last) => {
            statement_exits(stmts, sites);
            mark_arm_exits(last, sites);
        }
        ExprKind::InternalFunction(InternalFunction::If(_, then, other)) => {
            mark_arm_exits(then, sites);
            mark_arm_exits(other, sites);
        }
        ExprKind::Match(m) => {
            for arm in &m.arms {
                mark_arm_exits(&arm.expression, sites);
            }
        }
        _ => {}
    }
}

/// The path where a `check`'s `else` or an `or`'s right side runs: a
/// copy of `st` that knows `know`, on which terminal `e` runs.
fn terminal_branch<'a>(st: &PathState<'a>, know: Know, e: &Expression, out: &mut Out) {
    mark_arm_exits(e, &mut out.modeled_returns);
    // `recall`, `todo()`, and `test_fail()` have nothing to walk.
    let walkable = matches!(
        e.kind,
        ExprKind::Return(_)
            | ExprKind::Block(..)
            | ExprKind::Match(..)
            | ExprKind::InternalFunction(InternalFunction::If(..))
    );
    if !walkable {
        return;
    }
    let mut failed = st.clone();
    if failed.assume(know) {
        run_terminal(&mut failed, e, out);
    }
}

/// Run `e`, which never produces a value, on the path `st`: the `else`
/// of a `check`, the right side of an `or`, or an arm of type `Never`. A
/// `return` there is an exit, and the statements of a block there are
/// walked, since they can hold a `finish` or a `return`.
fn run_terminal<'a>(st: &mut PathState<'a>, e: &Expression, out: &mut Out) {
    if let ExprKind::Return(value) = &e.kind {
        // Only functions have `return`. Exits recorded for a command
        // block are never read.
        out.modeled_returns.insert(e.span);
        record_exit(st.clone(), value, out);
        return;
    }
    let e = resolve(st, e);
    branch_cond(st, &e, out, &mut |st, e, _| {
        collect_opaque(st, e);
        (nothing(), nothing())
    });
}

/// The span of every `return` in a function body, wherever it appears.
/// Lowering keeps source spans and never adds a `return`, so the spans
/// tell them apart.
fn return_sites(stmts: &[Statement]) -> BTreeSet<Span> {
    let mut sites = BTreeSet::new();
    visit_stmts(stmts, &mut |node| match node {
        Node::Stmt(s) if matches!(s.kind, StmtKind::Return(_)) => {
            sites.insert(s.span);
        }
        Node::Expr(e) if matches!(e.kind, ExprKind::Return(_)) => {
            sites.insert(e.span);
        }
        _ => {}
    });
    sites
}

/// Add the statement-level `return`s in `stmts` to `sites`: `return`
/// statements and the exits in the `else` of a `check` and the right side
/// of an `or`, including those in `if` and `match` statement bodies but
/// not those inside other expressions. The walk records each of these as
/// an exit whenever it reaches it, so one it never reaches can't run.
fn statement_exits(stmts: &[Statement], sites: &mut BTreeSet<Span>) {
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Return(_) => {
                sites.insert(stmt.span);
            }
            StmtKind::Check(c) => mark_arm_exits(&c.else_expression, sites),
            StmtKind::Let(l) => {
                if let ExprKind::Coalesce(_, rhs) = &l.expression.kind
                    && matches!(rhs.vtype.inner, TypeKind::Never)
                {
                    mark_arm_exits(rhs, sites);
                }
            }
            StmtKind::If(ifs) => {
                for (_, body) in &ifs.branches {
                    statement_exits(body, sites);
                }
                if let Some(body) = &ifs.fallback {
                    statement_exits(body, sites);
                }
            }
            StmtKind::Match(m) => {
                for arm in &m.arms {
                    statement_exits(&arm.statements, sites);
                }
            }
            _ => {}
        }
    }
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
    out: &mut Out,
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
                let (mut t, mut f) = cond_is(st, scrutinee, true, out);
                if let ExprKind::Identifier(var) = &inner.kind {
                    bound.names.push(var.inner.clone());
                    // With other values in the arm, the scrutinee may not
                    // be `Some` at all, so `x` may hold nothing.
                    if values.len() == 1
                        && let Some(fact) = query_of(st, scrutinee)
                    {
                        let full = full_key_pattern(&pattern_raw(&fact, st), &var.inner, st);
                        t = both(t, exists_with_values(&fact, full.clone(), st));
                        bound.query = Some((var.inner.clone(), full));
                    }
                } else {
                    // `Some(1)` matches only one value: when it doesn't,
                    // the scrutinee may still be `Some`.
                    f = nothing();
                }
                (t, f)
            }
            ExprKind::Ok(inner) | ExprKind::Err(inner) => {
                if let ExprKind::Identifier(var) = &inner.kind {
                    bound.names.push(var.inner.clone());
                }
                (nothing(), nothing())
            }
            // Any other value is a literal the scrutinee is compared with.
            _ => (same(scrutinee, value), unequal(scrutinee, value)),
        };
        when_true = either(when_true, t);
        when_false = both(when_false, f);
    }
    (when_true, when_false, bound)
}

/// What `expr` implies when it is true, and when it is false.
fn cond_of<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out) -> (Know, Know) {
    let expr = resolve(st, expr);
    cond_resolved(st, &expr, out)
}

/// [`cond_of`] for an expression already in the path's terms.
fn cond_resolved<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out) -> (Know, Know) {
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
        // `b` runs only where `a` lets it, so what `a` implies holds
        // wherever `b` decides.
        ExprKind::And(a, b) => {
            let (ta, fa) = cond_resolved(st, a, out);
            let (tb, fb) = cond_resolved(st, b, out);
            let b_false = both(ta.clone(), fb);
            (both(ta, tb), either_noted(st, expr.span, fa, b_false))
        }
        ExprKind::Or(a, b) => {
            let (ta, fa) = cond_resolved(st, a, out);
            let (tb, fb) = cond_resolved(st, b, out);
            let b_true = both(fa.clone(), tb);
            (either_noted(st, expr.span, ta, b_true), both(fa, fb))
        }
        ExprKind::InternalFunction(InternalFunction::Exists(fact)) => {
            let calls = call_facts(st, expr, out);
            let pat = pattern_raw(fact, st);
            with_calls(
                calls,
                (
                    exists_with_values(fact, pat.clone(), st),
                    absent_unless_filtered(fact, pat),
                ),
            )
        }
        ExprKind::InternalFunction(InternalFunction::FactCount(ty, n, fact)) => {
            let calls = call_facts(st, expr, out);
            let known = count_cond(st, expr, ty, n.inner, fact);
            with_calls(calls, known)
        }
        ExprKind::Is(inner, some) => cond_is(st, inner, *some, out),
        ExprKind::FunctionCall(fc) => {
            let args = args_facts(st, fc, out);
            let known = through_call(st, fc, expr.span, out, &mut |st, ret, out| {
                cond_resolved(st, ret, out)
            });
            with_calls(args, known)
        }
        ExprKind::Equal(a, b) | ExprKind::NotEqual(a, b) => {
            let calls = call_facts(st, expr, out);
            collect_opaque(st, expr);
            let a = linked(st, a.as_ref().clone());
            let b = linked(st, b.as_ref().clone());
            let equal = both(calls.clone(), both(equal_values(st, &a, &b), same(&a, &b)));
            let unequal = both(calls, unequal(&a, &b));
            if matches!(expr.kind, ExprKind::Equal(..)) {
                (equal, unequal)
            } else {
                (unequal, equal)
            }
        }
        _ => {
            let calls = call_facts(st, expr, out);
            collect_opaque(st, expr);
            (calls.clone(), calls)
        }
    }
}

/// What a counting query implies. `exists` is `at_least 1`.
fn count_cond(
    st: &mut PathState<'_>,
    expr: &Expression,
    ty: &FactCountType,
    n: i64,
    fact: &FactLiteral,
) -> (Know, Know) {
    let pat = pattern_raw(fact, st);
    let exists = exists_with_values(fact, pat.clone(), st);
    let absent = absent_unless_filtered(fact, pat);
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
            collect_opaque(st, expr);
            (nothing(), nothing())
        }
    }
}

/// What a fact literal not matching implies: `NotExists` for its key,
/// unless the literal filters on values. Then a fact with that key may
/// still exist with other values, so nothing is known. Value fields
/// that are bind markers are dropped when lowering, so an all-bind
/// filter is no filter.
fn absent_unless_filtered(fact: &FactLiteral, pat: FactPattern) -> Know {
    let filtered = fact.value_fields.as_ref().is_some_and(|v| !v.is_empty());
    if filtered {
        nothing()
    } else {
        fact_is(pat, FactState::NotExists)
    }
}

/// What `expr is Some` (or `is None`, when `some` is false) implies.
fn cond_is<'a>(
    st: &mut PathState<'a>,
    expr: &Expression,
    some: bool,
    out: &mut Out,
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
            let calls = call_facts(st, expr, out);
            let pat = pattern_raw(fact, st);
            with_calls(
                calls,
                (
                    exists_with_values(fact, pat.clone(), st),
                    absent_unless_filtered(fact, pat),
                ),
            )
        }
        ExprKind::Optional(None) => (None, nothing()),
        ExprKind::Optional(Some(_)) => (nothing(), None),
        ExprKind::FunctionCall(fc) => {
            let args = args_facts(st, fc, out);
            let known = through_call(st, fc, expr.span, out, &mut |st, ret, out| {
                cond_is(st, ret, true, out)
            });
            with_calls(args, known)
        }
        _ => {
            let calls = call_facts(st, expr, out);
            collect_opaque(st, expr);
            (calls.clone(), calls)
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
    out: &mut Out,
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

/// The calls to pure functions that run whenever `expr` does. A call on
/// the right of `&&`, `||`, or `or`, or in an arm of an `if` or `match`,
/// may not run, so it doesn't count. Neither does a call in a block,
/// whose value may use names the block binds, which mean nothing outside
/// it.
fn always_calls<'e>(expr: &'e Expression, calls: &mut Vec<(&'e FunctionCall, Span)>) {
    match &expr.kind {
        ExprKind::FunctionCall(fc) => {
            for arg in &fc.arguments {
                always_calls(arg, calls);
            }
            calls.push((fc, expr.span));
        }
        ExprKind::ForeignFunctionCall(fc) => {
            for arg in &fc.arguments {
                always_calls(arg, calls);
            }
        }
        ExprKind::And(a, _) | ExprKind::Or(a, _) | ExprKind::Coalesce(a, _) => {
            always_calls(a, calls);
        }
        ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => {
            always_calls(a, calls);
            always_calls(b, calls);
        }
        ExprKind::Not(e)
        | ExprKind::Is(e, _)
        | ExprKind::Dot(e, _)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e)
        | ExprKind::Optional(Some(e)) => always_calls(e, calls),
        ExprKind::NamedStruct(s) => {
            for (_, e) in &s.fields {
                always_calls(e, calls);
            }
        }
        ExprKind::InternalFunction(
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact),
        ) => {
            let values = fact.value_fields.iter().flatten();
            for (_, e) in fact.key_fields.iter().chain(values) {
                always_calls(e, calls);
            }
        }
        ExprKind::InternalFunction(InternalFunction::If(c, _, _)) => always_calls(c, calls),
        ExprKind::Match(m) => always_calls(&m.scrutinee, calls),
        _ => {}
    }
}

/// What holds once the calls `expr` always makes have returned. A pure
/// function returns through one of its exits, so what all of them know
/// holds after the call, even where its value is only compared, bound by
/// `let`, or passed to another call.
fn call_facts<'a>(st: &mut PathState<'a>, expr: &Expression, out: &mut Out) -> Know {
    let mut calls = Vec::new();
    always_calls(expr, &mut calls);
    let mut know = nothing();
    for (fc, span) in calls {
        let (returned, _) = through_call(st, fc, span, out, &mut |_, _, _| (nothing(), nothing()));
        know = both(know, returned);
    }
    know
}

/// [`call_facts`] for the arguments of a call, which run before it.
fn args_facts<'a>(st: &mut PathState<'a>, fc: &FunctionCall, out: &mut Out) -> Know {
    let mut know = nothing();
    for arg in &fc.arguments {
        let calls = call_facts(st, arg, out);
        know = both(know, calls);
    }
    know
}

/// Add what `calls` imply to both outcomes of a condition: the calls ran
/// whichever way it went.
fn with_calls(calls: Know, (when_true, when_false): (Know, Know)) -> (Know, Know) {
    (both(calls.clone(), when_true), both(calls, when_false))
}

/// Gives what one arm's or exit's value implies when true and when false.
type Eval<'e, 'a> = dyn FnMut(&mut PathState<'a>, &Expression, &mut Out) -> (Know, Know) + 'e;

/// What an `if`, `match`, or block expression implies, or `None` if
/// `expr` is another form. `eval` gives what one arm's value implies;
/// the result holds what every arm that can produce a value implies.
fn branch_cond<'a>(
    st: &mut PathState<'a>,
    expr: &Expression,
    out: &mut Out,
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
            // The scrutinee runs before any arm.
            let mut earlier_false = call_facts(st, &m.scrutinee, out);
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
            let ends = walk(stmts, vec![st.clone()], out);
            mark_arm_exits(e, &mut out.modeled_returns);
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
    out: &mut Out,
    eval: &mut Eval<'_, 'a>,
) -> (Know, Know) {
    // The exits in the arm count as recorded even if the arm can't run.
    mark_arm_exits(e, &mut out.modeled_returns);
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
    out: &mut Out,
    eval: &mut Eval<'_, 'a>,
) -> (Know, Know) {
    let mut result = (None, None);
    if matches!(e.vtype.inner, TypeKind::Never) {
        // The arm never produces a value, but it still runs.
        run_terminal(&mut end, e, out);
    } else {
        let e = resolve(&end, e);
        // The arm may itself be an `if`, `match`, or block. Nothing it
        // proves about its own names can leave it: outside, those names
        // are unbound or mean something else.
        let (t, f) =
            branch_cond(&mut end, &e, out, eval).unwrap_or_else(|| eval(&mut end, &e, out));
        let facts = without_names(Some(end.facts.clone()), bound);
        result = (
            both(facts.clone(), without_names(t, bound)),
            both(facts, without_names(f, bound)),
        );
    }
    // What the arm touched carries over. It can't have changed the
    // database: every mutation ends its path before the arm's value.
    merge_opaque(&mut st.opaque, end.opaque.into_iter().skip(base).collect());
    result
}

/// `know` without the facts that mention any of `names`.
fn without_names(know: Know, names: &[Identifier]) -> Know {
    know.map(|facts| {
        facts
            .into_iter()
            .filter(|(p, _)| !names.iter().any(|v| mentions_pattern(p, v)))
            .collect()
    })
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
    let names: Vec<Ident> = st
        .az
        .pure_functions
        .get(name)
        .map_or_else(Vec::new, |body| {
            let mut names = Vec::new();
            stmt_exprs(&body.statements, &mut |e| {
                visit_facts(e, &mut |fact, _| names.push(fact.identifier.clone()));
            });
            names
        });
    for fact in names {
        st.lose_track(fact, span, Why::TooComplex);
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
fn analyze_finish<'a>(stmts: &[Statement], st: &mut PathState<'a>, out: &mut Out) {
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
    out: &mut Out,
) {
    for stmt in stmts {
        let mut found = Vec::new();
        match &stmt.kind {
            StmtKind::Create(c) => {
                let pat = pattern_of(&c.fact, st);
                if let Some(prev) = manipulated(st, touched, &pat) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if !proven_absent(st, &pat) {
                    found.push(unproven_create(stmt.span, &pat, &st.opaque));
                }
                apply_change(st, pat.clone(), Change::Create);
                touched.push(pat);
            }
            StmtKind::Update(u) => {
                let pat = pattern_of(&u.fact, st);
                if let Some(prev) = manipulated(st, touched, &pat) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if partially_stated(st, &u.fact) {
                    found.push(partial_values(stmt.span, &pat));
                } else if !proven_exists(st, &pat) {
                    found.push(unproven_exists(stmt.span, &pat, Mutation::Update, st));
                } else if !values_proven(st, &u.fact, &pat) {
                    found.push(unproven_values(stmt.span, &pat, st));
                }
                apply_change(st, pat.clone(), Change::Update);
                touched.push(pat);
            }
            StmtKind::Delete(d) => {
                let pat = pattern_of(&d.fact, st);
                if let Some(prev) = manipulated(st, touched, &pat) {
                    found.push(double_manipulation(stmt.span, &pat, prev));
                } else if !proven_exists(st, &pat) {
                    found.push(unproven_exists(stmt.span, &pat, Mutation::Delete, st));
                }
                apply_change(st, pat.clone(), Change::Delete);
                touched.push(pat);
            }
            StmtKind::FunctionCall(fc) => {
                let name = &fc.identifier.inner;
                let recursive = calls.iter().any(|(n, _)| n == name);
                let az = st.az;
                match (az.finish_functions.get(name), recursive) {
                    (Some(body), false) => {
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
                    // A recursive call is not followed: it may mutate any
                    // fact.
                    (Some(_), true) => {
                        found.push(recursive_call(stmt.span, name));
                        st.forget_all();
                    }
                    // The compiler rejects calls to unknown functions.
                    (None, _) => st.forget_all(),
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
            add_warning(&mut out.warnings, w);
        }
    }
}

/// The fact already manipulated in this finish block that `pat` names,
/// if any. Keys the path knows are equal name the same fact.
fn manipulated<'t>(
    st: &PathState<'_>,
    touched: &'t [FactPattern],
    pat: &FactPattern,
) -> Option<&'t FactPattern> {
    let view = st.view();
    let pat = view.pattern(pat);
    touched
        .iter()
        .find(|t| same_pattern(&view.pattern(t), &pat))
}

/// Is `pat` known not to exist on this path? It must provably differ
/// from every fact created or updated since the block started, and the
/// database must have started empty or an observation cover it.
fn proven_absent(st: &PathState<'_>, pat: &FactPattern) -> bool {
    let view = st.view();
    let written = view.pattern(pat);
    st.untouched(pat)
        && (st.empty_db
            || view
                .named(&st.facts, &pat.name)
                .iter()
                .any(|(p, s)| *s == FactState::NotExists && covers(p, &written)))
}

/// Is `pat` known to exist on this path?
///
/// Unlike [`proven_absent`], a bind marker does not help: `F[a: x, b: ?]`
/// existing says nothing about any particular `b`. So the observation must
/// name exactly the same key.
fn proven_exists(st: &PathState<'_>, pat: &FactPattern) -> bool {
    let view = st.view();
    let pat = view.pattern(pat);
    view.named(&st.facts, &pat.name)
        .iter()
        .any(|(p, s)| *s == FactState::Exists && same_pattern(p, &pat))
}

/// Does every value an `update` states equal the stored one? The VM
/// requires the stated values to match the stored fact.
///
/// A stated value passes when it is the same field of the same fact,
/// read by a query, filtered on by a fact literal, checked equal to such
/// a value, or returned by a helper. An `update` or `delete` of a fact
/// that may be this one forgets all of these.
fn values_proven(st: &mut PathState<'_>, fact: &FactLiteral, pat: &FactPattern) -> bool {
    let Some(values) = &fact.value_fields else {
        return true;
    };
    let view = st.view();
    let pat = view.pattern(pat);
    values.iter().all(|(field, expr)| {
        let expr = resolve(st, expr);
        stored_refs(st, &expr)
            .iter()
            .any(|(p, f)| (*f == field.inner) & same_pattern(&view.pattern(p), &pat))
    })
}

/// What a fact literal matching implies: its fact exists, and when the
/// literal names the whole key, its stored values are the ones the
/// literal filters on.
fn exists_with_values(fact: &FactLiteral, pat: FactPattern, st: &PathState<'_>) -> Know {
    let whole = pat.keys.len() == st.az.key_count(&pat.name.inner);
    let mut facts: Facts = fact
        .value_fields
        .iter()
        .flatten()
        .filter(|_| whole)
        .map(|(field, value)| {
            let entry = value_entry(&pat, &field.inner, value.clone());
            (entry, FactState::Exists)
        })
        .collect();
    facts.push((pat, FactState::Exists));
    Some(facts)
}

/// A value entry: `pat`, a whole key, exists with `value` as its stored
/// `field`.
fn value_entry(pat: &FactPattern, field: &Identifier, value: Expression) -> FactPattern {
    let mut entry = pat.clone();
    entry.keys.push((field.clone(), value));
    entry
}

/// Split a value entry into its fact's pattern, the field, and the value.
/// Any other pattern isn't a value entry.
fn value_of<'p>(
    entry: &'p FactPattern,
    az: &Analyzer,
) -> Option<(FactPattern, &'p Identifier, &'p Expression)> {
    let ((field, value), keys) = entry.keys.split_last()?;
    let pat = FactPattern {
        keys: keys.to_vec(),
        ..entry.clone()
    };
    (keys.len() == az.key_count(&entry.name.inner)).then_some((pat, field, value))
}

/// The stored values `expr` is known to equal: for each, the fact it was
/// read from and the value field. `expr` may be a value field of a
/// variable bound to a query, a call to a helper whose every exit
/// returns the same stored value, or a value the path knows equals one.
fn stored_refs(st: &mut PathState<'_>, expr: &Expression) -> Vec<(FactPattern, Identifier)> {
    let read = match &expr.kind {
        ExprKind::Dot(base, field) => match &base.kind {
            ExprKind::Identifier(var) => bound_value(st, &var.inner, &field.inner),
            _ => None,
        },
        ExprKind::FunctionCall(fc) => call_returns_value(st, fc),
        _ => None,
    };
    let view = st.view();
    let expr = view.expr(expr);
    let known = st.facts.iter().filter_map(|(entry, _)| {
        let (pat, field, value) = value_of(entry, st.az)?;
        matches_expr(&view.expr(value), &expr).then(|| (pat, field.clone()))
    });
    read.into_iter().chain(known).collect()
}

/// `var.field`, when `var` holds a fact read by a query and `field` is
/// one of its values.
fn bound_value(
    st: &PathState<'_>,
    var: &Identifier,
    field: &Identifier,
) -> Option<(FactPattern, Identifier)> {
    let (_, pat) = st.query_bindings.iter().find(|(v, _)| v == var)?;
    (!st.az.is_key(&pat.name.inner, field)).then(|| (pat.clone(), field.clone()))
}

/// The stored value a call to a pure function returns, in the caller's
/// terms, when every exit returns the same one.
fn call_returns_value(
    st: &mut PathState<'_>,
    fc: &FunctionCall,
) -> Option<(FactPattern, Identifier)> {
    let summary = st
        .az
        .summary(&fc.identifier.inner)
        .filter(|s| s.params.len() == fc.arguments.len())?;
    let map: BTreeMap<Identifier, Expression> = summary
        .params
        .iter()
        .cloned()
        .zip(fc.arguments.iter().cloned())
        .collect();
    let mut found: Option<(FactPattern, Identifier)> = None;
    for exit in &summary.exits {
        let (pat, field) = exit.value.as_ref()?;
        let pat = subst_pattern(pat, &map, &st.az.globals)?;
        let differs = found
            .as_ref()
            .is_some_and(|(prev, f)| (f != field) | !same_pattern(prev, &pat));
        if differs {
            return None;
        }
        found = Some((pat, field.clone()));
    }
    found
}

/// What `a == b` implies about stored values: whatever stored value one
/// side equals, the other equals too.
fn equal_values(st: &mut PathState<'_>, a: &Expression, b: &Expression) -> Know {
    let mut facts = Vec::new();
    for (side, other) in [(a, b), (b, a)] {
        for (pat, field) in stored_refs(st, side) {
            facts.push((value_entry(&pat, &field, other.clone()), FactState::Exists));
        }
    }
    Some(facts)
}

/// Does an `update` state some of its fact's values but not all? The VM
/// compares the stated values with the whole stored value list, so such
/// an update always fails. A value bound with `?` is dropped when
/// lowering, so it shows up as missing.
fn partially_stated(st: &PathState<'_>, fact: &FactLiteral) -> bool {
    let stated = fact.value_fields.as_ref().map_or(0, Vec::len);
    let total = st
        .az
        .facts
        .get(&fact.identifier.inner)
        .map_or(0, |schema| schema.values);
    stated > 0 && stated < total
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

/// Notes for the points where the analysis lost track of the same fact.
fn opaque_notes(pat: &FactPattern, opaque: &[OpaquePoint]) -> Vec<(Span, String)> {
    opaque
        .iter()
        .filter(|(name, _, _)| *name == pat.name)
        .map(|(name, span, why)| {
            let note = match why {
                Why::TooComplex => format!("touches `{name}` but is too complex to analyze"),
                Why::Joined => format!("paths were joined here, dropping facts about `{name}`"),
            };
            (*span, note)
        })
        .collect()
}

/// `footnotes`, plus a note when a join dropped facts about `pat`'s fact
/// on the way here. The warning may then come from the join rather than
/// from the policy.
fn with_join_note(
    mut footnotes: Vec<(Footnote, String)>,
    pat: &FactPattern,
    opaque: &[OpaquePoint],
) -> Vec<(Footnote, String)> {
    let joined = opaque
        .iter()
        .any(|(name, _, why)| (*name == pat.name) & (*why == Why::Joined));
    footnotes.extend(joined.then(|| {
        (
            Footnote::Note,
            "paths were joined on the way here, dropping facts about this one, so this \
             warning may be a false positive. Raising the limit with `--max-paths` will tell"
                .to_owned(),
        )
    }));
    footnotes
}

fn unproven_create(span: Span, pat: &FactPattern, opaque: &[OpaquePoint]) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!("cannot prove `{}` does not exist before `create`", pat.text),
        label: "this fact may already exist".to_owned(),
        notes: opaque_notes(pat, opaque),
        footnotes: with_join_note(
            vec![
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
            pat,
            opaque,
        ),
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
    if st.known_absent(pat) {
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
        footnotes: with_join_note(footnotes, pat, &st.opaque),
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
        footnotes: with_join_note(
            vec![
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
            pat,
            &st.opaque,
        ),
    }
}

fn partial_values(span: Span, pat: &FactPattern) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!(
            "the stated values of `{}` can never match the stored fact",
            pat.text
        ),
        label: "this update always fails".to_owned(),
        notes: Vec::new(),
        footnotes: vec![
            (
                Footnote::Note,
                "`update` compares the stated values with every stored value, \
                 so leaving any of them as `?` always fails"
                    .to_owned(),
            ),
            (
                Footnote::Help,
                "state every value, or bind all of them with `?` to skip the comparison".to_owned(),
            ),
        ],
    }
}

fn paths_joined(site: Span, max: usize, dropped: &[Ident]) -> ObligationWarning {
    let facts = match dropped {
        [] => "facts".to_owned(),
        names => {
            let names: Vec<String> = names.iter().map(|name| format!("`{name}`")).collect();
            format!("facts about {}", names.join(", "))
        }
    };
    ObligationWarning {
        span: site,
        message: format!("paths were joined here, dropping {facts} that only some of them knew"),
        label: format!("more than {max} distinct paths leave this branch"),
        notes: Vec::new(),
        footnotes: vec![
            (
                Footnote::Note,
                format!(
                    "the analysis keeps at most {max} distinct paths at one point. Past that \
                     it joins them and keeps only what all of them know, so a later warning \
                     about these facts may be a false positive"
                ),
            ),
            (
                Footnote::Help,
                "raise the limit with `--max-paths` or `Compiler::max_paths`".to_owned(),
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
fn observe_let<'a>(st: &mut PathState<'a>, stmt: &LetStatement, out: &mut Out) -> bool {
    let var = stmt.identifier.inner.clone();
    if let ExprKind::Coalesce(lhs, rhs) = &stmt.expression.kind
        && matches!(rhs.vtype.inner, TypeKind::Never)
    {
        let lhs = resolve(st, lhs);
        let (mut when_some, when_none) = cond_is(st, &lhs, true, out);
        terminal_branch(st, when_none, rhs, out);
        // The compiler forbids shadowing, so `lhs` can't mention `var`.
        st.forget_name(&var);
        if let Some(fact) = query_of(st, &lhs) {
            let full = full_key_pattern(&pattern_raw(&fact, st), &var, st);
            when_some = both(when_some, exists_with_values(&fact, full.clone(), st));
            st.bind_query(var, full);
        }
        return st.assume(when_some);
    }
    st.forget_name(&var);
    let value = resolve(st, &stmt.expression);
    if is_substitutable(&stmt.expression) {
        let calls = call_facts(st, &value, out);
        st.env.insert(var, value);
        return st.assume(calls);
    }
    // The value of an `if`, `match`, or block is unknown, but the path
    // knows what holds when some arm produced it.
    if let Some((produced, _)) = branch_cond(st, &value, out, &mut |st, e, out| {
        let calls = call_facts(st, e, out);
        collect_opaque(st, e);
        (calls.clone(), calls)
    }) {
        let mut know = produced;
        if let Some(fact) = match_returns_query(st, &value) {
            let full = full_key_pattern(&pattern_raw(&fact, st), &var, st);
            know = both(know, exists_with_values(&fact, full.clone(), st));
            st.bind_query(var, full);
        }
        return st.assume(know);
    }
    let calls = call_facts(st, &value, out);
    collect_opaque(st, &value);
    st.assume(calls)
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
            .map(|(name, expr)| (name.inner.clone(), linked(st, resolve(st, expr))))
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
            .map(|(name, expr)| (name.inner.clone(), linked(st, expr.clone())))
            .collect(),
        span: fact.span(),
        text: fact_text(fact, &st.az.src),
    }
}

/// `key`, or the key a query gave, when `key` reads it from the query's
/// result. `key` is in the path's terms, so a name in it is one the path
/// bound, and a finish function's parameter has already been replaced by
/// the caller's argument.
fn linked(st: &PathState<'_>, key: Expression) -> Expression {
    if let ExprKind::Dot(base, field) = &key.kind
        && let ExprKind::Identifier(var) = &base.kind
        && let Some(given) = st.key_links.get(&(var.inner.clone(), field.inner.clone()))
    {
        return given.clone();
    }
    key
}

/// The pattern of the one fact `var` holds after it is bound to the
/// result of a query with `prefix`'s keys: those keys, followed by
/// `var.<key>` for each remaining key field of the schema.
fn full_key_pattern(prefix: &FactPattern, var: &Identifier, st: &PathState<'_>) -> FactPattern {
    let mut keys = prefix.keys.clone();
    let schema = st.az.facts.get(&prefix.name.inner).map(|s| &s.keys);
    for (key, ty) in schema.into_iter().flatten().skip(keys.len()) {
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

/// Does `pred` hold for `expr` or any expression inside it, including
/// inside the statements of a block expression?
fn any_sub(expr: &Expression, pred: &mut impl FnMut(&Expression) -> bool) -> bool {
    let mut found = false;
    visit_expr(expr, &mut |node| {
        found |= node.expr().is_some_and(&mut *pred);
    });
    found
}

/// A statement or an expression, for [`visit_stmts`] and [`visit_expr`].
#[derive(Clone, Copy)]
enum Node<'n> {
    Stmt(&'n Statement),
    Expr(&'n Expression),
}

impl<'n> Node<'n> {
    fn expr(self) -> Option<&'n Expression> {
        match self {
            Self::Expr(e) => Some(e),
            Self::Stmt(_) => None,
        }
    }
}

/// Call `f` on every statement and expression in `stmts`, at any depth:
/// nested statement bodies, block expressions, fact literals, and `match`
/// patterns included.
fn visit_stmts<'n>(stmts: &'n [Statement], f: &mut impl FnMut(Node<'n>)) {
    for stmt in stmts {
        f(Node::Stmt(stmt));
        match &stmt.kind {
            StmtKind::Let(l) => visit_expr(&l.expression, f),
            StmtKind::Check(c) => {
                visit_expr(&c.expression, f);
                visit_expr(&c.else_expression, f);
            }
            StmtKind::If(ifs) => {
                for (cond, body) in &ifs.branches {
                    visit_expr(cond, f);
                    visit_stmts(body, f);
                }
                if let Some(body) = &ifs.fallback {
                    visit_stmts(body, f);
                }
            }
            StmtKind::Match(m) => {
                visit_expr(&m.expression, f);
                for arm in &m.arms {
                    visit_pattern(&arm.pattern, f);
                    visit_stmts(&arm.statements, f);
                }
            }
            StmtKind::Map(m) => {
                visit_fact(&m.fact, f);
                visit_stmts(&m.statements, f);
            }
            StmtKind::Finish(body) => visit_stmts(body, f),
            StmtKind::Return(r) => visit_expr(&r.expression, f),
            StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
                visit_expr(e, f);
            }
            StmtKind::ActionCall(c) | StmtKind::FunctionCall(c) => {
                for e in &c.arguments {
                    visit_expr(e, f);
                }
            }
            StmtKind::Create(c) => visit_fact(&c.fact, f),
            StmtKind::Update(u) => {
                visit_fact(&u.fact, f);
                for (_, e) in &u.to {
                    visit_expr(e, f);
                }
            }
            StmtKind::Delete(d) => visit_fact(&d.fact, f),
            StmtKind::Recall(r) => {
                for e in &r.arguments {
                    visit_expr(e, f);
                }
            }
        }
    }
}

/// [`visit_stmts`] for one expression.
fn visit_expr<'n>(expr: &'n Expression, f: &mut impl FnMut(Node<'n>)) {
    f(Node::Expr(expr));
    match &expr.kind {
        ExprKind::Identifier(_)
        | ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::EnumReference(_) => {}
        ExprKind::Optional(inner) => {
            if let Some(e) = inner {
                visit_expr(e, f);
            }
        }
        ExprKind::NamedStruct(s) => {
            for (_, e) in &s.fields {
                visit_expr(e, f);
            }
        }
        ExprKind::InternalFunction(func) => match func {
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact) => visit_fact(fact, f),
            InternalFunction::If(c, t, e) => {
                visit_expr(c, f);
                visit_expr(t, f);
                visit_expr(e, f);
            }
            InternalFunction::Todo(_) | InternalFunction::TestFail(..) => {}
        },
        ExprKind::FunctionCall(c) => {
            for e in &c.arguments {
                visit_expr(e, f);
            }
        }
        ExprKind::ForeignFunctionCall(c) => {
            for e in &c.arguments {
                visit_expr(e, f);
            }
        }
        ExprKind::Recall(c) => {
            for e in &c.arguments {
                visit_expr(e, f);
            }
        }
        ExprKind::Return(e)
        | ExprKind::Not(e)
        | ExprKind::Is(e, _)
        | ExprKind::Dot(e, _)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e) => visit_expr(e, f),
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Coalesce(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => {
            visit_expr(a, f);
            visit_expr(b, f);
        }
        ExprKind::Block(stmts, e) => {
            visit_stmts(stmts, f);
            visit_expr(e, f);
        }
        ExprKind::Match(m) => {
            visit_expr(&m.scrutinee, f);
            for arm in &m.arms {
                visit_pattern(&arm.pattern, f);
                visit_expr(&arm.expression, f);
            }
        }
    }
}

/// [`visit_stmts`] for the key and value fields of a fact literal.
fn visit_fact<'n>(fact: &'n FactLiteral, f: &mut impl FnMut(Node<'n>)) {
    for (_, e) in &fact.key_fields {
        visit_expr(e, f);
    }
    for (_, e) in fact.value_fields.iter().flatten() {
        visit_expr(e, f);
    }
}

/// [`visit_stmts`] for the values of a `match` pattern.
fn visit_pattern<'n>(pattern: &'n MatchPattern, f: &mut impl FnMut(Node<'n>)) {
    if let MatchPattern::Values(values) = pattern {
        for v in values {
            visit_expr(v, f);
        }
    }
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
/// be bound by an enclosing block or `match` arm, and struct composition
/// is rejected. A substitution that would move a value into a block or
/// arm that binds a name the value mentions is refused too, since that
/// name would then refer to the block's or arm's binding. Returns `None`
/// if any of these fails. Without `strict`, other names are kept as they
/// are.
fn subst(
    expr: &Expression,
    env: &BTreeMap<Identifier, Expression>,
    strict: Option<&[Identifier]>,
) -> Option<Expression> {
    let sub = Subst {
        env,
        strict,
        aliases: &[],
    };
    let mut expr = expr.clone();
    rewrite(&mut expr, &sub, &mut Vec::new()).then_some(expr)
}

/// What [`rewrite`] substitutes, and what it requires.
struct Subst<'s> {
    /// Values for names.
    env: &'s BTreeMap<Identifier, Expression>,
    /// With `Some`, every other name must be one of these globals. See
    /// [`subst`].
    strict: Option<&'s [Identifier]>,
    /// Values known equal to others, each written as the other: `(from,
    /// to)`. Each `to` is already written this way.
    aliases: &'s [(Expression, Expression)],
}

/// [`subst`] in place. `binders` holds the names bound by the blocks and
/// arms of the expression being rewritten that enclose `expr`.
fn rewrite(expr: &mut Expression, sub: &Subst<'_>, binders: &mut Vec<Identifier>) -> bool {
    if !rewrite_parts(expr, sub, binders) {
        return false;
    }
    // A value known equal to another is written as that one, unless the
    // expression binds a name either mentions.
    let alias = sub.aliases.iter().find(|(from, to)| {
        matches_expr(expr, from) & !binders.iter().any(|b| mentions(from, b) | mentions(to, b))
    });
    if let Some((_, to)) = alias {
        *expr = to.clone();
    }
    true
}

/// [`rewrite`] for `expr` and the expressions inside it, before any alias
/// for `expr` itself.
fn rewrite_parts(expr: &mut Expression, sub: &Subst<'_>, binders: &mut Vec<Identifier>) -> bool {
    if let ExprKind::Identifier(id) = &expr.kind {
        // A name bound by an enclosing block or arm refers to that binding.
        if binders.contains(&id.inner) {
            return true;
        }
        if let Some(value) = sub.env.get(&id.inner) {
            if binders.iter().any(|b| mentions(value, b)) {
                return false;
            }
            *expr = value.clone();
            return true;
        }
        return sub.strict.is_none_or(|globals| globals.contains(&id.inner));
    }
    match &mut expr.kind {
        ExprKind::Identifier(_)
        | ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::EnumReference(_) => true,
        ExprKind::Optional(inner) => inner.as_mut().is_none_or(|e| rewrite(e, sub, binders)),
        ExprKind::NamedStruct(s) => {
            (sub.strict.is_none() || s.sources.is_empty())
                && s.fields.iter_mut().all(|(_, e)| rewrite(e, sub, binders))
        }
        ExprKind::InternalFunction(func) => match func {
            InternalFunction::Query(fact)
            | InternalFunction::Exists(fact)
            | InternalFunction::FactCount(_, _, fact) => rewrite_fact(fact, sub, binders),
            InternalFunction::If(c, t, e) => {
                rewrite(c, sub, binders) && rewrite(t, sub, binders) && rewrite(e, sub, binders)
            }
            InternalFunction::Todo(_) | InternalFunction::TestFail(..) => true,
        },
        ExprKind::FunctionCall(c) => c.arguments.iter_mut().all(|e| rewrite(e, sub, binders)),
        ExprKind::ForeignFunctionCall(c) => {
            c.arguments.iter_mut().all(|e| rewrite(e, sub, binders))
        }
        ExprKind::Recall(c) => c.arguments.iter_mut().all(|e| rewrite(e, sub, binders)),
        // A field read from a struct literal is that field's value. The
        // typed tree lists every field of a literal, including those
        // taken from a struct it was composed from.
        ExprKind::Dot(base, field) => {
            if !rewrite(base, sub, binders) {
                return false;
            }
            let value = match &base.kind {
                ExprKind::NamedStruct(s) => s
                    .fields
                    .iter()
                    .find(|(name, _)| name.inner == field.inner)
                    .map(|(_, value)| value.clone()),
                _ => None,
            };
            if let Some(value) = value {
                *expr = value;
            }
            true
        }
        ExprKind::Return(e)
        | ExprKind::Not(e)
        | ExprKind::Is(e, _)
        | ExprKind::Substruct(e, _)
        | ExprKind::Cast(e, _)
        | ExprKind::Ok(e)
        | ExprKind::Err(e) => rewrite(e, sub, binders),
        ExprKind::And(a, b)
        | ExprKind::Or(a, b)
        | ExprKind::Coalesce(a, b)
        | ExprKind::Equal(a, b)
        | ExprKind::NotEqual(a, b)
        | ExprKind::GreaterThan(a, b)
        | ExprKind::LessThan(a, b)
        | ExprKind::GreaterThanOrEqual(a, b)
        | ExprKind::LessThanOrEqual(a, b) => rewrite(a, sub, binders) && rewrite(b, sub, binders),
        ExprKind::Block(stmts, e) => {
            let depth = binders.len();
            binders.extend(bound_names(stmts));
            let ok = rewrite_stmts(stmts, sub, binders) && rewrite(e, sub, binders);
            binders.truncate(depth);
            ok
        }
        ExprKind::Match(m) => {
            rewrite(&mut m.scrutinee, sub, binders)
                && m.arms.iter_mut().all(|arm| {
                    let depth = binders.len();
                    binders.extend(arm_names(&arm.pattern));
                    let ok = rewrite(&mut arm.expression, sub, binders);
                    binders.truncate(depth);
                    ok
                })
        }
    }
}

/// [`rewrite`] for the expressions in the statements of a block
/// expression.
fn rewrite_stmts(stmts: &mut [Statement], sub: &Subst<'_>, binders: &mut Vec<Identifier>) -> bool {
    stmts.iter_mut().all(|stmt| match &mut stmt.kind {
        StmtKind::Let(l) => rewrite(&mut l.expression, sub, binders),
        StmtKind::Check(c) => {
            rewrite(&mut c.expression, sub, binders)
                && rewrite(&mut c.else_expression, sub, binders)
        }
        StmtKind::If(ifs) => {
            ifs.branches
                .iter_mut()
                .all(|(c, body)| rewrite(c, sub, binders) && rewrite_stmts(body, sub, binders))
                && ifs
                    .fallback
                    .as_mut()
                    .is_none_or(|body| rewrite_stmts(body, sub, binders))
        }
        StmtKind::Match(m) => {
            rewrite(&mut m.expression, sub, binders)
                && m.arms
                    .iter_mut()
                    .all(|arm| rewrite_stmts(&mut arm.statements, sub, binders))
        }
        // `map` is only allowed in actions, which are never rewritten.
        StmtKind::Map(_) => false,
        StmtKind::Finish(body) => rewrite_stmts(body, sub, binders),
        StmtKind::Return(r) => rewrite(&mut r.expression, sub, binders),
        StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
            rewrite(e, sub, binders)
        }
        StmtKind::ActionCall(c) | StmtKind::FunctionCall(c) => {
            c.arguments.iter_mut().all(|e| rewrite(e, sub, binders))
        }
        StmtKind::Create(c) => rewrite_fact(&mut c.fact, sub, binders),
        // A finish block is never rewritten under `strict`, so neither
        // part can fail; `&` says so without a short circuit.
        StmtKind::Update(u) => {
            rewrite_fact(&mut u.fact, sub, binders)
                & u.to.iter_mut().all(|(_, e)| rewrite(e, sub, binders))
        }
        StmtKind::Delete(d) => rewrite_fact(&mut d.fact, sub, binders),
        StmtKind::Recall(r) => r.arguments.iter_mut().all(|e| rewrite(e, sub, binders)),
    })
}

fn rewrite_fact(fact: &mut FactLiteral, sub: &Subst<'_>, binders: &mut Vec<Identifier>) -> bool {
    fact.key_fields
        .iter_mut()
        .all(|(_, e)| rewrite(e, sub, binders))
        && fact
            .value_fields
            .as_mut()
            .is_none_or(|values| values.iter_mut().all(|(_, e)| rewrite(e, sub, binders)))
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
        ExprKind::NamedStruct(s) => s.fields.iter().all(|(_, e)| is_substitutable(e)),
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

/// A fact mutation, for [`apply_change`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Change {
    Create,
    Update,
    Delete,
}

/// Record a mutation's postcondition. What the path knows about a fact
/// that provably differs from the mutated one is kept. Of what it knows
/// about one that may be the same:
///
/// - a `create` keeps everything. Creating a fact removes none, and where
///   a fact the path knew existed was the one created, the `create`
///   raised an exception;
/// - a `delete` keeps only absence, since it may remove the fact;
/// - an `update` keeps only absence too. The fact still exists, but its
///   values may have changed, and mutating it again in the same finish
///   block is an exception that the touched set only catches for
///   identical keys. Forgetting that it exists keeps a second mutation
///   of a fact that may be the same one from being proven.
///
/// A `create` or `update` may make a fact exist where the path knew it
/// absent. Recording it in `mutated` limits that absence to the facts
/// that provably differ from it.
fn apply_change(st: &mut PathState<'_>, pat: FactPattern, change: Change) {
    let view = st.view();
    let written = view.pattern(&pat);
    let written = written.into_owned();
    let differing = view.differing(&st.facts).into_owned();
    let differs = |p: &FactPattern| differ(&differing, &view.pattern(p), &written);
    st.facts.retain(|(p, s)| {
        let kept = match change {
            Change::Create => true,
            Change::Update | Change::Delete => *s != FactState::Exists,
        };
        kept | differs(p)
    });
    if change != Change::Create {
        st.query_bindings.retain(|(_, p)| differs(p));
    }
    let state = if change == Change::Delete {
        FactState::NotExists
    } else {
        st.mutated.push(pat.clone());
        FactState::Exists
    };
    observe(st, pat, state);
}

/// Can `p` and `q` never be the same fact? True for different facts, and
/// for keys where both give literals that differ, or values `known` says
/// differ.
fn differ(known: &Facts, p: &FactPattern, q: &FactPattern) -> bool {
    p.name != q.name
        || p.keys
            .iter()
            .zip(&q.keys)
            .any(|((_, a), (_, b))| literals_differ(a, b) | known_unequal(known, a, b))
}

/// Does `known` say that `a` and `b` hold different values?
fn known_unequal(known: &Facts, a: &Expression, b: &Expression) -> bool {
    known.iter().any(|(p, s)| {
        let values = p.keys.iter().map(|(_, e)| e);
        (*s == FactState::Differ)
            & (p.keys.len() == 2)
            & values.zip([a, b]).all(|(x, y)| matches_expr(x, y))
    })
}

/// What `a` and `b` differing says: an entry for each order, so a lookup
/// needs only one. The same expression can't differ from itself, so that
/// is impossible.
fn unequal(a: &Expression, b: &Expression) -> Know {
    if matches_expr(a, b) {
        return None;
    }
    Some(vec![
        (pair_entry(a, b), FactState::Differ),
        (pair_entry(b, a), FactState::Differ),
    ])
}

/// What `a == b` holding says. Whether that is possible is decided when a
/// path takes it on: see [`PathState::equate`].
fn same(a: &Expression, b: &Expression) -> Know {
    Some(vec![(pair_entry(a, b), FactState::Same)])
}

/// The name of entries relating two values. No fact can be named `fact`,
/// a keyword, so these entries never meet a real one.
fn pair_name() -> Ident {
    Ident::new(ident!("fact"), Span::empty())
}

/// An entry relating two values, for [`FactState::Differ`] and
/// [`FactState::Same`].
fn pair_entry(a: &Expression, b: &Expression) -> FactPattern {
    FactPattern {
        name: pair_name(),
        keys: vec![(ident!("fact"), a.clone()), (ident!("fact"), b.clone())],
        span: Span::empty(),
        text: String::new(),
    }
}

/// The two values a pair entry relates, once.
fn pair_values(p: &FactPattern) -> impl Iterator<Item = (&Expression, &Expression)> {
    p.keys
        .iter()
        .zip(p.keys.iter().skip(1))
        .map(|((_, a), (_, b))| (a, b))
}

/// How many expressions `e` is made of.
fn size(e: &Expression) -> usize {
    let mut n = 0usize;
    visit_expr(e, &mut |_| n = n.saturating_add(1));
    n
}

/// Is `e` a literal?
fn is_literal(e: &Expression) -> bool {
    matches!(
        e.kind,
        ExprKind::Unit
            | ExprKind::Int(_)
            | ExprKind::String(_)
            | ExprKind::Bool(_)
            | ExprKind::EnumReference(_)
    )
}

/// How briefly `e` names one value, for choosing which side of an
/// equality the path keeps. A literal always names the same value. An
/// expression over `this`, `envelope`, and globals does for the whole
/// block. One over another name does only until the name is bound again.
fn transience(e: &Expression, globals: &[Identifier]) -> u8 {
    let lasting = [ident!("this"), ident!("envelope")];
    let local = any_sub(e, &mut |n| match &n.kind {
        ExprKind::Identifier(id) => !(lasting.contains(&id.inner) | globals.contains(&id.inner)),
        _ => false,
    });
    if is_literal(e) {
        0
    } else if local {
        2
    } else {
        1
    }
}

/// Are `a` and `b` literals with different values?
fn literals_differ(a: &Expression, b: &Expression) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Int(x), ExprKind::Int(y)) => x != y,
        (ExprKind::String(x), ExprKind::String(y)) => x != y,
        (ExprKind::Bool(x), ExprKind::Bool(y)) => x != y,
        (ExprKind::EnumReference(x), ExprKind::EnumReference(y)) => {
            (&x.identifier, &x.value) != (&y.identifier, &y.value)
        }
        _ => false,
    }
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
            .all(|((_, e1), (_, e2))| matches_expr(e1, e2))
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
        // The key's type makes the enum names agree.
        (ExprKind::EnumReference(x), ExprKind::EnumReference(y)) => {
            (&x.identifier, &x.value) == (&y.identifier, &y.value)
        }
        (ExprKind::Dot(b1, f1), ExprKind::Dot(b2, f2)) => f1 == f2 && matches_expr(b1, b2),
        // Pure functions are deterministic and fact state cannot change
        // between policy statements, so equal calls yield equal values.
        (ExprKind::FunctionCall(f1), ExprKind::FunctionCall(f2)) => {
            f1.identifier == f2.identifier
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
fn collect_opaque(st: &mut PathState<'_>, expr: &Expression) {
    visit_facts(expr, &mut |fact, span| {
        st.lose_track(fact.identifier.clone(), span, Why::TooComplex);
    });
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
