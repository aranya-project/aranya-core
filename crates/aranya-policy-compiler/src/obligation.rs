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

use std::collections::BTreeMap;

use annotate_snippets::{AnnotationKind, Level, Renderer, Snippet};
use aranya_policy_ast::{
    Ident, Identifier, Span, Spanned as _, TypeKind,
    thir::{
        ExprKind, Expression, FactLiteral, InternalFunction, LetStatement, Statement, StmtKind,
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

/// Analysis state along a single control-flow path.
#[derive(Debug, Clone)]
struct PathState<'a> {
    /// The full policy source text, for diagnostics.
    src: &'a str,
    facts: Vec<(FactPattern, FactState)>,
    /// `let`-bound names with simple (substitutable) values.
    env: BTreeMap<Identifier, Expression>,
    /// Fact-touching expressions the extractor could not interpret.
    opaque: Vec<(Ident, Span)>,
    /// The fact database is known to be empty at the start of the block
    /// (an `init` command), except for facts named in `dirty`.
    empty_db: bool,
    /// Facts that may have been mutated since the block started.
    dirty: Vec<Identifier>,
    /// Variables bound by `let x = query F[..] or <terminal>`, with the
    /// fact they hold. Used to prove an `update`'s stated values match
    /// the stored fact.
    query_bindings: Vec<(Identifier, FactPattern)>,
    /// Finish function bodies, for following mutations through calls.
    functions: &'a FinishFunctions,
}

/// The lowered body of a finish function.
#[derive(Debug, Clone)]
pub(crate) struct FinishFunctionBody {
    /// Parameter names, in order.
    pub(crate) params: Vec<Identifier>,
    /// The function's statements.
    pub(crate) statements: Vec<Statement>,
}

/// Finish function bodies by name.
pub(crate) type FinishFunctions = BTreeMap<Identifier, FinishFunctionBody>;

impl PathState<'_> {
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
}

/// Analyze the lowered statements of a command `policy` or `recall` block.
///
/// `src` is the full policy source text. `empty_db` is true for the
/// blocks of an `init` command, which always runs against an empty fact
/// database: the runtime only accepts an init command as the root of the
/// graph. `functions` holds the finish functions the block may call;
/// their mutations are checked at each call site.
pub(crate) fn analyze_block(
    stmts: &[Statement],
    src: &str,
    empty_db: bool,
    functions: &FinishFunctions,
) -> Vec<ObligationWarning> {
    let st = PathState {
        src,
        facts: Vec::new(),
        env: BTreeMap::new(),
        opaque: Vec::new(),
        empty_db,
        dirty: Vec::new(),
        query_bindings: Vec::new(),
        functions,
    };
    let mut warnings = Vec::new();
    walk(stmts, &[], st, &mut warnings);
    dedup_warnings(warnings)
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
fn walk(
    stmts: &[Statement],
    cont: &[&[Statement]],
    mut st: PathState<'_>,
    warnings: &mut Vec<ObligationWarning>,
) {
    let mut remaining = stmts;
    while let Some((stmt, rest)) = remaining.split_first() {
        match &stmt.kind {
            StmtKind::Let(l) => observe_let(&mut st, l),
            StmtKind::Check(c) => observe_check(&mut st, &c.expression),
            StmtKind::If(ifs) => {
                let mut next: Vec<&[Statement]> = Vec::new();
                next.push(rest);
                next.extend_from_slice(cont);
                for (cond, body) in &ifs.branches {
                    let mut branch_st = st.clone();
                    collect_opaque(&mut branch_st, cond);
                    walk(body, &next, branch_st, warnings);
                }
                let mut fallback_st = st;
                for (cond, _) in &ifs.branches {
                    collect_opaque(&mut fallback_st, cond);
                }
                match &ifs.fallback {
                    Some(body) => walk(body, &next, fallback_st, warnings),
                    None => walk(rest, cont, fallback_st, warnings),
                }
                return;
            }
            StmtKind::Match(m) => {
                let mut next: Vec<&[Statement]> = Vec::new();
                next.push(rest);
                next.extend_from_slice(cont);
                collect_opaque(&mut st, &m.expression);
                for arm in &m.arms {
                    walk(&arm.statements, &next, st.clone(), warnings);
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
                walk(&m.statements, &[], st.clone(), warnings);
            }
            StmtKind::Finish(fstmts) => {
                analyze_finish(fstmts, &mut st, warnings);
                // A finish block terminates policy execution.
                return;
            }
            StmtKind::Emit(e) | StmtKind::Publish(e) | StmtKind::DebugAssert(e) => {
                collect_opaque(&mut st, e);
            }
            StmtKind::Return(_) | StmtKind::Recall(_) => return,
            StmtKind::ActionCall(_) | StmtKind::FunctionCall(_) => {}
            // Mutations only appear inside finish contexts, which are
            // handled by `analyze_finish`.
            StmtKind::Create(_) | StmtKind::Update(_) | StmtKind::Delete(_) => {}
        }
        remaining = rest;
    }
    if let Some((first, rest)) = cont.split_first() {
        walk(first, rest, st, warnings);
    }
}

/// Check obligations for the mutations in a finish block.
fn analyze_finish(
    stmts: &[Statement],
    st: &mut PathState<'_>,
    warnings: &mut Vec<ObligationWarning>,
) {
    let mut touched: Vec<FactPattern> = Vec::new();
    let mut calls: Vec<(Identifier, Span)> = Vec::new();
    finish_statements(stmts, st, &mut touched, &mut calls, warnings);
}

/// Check the mutations in a finish block or in a finish function called
/// from one. `touched` is shared by the whole finish block, including the
/// functions it calls. `calls` is the stack of finish function calls that
/// led here, innermost last.
fn finish_statements(
    stmts: &[Statement],
    st: &mut PathState<'_>,
    touched: &mut Vec<FactPattern>,
    calls: &mut Vec<(Identifier, Span)>,
    warnings: &mut Vec<ObligationWarning>,
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
                match st.functions.get(name) {
                    Some(body) if !recursive && body.params.len() == fc.arguments.len() => {
                        // Bind the parameters to the caller's arguments,
                        // so the function's fact keys are expressed in the
                        // caller's terms.
                        let env = body
                            .params
                            .iter()
                            .zip(&fc.arguments)
                            .map(|(p, a)| (p.clone(), substitute(a, &st.env)))
                            .collect();
                        let caller_env = core::mem::replace(&mut st.env, env);
                        calls.push((name.clone(), stmt.span));
                        finish_statements(&body.statements, st, touched, calls, warnings);
                        calls.pop();
                        st.env = caller_env;
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
            warnings.push(w);
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
/// The accepted form is `x.field` for the same `field`, where `x` was bound
/// by `let x = query F[k] or <terminal>` with the same key, and `F` has not
/// been mutated since.
fn values_proven(st: &PathState<'_>, fact: &FactLiteral, pat: &FactPattern) -> bool {
    let Some(values) = &fact.value_fields else {
        return true;
    };
    values.iter().all(|(field, expr)| {
        let expr = substitute(expr, &st.env);
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

/// Extract an observation from a `check` expression's fall-through arm
/// (the else arm is `Never`-typed, so fall-through is the only continuation).
fn observe_check(st: &mut PathState<'_>, expr: &Expression) {
    match &expr.kind {
        ExprKind::Not(inner) => {
            if let ExprKind::InternalFunction(InternalFunction::Exists(fact)) = &inner.kind {
                let pat = pattern_of(fact, st);
                observe(st, pat, FactState::NotExists);
            } else {
                collect_opaque(st, expr);
            }
        }
        ExprKind::InternalFunction(InternalFunction::Exists(fact)) => {
            let pat = pattern_of(fact, st);
            observe(st, pat, FactState::Exists);
        }
        _ => collect_opaque(st, expr),
    }
}

/// Extract an observation or a substitutable binding from a `let`.
fn observe_let(st: &mut PathState<'_>, stmt: &LetStatement) {
    // `let x = query F[..] or <terminal>` proves the fact exists on
    // fall-through.
    if let ExprKind::Coalesce(lhs, rhs) = &stmt.expression.kind
        && matches!(rhs.vtype.inner, TypeKind::Never)
        && let ExprKind::InternalFunction(InternalFunction::Query(fact)) = &lhs.kind
    {
        let pat = pattern_of(fact, st);
        let var = stmt.identifier.inner.clone();
        st.query_bindings.retain(|(v, _)| *v != var);
        st.query_bindings.push((var, pat.clone()));
        observe(st, pat, FactState::Exists);
        return;
    }
    if is_simple(&stmt.expression) {
        let value = substitute(&stmt.expression, &st.env);
        st.env.insert(stmt.identifier.inner.clone(), value);
    } else {
        collect_opaque(st, &stmt.expression);
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

fn pattern_of(fact: &FactLiteral, st: &PathState<'_>) -> FactPattern {
    FactPattern {
        name: fact.identifier.clone(),
        keys: fact
            .key_fields
            .iter()
            .map(|(name, expr)| (name.inner.clone(), substitute(expr, &st.env)))
            .collect(),
        span: fact.span(),
        text: fact_text(fact, st.src),
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

/// Is this expression simple enough to substitute into key patterns?
fn is_simple(expr: &Expression) -> bool {
    match &expr.kind {
        ExprKind::Unit
        | ExprKind::Int(_)
        | ExprKind::String(_)
        | ExprKind::Bool(_)
        | ExprKind::Identifier(_)
        | ExprKind::EnumReference(_) => true,
        ExprKind::Dot(base, _) => is_simple(base),
        _ => false,
    }
}

/// One-step substitution of `let`-bound names, so trivially aliased keys
/// compare equal.
fn substitute(expr: &Expression, env: &BTreeMap<Identifier, Expression>) -> Expression {
    match &expr.kind {
        ExprKind::Identifier(id) => match env.get(&id.inner) {
            Some(replacement) => replacement.clone(),
            None => expr.clone(),
        },
        ExprKind::Dot(base, field) => Expression {
            kind: ExprKind::Dot(Box::new(substitute(base, env)), field.clone()),
            vtype: expr.vtype.clone(),
            span: expr.span,
        },
        _ => expr.clone(),
    }
}

/// Record every fact-touching subexpression as an opaque observation point.
fn collect_opaque(st: &mut PathState<'_>, expr: &Expression) {
    visit_facts(expr, &mut |fact, span| {
        st.opaque.push((fact.identifier.clone(), span));
    });
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
mod tests {
    use aranya_policy_ast::Version;
    use aranya_policy_lang::lang::parse_policy_str;

    use super::ObligationWarning;
    use crate::Compiler;

    #[track_caller]
    fn warnings_for(text: &str) -> Vec<ObligationWarning> {
        let policy = parse_policy_str(text, Version::V2).expect("parse");
        let (_module, warnings) = Compiler::new(&policy)
            .debug(true)
            .allow_baseless(true)
            .analyze_obligations(true)
            .compile_with_diagnostics()
            .expect("compile");
        warnings
    }

    /// Wrap a policy body in a command with the `Account` fact defined.
    fn command(policy_block: &str) -> String {
        format!(
            r#"
            fact Account[user int]=>{{balance int}}

            command Foo {{
                fields {{ user int }}
                policy {{
                    {policy_block}
                }}
                recall failed() {{ finish {{}} }}
            }}
            "#
        )
    }

    #[test]
    fn check_then_create_passes() {
        let warnings = warnings_for(&command(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn create_without_check_warns() {
        let warnings = warnings_for(&command(
            r#"
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(
            warnings[0].message,
            "cannot prove `Account[user: this.user]` does not exist before `create`"
        );
        assert!(warnings[0].notes.is_empty());
    }

    #[test]
    fn check_in_one_branch_warns_on_other_path() {
        let warnings = warnings_for(&command(
            r#"
            if this.user == 1 {
                check !exists Account[user: this.user] else recall failed()
            }
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("cannot prove"));
    }

    #[test]
    fn check_in_all_branches_passes() {
        let warnings = warnings_for(&command(
            r#"
            if this.user == 1 {
                check !exists Account[user: this.user] else recall failed()
            } else {
                check !exists Account[user: this.user] else recall failed()
            }
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn unchecked_on_several_paths_warns_once() {
        let warnings = warnings_for(&command(
            r#"
            if this.user == 1 {
                let a = 1
            } else {
                let b = 2
            }
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("cannot prove"));
    }

    #[test]
    fn duplicate_warnings_merge_notes() {
        let warnings = warnings_for(&command(
            r#"
            if this.user == 1 {
                check !(exists Account[user: this.user] && this.user == 1) else recall failed()
            } else {
                check !(exists Account[user: this.user] || this.user == 2) else recall failed()
            }
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(warnings[0].notes.len(), 2, "notes: {:?}", warnings[0].notes);
    }

    /// Wrap a policy body in an `init: true` command.
    fn init_command(policy_block: &str) -> String {
        format!(
            r#"
            fact Account[user int]=>{{balance int}}
            fact Owner[]=>{{user int}}

            command Init {{
                attributes {{ init: true }}
                fields {{ user int }}
                policy {{
                    {policy_block}
                }}
            }}
            "#
        )
    }

    #[test]
    fn init_command_create_passes() {
        let warnings = warnings_for(&init_command(
            r#"
            finish {
                create Account[user: this.user]=>{balance: 0}
                create Owner[]=>{user: this.user}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn init_command_double_create_warns() {
        let warnings = warnings_for(&init_command(
            r#"
            finish {
                create Account[user: this.user]=>{balance: 0}
                create Account[user: this.user]=>{balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("more than once"));
    }

    #[test]
    fn init_false_is_not_init() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}

            command Foo {
                attributes { init: false }
                fields { user int }
                policy {
                    finish {
                        create Account[user: this.user]=>{balance: 0}
                    }
                }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    }

    #[test]
    fn rendered_warning_shows_label_note_and_help() {
        let text = command(
            r#"
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        );
        let policy = parse_policy_str(&text, Version::V2).expect("parse");
        let (_module, warnings) = Compiler::new(&policy)
            .debug(true)
            .allow_baseless(true)
            .analyze_obligations(true)
            .compile_with_diagnostics()
            .expect("compile");
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        let rendered = warnings[0].render(&text);
        for expected in [
            "warning: cannot prove `Account[user: this.user]` does not exist before `create`",
            "this fact may already exist",
            "note: creating a fact that already exists is a runtime exception",
            "help: check that it does not exist first: `check !exists Account[user: this.user] else ...`",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected:?} in:\n{rendered}"
            );
        }
    }

    #[test]
    fn update_without_check_warns() {
        let warnings = warnings_for(&command(
            r#"
            finish {
                update Account[user: this.user] to {balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(
            warnings[0].message,
            "cannot prove `Account[user: this.user]` exists before `update`"
        );
    }

    #[test]
    fn delete_without_check_warns() {
        let warnings = warnings_for(&command(
            r#"
            finish {
                delete Account[user: this.user]
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(
            warnings[0].message,
            "cannot prove `Account[user: this.user]` exists before `delete`"
        );
    }

    #[test]
    fn check_exists_then_delete_passes() {
        let warnings = warnings_for(&command(
            r#"
            check exists Account[user: this.user] else recall failed()
            finish {
                delete Account[user: this.user]
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn check_not_exists_does_not_prove_exists() {
        let warnings = warnings_for(&command(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                delete Account[user: this.user]
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("exists before `delete`"));
    }

    #[test]
    fn bind_prefix_does_not_prove_exists() {
        let warnings = warnings_for(
            r#"
            fact Grant[user int, perm int]=>{}

            command Foo {
                fields { user int }
                policy {
                    check exists Grant[user: this.user, perm: ?] else recall failed()
                    finish {
                        delete Grant[user: this.user, perm: 3]
                    }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("exists before `delete`"));
    }

    #[test]
    fn update_values_from_query_pass() {
        let warnings = warnings_for(&command(
            r#"
            let account = query Account[user: this.user]=>{balance: ?} or recall failed()
            finish {
                update Account[user: this.user]=>{balance: account.balance} to {balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn update_values_through_let_alias_pass() {
        let warnings = warnings_for(&command(
            r#"
            let account = query Account[user: this.user] or recall failed()
            let old = account.balance
            finish {
                update Account[user: this.user]=>{balance: old} to {balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn update_literal_values_warn() {
        let warnings = warnings_for(&command(
            r#"
            check exists Account[user: this.user] else recall failed()
            finish {
                update Account[user: this.user]=>{balance: 5} to {balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(
            warnings[0].message.contains("stated values"),
            "warnings: {warnings:?}"
        );
    }

    #[test]
    fn update_values_from_query_of_other_fact_warn() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}
            fact Limit[user int]=>{balance int}

            command Foo {
                fields { user int }
                policy {
                    let limit = query Limit[user: this.user] or recall failed()
                    check exists Account[user: this.user] else recall failed()
                    finish {
                        update Account[user: this.user]=>{balance: limit.balance} to {balance: 1}
                    }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("stated values"));
    }

    #[test]
    fn init_command_update_always_fails() {
        let warnings = warnings_for(&init_command(
            r#"
            finish {
                update Account[user: this.user] to {balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(
            warnings[0]
                .footnotes
                .iter()
                .any(|(_, text)| text.contains("always fails")),
            "warnings: {warnings:?}"
        );
    }

    /// A policy with a finish function that creates an `Account`.
    fn with_open_function(policy_block: &str) -> String {
        format!(
            r#"
            fact Account[user int]=>{{balance int}}

            finish function open_account(u int) {{
                create Account[user: u]=>{{balance: 0}}
            }}

            command Foo {{
                fields {{ user int }}
                policy {{
                    {policy_block}
                }}
                recall failed() {{ finish {{}} }}
            }}
            "#
        )
    }

    #[test]
    fn finish_function_create_checked_by_caller_passes() {
        let warnings = warnings_for(&with_open_function(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                open_account(this.user)
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn finish_function_create_unchecked_warns_with_call_note() {
        let warnings = warnings_for(&with_open_function(
            r#"
            finish {
                open_account(this.user)
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(
            warnings[0].message,
            "cannot prove `Account[user: u]` does not exist before `create`"
        );
        assert!(
            warnings[0]
                .notes
                .iter()
                .any(|(_, n)| n == "in this call to `open_account`"),
            "notes: {:?}",
            warnings[0].notes
        );
    }

    #[test]
    fn finish_function_checked_for_other_key_warns() {
        let warnings = warnings_for(&with_open_function(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                open_account(1)
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
    }

    #[test]
    fn finish_function_double_manipulation_across_call() {
        let warnings = warnings_for(&with_open_function(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                create Account[user: this.user]=>{balance: 1}
                open_account(this.user)
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("more than once"));
    }

    #[test]
    fn nested_finish_functions_are_followed() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}

            finish function open_inner(u int) {
                create Account[user: u]=>{balance: 0}
            }

            finish function open_outer(v int) {
                open_inner(v)
            }

            command Foo {
                fields { user int }
                policy {
                    check !exists Account[user: this.user] else recall failed()
                    finish {
                        open_outer(this.user)
                    }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn shared_finish_function_warns_once_with_each_call() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}

            finish function open_account(u int) {
                create Account[user: u]=>{balance: 0}
            }

            command Foo {
                fields { user int }
                policy {
                    finish { open_account(this.user) }
                }
            }

            command Bar {
                fields { user int }
                policy {
                    finish { open_account(this.user) }
                }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        let calls = warnings[0]
            .notes
            .iter()
            .filter(|(_, n)| n.starts_with("in this call"))
            .count();
        assert_eq!(calls, 2, "notes: {:?}", warnings[0].notes);
    }

    #[test]
    fn finish_function_update_uses_caller_query() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}

            finish function set_balance(u int, old int, new int) {
                update Account[user: u]=>{balance: old} to {balance: new}
            }

            command Foo {
                fields { user int }
                policy {
                    let account = query Account[user: this.user] or recall failed()
                    finish {
                        set_balance(this.user, account.balance, 5)
                    }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn recursive_finish_function_warns() {
        let warnings = warnings_for(
            r#"
            fact Account[user int]=>{balance int}

            finish function ping(u int) {
                pong(u)
            }

            finish function pong(u int) {
                create Account[user: u]=>{balance: 0}
                ping(u)
            }

            command Foo {
                fields { user int }
                policy {
                    check !exists Account[user: this.user] else recall failed()
                    finish { ping(this.user) }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert_eq!(
            warnings[0].message,
            "cannot check fact mutations through recursive call to `ping`"
        );
    }

    #[test]
    fn double_create_warns() {
        let warnings = warnings_for(&command(
            r#"
            check !exists Account[user: this.user] else recall failed()
            finish {
                create Account[user: this.user]=>{balance: 0}
                create Account[user: this.user]=>{balance: 1}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("more than once"));
    }

    #[test]
    fn delete_then_create_warns() {
        let warnings = warnings_for(&command(
            r#"
            check exists Account[user: this.user] else recall failed()
            finish {
                delete Account[user: this.user]
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("more than once"));
    }

    #[test]
    fn bind_prefix_subsumes_concrete_key() {
        let warnings = warnings_for(
            r#"
            fact Grant[user int, perm int]=>{}

            command Foo {
                fields { user int }
                policy {
                    check !exists Grant[user: this.user, perm: ?] else recall failed()
                    finish {
                        create Grant[user: this.user, perm: 3]=>{}
                    }
                }
                recall failed() { finish {} }
            }
            "#,
        );
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn let_alias_matches() {
        let warnings = warnings_for(&command(
            r#"
            let uid = this.user
            check !exists Account[user: uid] else recall failed()
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn opaque_check_reported_in_notes() {
        let warnings = warnings_for(&command(
            r#"
            check !(exists Account[user: this.user] && this.user == 1) else recall failed()
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings.len(), 1, "warnings: {warnings:?}");
        assert!(warnings[0].message.contains("cannot prove"));
        assert_eq!(warnings[0].notes.len(), 1, "notes: {:?}", warnings[0].notes);
        assert!(warnings[0].notes[0].1.contains("too complex"));
    }

    #[test]
    fn query_or_recall_then_update_passes() {
        let warnings = warnings_for(&command(
            r#"
            let account = query Account[user: this.user] or recall failed()
            let unused = account.balance
            finish {
                update Account[user: this.user] to {balance: 0}
            }
            "#,
        ));
        assert_eq!(warnings, vec![], "expected no warnings");
    }

    #[test]
    fn disabled_analysis_reports_nothing() {
        let text = command(
            r#"
            finish {
                create Account[user: this.user]=>{balance: 0}
            }
            "#,
        );
        let policy = parse_policy_str(&text, Version::V2).expect("parse");
        let (_module, warnings) = Compiler::new(&policy)
            .debug(true)
            .allow_baseless(true)
            .compile_with_diagnostics()
            .expect("compile");
        assert_eq!(warnings, vec![], "expected no warnings when disabled");
    }
}
