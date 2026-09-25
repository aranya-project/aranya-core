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
    /// The primary warning message.
    pub message: String,
    /// Additional notes, each pointing at a source location.
    pub notes: Vec<(Span, String)>,
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
                .label(self.message.clone())
                .highlight_source(true),
        ];
        for (span, note) in &self.notes {
            annotations.push(
                AnnotationKind::Context
                    .span((*span).into())
                    .label(note.clone()),
            );
        }
        let report = vec![title.element(Snippet::source(input).annotations(annotations))];
        Renderer::plain().render(&report)
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
}

/// Analysis state along a single control-flow path.
#[derive(Debug, Clone, Default)]
struct PathState {
    facts: Vec<(FactPattern, FactState)>,
    /// `let`-bound names with simple (substitutable) values.
    env: BTreeMap<Identifier, Expression>,
    /// Fact-touching expressions the extractor could not interpret.
    opaque: Vec<(Ident, Span)>,
}

/// Analyze the lowered statements of a command `policy` or `recall` block.
pub(crate) fn analyze_block(stmts: &[Statement]) -> Vec<ObligationWarning> {
    let mut warnings = Vec::new();
    walk(stmts, &[], PathState::default(), &mut warnings);
    dedup_warnings(warnings)
}

/// Collapse warnings that differ only in their notes.
///
/// Statements after an `if`/`match` are walked once per path, so a
/// statement reached by several failing paths is reported once per path.
/// Warnings with the same span and message are merged, keeping the first
/// occurrence's position and taking the union of the notes (different
/// paths may have skipped different opaque expressions).
fn dedup_warnings(warnings: Vec<ObligationWarning>) -> Vec<ObligationWarning> {
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
    mut st: PathState,
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
fn analyze_finish(stmts: &[Statement], st: &mut PathState, warnings: &mut Vec<ObligationWarning>) {
    let mut touched: Vec<FactPattern> = Vec::new();
    for stmt in stmts {
        match &stmt.kind {
            StmtKind::Create(c) => {
                let pat = pattern_of(&c.fact, &st.env);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    warnings.push(double_manipulation(stmt.span, &pat, prev));
                } else if !st
                    .facts
                    .iter()
                    .any(|(p, s)| *s == FactState::NotExists && covers(p, &pat))
                {
                    warnings.push(unproven_create(stmt.span, &pat, &st.opaque));
                }
                set_state(st, pat.clone(), FactState::Exists);
                touched.push(pat);
            }
            StmtKind::Update(u) => {
                let pat = pattern_of(&u.fact, &st.env);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    warnings.push(double_manipulation(stmt.span, &pat, prev));
                }
                set_state(st, pat.clone(), FactState::Exists);
                touched.push(pat);
            }
            StmtKind::Delete(d) => {
                let pat = pattern_of(&d.fact, &st.env);
                if let Some(prev) = touched.iter().find(|t| same_pattern(t, &pat)) {
                    warnings.push(double_manipulation(stmt.span, &pat, prev));
                }
                set_state(st, pat.clone(), FactState::NotExists);
                touched.push(pat);
            }
            StmtKind::FunctionCall(_) => {
                // A finish function may mutate any fact.
                st.facts.clear();
            }
            _ => {}
        }
    }
}

fn unproven_create(span: Span, pat: &FactPattern, opaque: &[(Ident, Span)]) -> ObligationWarning {
    let notes = opaque
        .iter()
        .filter(|(name, _)| *name == pat.name)
        .map(|(name, span)| {
            (
                *span,
                format!("this expression touches `{name}` but was too complex to analyze"),
            )
        })
        .collect();
    ObligationWarning {
        span,
        message: format!(
            "cannot prove fact `{}` does not exist before `create`; \
             creating an existing fact is a runtime exception",
            pat.name
        ),
        notes,
    }
}

fn double_manipulation(span: Span, pat: &FactPattern, prev: &FactPattern) -> ObligationWarning {
    ObligationWarning {
        span,
        message: format!(
            "fact `{}` is manipulated more than once in this finish block, \
             which is a runtime exception",
            pat.name
        ),
        notes: vec![(prev.span, "first manipulated here".to_owned())],
    }
}

/// Extract an observation from a `check` expression's fall-through arm
/// (the else arm is `Never`-typed, so fall-through is the only continuation).
fn observe_check(st: &mut PathState, expr: &Expression) {
    match &expr.kind {
        ExprKind::Not(inner) => {
            if let ExprKind::InternalFunction(InternalFunction::Exists(fact)) = &inner.kind {
                let pat = pattern_of(fact, &st.env);
                observe(st, pat, FactState::NotExists);
            } else {
                collect_opaque(st, expr);
            }
        }
        ExprKind::InternalFunction(InternalFunction::Exists(fact)) => {
            let pat = pattern_of(fact, &st.env);
            observe(st, pat, FactState::Exists);
        }
        _ => collect_opaque(st, expr),
    }
}

/// Extract an observation or a substitutable binding from a `let`.
fn observe_let(st: &mut PathState, stmt: &LetStatement) {
    // `let x = query F[..] or <terminal>` proves the fact exists on
    // fall-through.
    if let ExprKind::Coalesce(lhs, rhs) = &stmt.expression.kind
        && matches!(rhs.vtype.inner, TypeKind::Never)
        && let ExprKind::InternalFunction(InternalFunction::Query(fact)) = &lhs.kind
    {
        let pat = pattern_of(fact, &st.env);
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
fn observe(st: &mut PathState, pat: FactPattern, state: FactState) {
    st.facts.retain(|(p, _)| !same_pattern(p, &pat));
    st.facts.push((pat, state));
}

/// Record a mutation's postcondition. A mutation invalidates all other
/// knowledge about the same fact name, since other patterns may alias
/// the mutated key.
fn set_state(st: &mut PathState, pat: FactPattern, state: FactState) {
    st.facts.retain(|(p, _)| p.name != pat.name);
    st.facts.push((pat, state));
}

fn pattern_of(fact: &FactLiteral, env: &BTreeMap<Identifier, Expression>) -> FactPattern {
    FactPattern {
        name: fact.identifier.clone(),
        keys: fact
            .key_fields
            .iter()
            .map(|(name, expr)| (name.inner.clone(), substitute(expr, env)))
            .collect(),
        span: fact.span(),
    }
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
fn collect_opaque(st: &mut PathState, expr: &Expression) {
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
        assert!(warnings[0].message.contains("cannot prove fact `Account`"));
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
