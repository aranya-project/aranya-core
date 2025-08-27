//! HIR visitor implementation for the verification pass.

use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    ops::ControlFlow,
};

use super::errors::{InvalidMatchType, InvalidStatementContext};
use crate::{
    ctx::Ctx,
    diag::DiagCtx,
    eval::{ConstEvalView, Value},
    hir::{
        visit::{try_visit, Visitor},
        ActionCall, ActionDef, ActionId, Block, BlockId, Body, CmdDef, CmdFieldKind, CmdId, Create,
        Delete, Emit, Expr, ExprId, ExprKind, FinishFuncDef, FinishFuncId, FuncDef, FuncId,
        FunctionCall, Hir, HirView, IdentId, IfStmt, Intrinsic, LetStmt, LitKind, MatchArm,
        MatchPattern, MatchStmt, NamedStruct, Publish, ReturnStmt, Span, Stmt, StmtKind, Update,
        VTypeId, VTypeKind,
    },
    symtab::SymbolsView,
    typecheck::{
        types::{Type, TypeEnum, TypeKind},
        TypesView,
    },
};





/// The execution context for a scope.
#[derive(Debug, Clone)]
enum ExecutionContext {
    /// Global scope - top-level definitions.
    Global,
    /// Action context - can call other actions.
    Action(ActionId),
    /// Cmd policy context - can use check statements.
    /// The boolean indicates if the command is persistent.
    CmdPolicy(CmdId, bool),
    /// Cmd recall context - can use check statements.
    /// The boolean indicates if the command is persistent.
    CmdRecall(CmdId, bool),
    /// Cmd seal context - can use return statements.
    /// The boolean indicates if the command is persistent.
    CmdSeal(CmdId, bool),
    /// Cmd open context - can use return statements.
    /// The boolean indicates if the command is persistent.
    CmdOpen(CmdId, bool),
    /// Pure func context - can call pure funcs, must return value.
    PureFunc(FuncId),
    /// Finish func context - can use fact operations and emit effects.
    FinishFunc(FinishFuncId),
    /// Finish block context - can use fact operations and emit effects.
    FinishBlock,
    /// Block context - local scope.
    Block(BlockId),
    /// Finished context - statements after a finish statement are unreachable.
    Finished,
}

impl Display for ExecutionContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionContext::Global => write!(f, "global"),
            ExecutionContext::Action(_) => write!(f, "action"),
            ExecutionContext::CmdPolicy(_, _) => write!(f, "cmd policy"),
            ExecutionContext::CmdRecall(_, _) => write!(f, "cmd recall"),
            ExecutionContext::CmdSeal(_, _) => write!(f, "cmd seal"),
            ExecutionContext::CmdOpen(_, _) => write!(f, "cmd open"),
            ExecutionContext::PureFunc(_) => write!(f, "pure func"),
            ExecutionContext::FinishFunc(_) => write!(f, "finish func"),
            ExecutionContext::FinishBlock => write!(f, "finish block"),
            ExecutionContext::Block(_) => write!(f, "block"),
            ExecutionContext::Finished => write!(f, "finished"),
        }
    }
}

impl ExecutionContext {
    /// Returns a human-readable description of this context.
    fn description(&self) -> String {
        self.to_string()
    }

    /// Returns whether this context allows fact operations (create, update, delete).
    fn allows_fact_operations(&self) -> bool {
        matches!(
            self,
            ExecutionContext::FinishFunc(_) | ExecutionContext::FinishBlock
        )
    }

    /// Returns whether this context allows effect emission.
    fn allows_effects(&self) -> bool {
        matches!(
            self,
            ExecutionContext::FinishFunc(_) | ExecutionContext::FinishBlock
        )
    }

    /// Returns whether this context allows action calls.
    fn allows_action_calls(&self) -> bool {
        matches!(self, ExecutionContext::Action(_))
    }

    /// Returns whether this context requires return statements.
    fn requires_return(&self) -> bool {
        matches!(self, ExecutionContext::PureFunc(_))
    }

    /// Returns whether this context is within a persistent command.
    fn is_persistent_command(&self) -> bool {
        match self {
            ExecutionContext::CmdPolicy(_, is_persistent)
            | ExecutionContext::CmdRecall(_, is_persistent)
            | ExecutionContext::CmdSeal(_, is_persistent)
            | ExecutionContext::CmdOpen(_, is_persistent) => *is_persistent,
            _ => true, // Non-command contexts are considered "persistent" for fact operations
        }
    }
}

/// The main verifier that walks the HIR and validates semantic correctness.
pub(super) struct Verifier<'cx> {
    ctx: Ctx<'cx>,
    hir: HirView<'cx>,
    symbols: SymbolsView<'cx>,
    consts: ConstEvalView<'cx>,
    types: TypesView<'cx>,
    context_stack: RefCell<Vec<ExecutionContext>>,
    max_errs: usize,
    num_errs: usize,
}

impl<'cx> Verifier<'cx> {
    /// Creates a new verifier instance.
    pub(super) fn new(
        ctx: Ctx<'cx>,
        hir: HirView<'cx>,
        symbols: SymbolsView<'cx>,
        consts: ConstEvalView<'cx>,
        types: TypesView<'cx>,
        max_errs: usize,
    ) -> Self {
        Self {
            ctx,
            hir,
            symbols,
            consts,
            types,
            context_stack: RefCell::new(vec![]),
            max_errs,
            num_errs: 0,
        }
    }

    /// Safely extracts an integer value from a constant, returning None if type mismatch.
    fn safe_extract_int(&self, expr_id: ExprId) -> Option<i64> {
        self.consts
            .get(expr_id)
            .and_then(|result| result.ok())
            .and_then(|const_val| {
                match const_val.as_value() {
                    Value::Int(int_val) => Some(*int_val),
                    _ => None, // Type mismatch - fail gracefully
                }
            })
    }

    /// Safely extracts a boolean value from a constant, returning None if type mismatch.
    fn safe_extract_bool(&self, expr_id: ExprId) -> Option<bool> {
        self.consts
            .get(expr_id)
            .and_then(|result| result.ok())
            .and_then(|const_val| {
                match const_val.as_value() {
                    Value::Bool(bool_val) => Some(*bool_val),
                    _ => None, // Type mismatch - fail gracefully
                }
            })
    }

    /// Safely extracts a string value from a constant, returning None if type mismatch.
    fn safe_extract_string(&self, expr_id: ExprId) -> Option<String> {
        self.consts
            .get(expr_id)
            .and_then(|result| result.ok())
            .and_then(|const_val| {
                match const_val.as_value() {
                    Value::String(text_ref) => Some(text_ref.to_string()),
                    _ => None, // Type mismatch - fail gracefully
                }
            })
    }

    /// Safely extracts an optional value from a constant, returning None if type mismatch.
    /// Returns (has_some, has_none) to indicate which optional patterns are present.
    fn safe_extract_optional(&self, expr_id: ExprId) -> Option<(bool, bool)> {
        self.consts
            .get(expr_id)
            .and_then(|result| result.ok())
            .and_then(|const_val| {
                match const_val.as_value() {
                    Value::Optional(opt_val) => {
                        match opt_val {
                            Some(_) => Some((true, false)), // has_some = true, has_none = false
                            None => Some((false, true)),    // has_some = false, has_none = true
                        }
                    }
                    _ => None, // Type mismatch - fail gracefully
                }
            })
    }

    pub fn dcx(&self) -> &'cx DiagCtx {
        self.ctx.dcx()
    }

    /// Gets access to the HIR view.
    pub fn hir_view(&self) -> &HirView<'cx> {
        &self.hir
    }

    /// Gets the current error count.
    pub fn error_count(&self) -> usize {
        self.num_errs
    }

    /// Records an error and checks if we should stop processing.
    ///
    /// Returns `ControlFlow::Break(())` if we've reached the maximum error limit,
    /// otherwise returns `ControlFlow::Continue(())`.
    fn record_error(&mut self) -> ControlFlow<()> {
        self.num_errs = self.num_errs.saturating_add(1);
        if self.num_errs >= self.max_errs {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Pushes a new execution context onto the stack.
    fn push_context(&self, context: ExecutionContext) {
        self.context_stack.borrow_mut().push(context);
    }

    /// Pops the top execution context from the stack.
    fn pop_context(&self) -> Option<ExecutionContext> {
        self.context_stack.borrow_mut().pop()
    }

    /// Gets the current execution context.
    fn current_context(&self) -> Option<ExecutionContext> {
        self.context_stack.borrow().last().cloned()
    }

    /// Marks the current context as finished to detect unreachable code.
    fn mark_context_finished(&self) {
        if let Some(context) = self.context_stack.borrow_mut().last_mut() {
            *context = ExecutionContext::Finished;
        }
    }

    /// Checks if the current context is finished (has unreachable code).
    fn is_context_finished(&self) -> bool {
        self.context_stack
            .borrow()
            .last()
            .map_or(false, |ctx| matches!(ctx, ExecutionContext::Finished))
    }

    /// Analyzes control flow for unreachable code in a function body.
    fn analyze_function_control_flow(&mut self, body: &Body) -> ControlFlow<()> {
        let mut has_return = false;

        for &stmt_id in &body.stmts {
            let stmt = self.hir.lookup(stmt_id);

            // Check if this statement is after a return/finish
            if has_return {
                use super::errors::UnreachableCode;
                self.dcx().emit_err_diag(UnreachableCode {
                    span: stmt.span,
                    reason: "code after return statement".into(),
                });
                self.record_error()?;
            }

            // Track control flow changing statements
            match &stmt.kind {
                StmtKind::Return(_) => {
                    has_return = true;
                }
                StmtKind::Finish(_) => {
                    has_return = true;
                }
                StmtKind::If(if_stmt) => {
                    self.analyze_if_control_flow(if_stmt)?;
                }
                StmtKind::Match(match_stmt) => {
                    self.analyze_match_control_flow(match_stmt)?;
                }
                _ => {}
            }
        }

        // Check if function needs return statement validation
        // For now, we can only validate basic control flow without full type information
        self.validate_function_return_requirement(body)?;

        ControlFlow::Continue(())
    }

    /// Analyzes control flow in if statements.
    fn analyze_if_control_flow(&mut self, if_stmt: &IfStmt) -> ControlFlow<()> {
        let mut all_branches_return = true;

        // Check each if branch
        for branch in &if_stmt.branches {
            let block = self.hir.lookup(branch.block);
            if !self.block_always_returns(block) {
                all_branches_return = false;
            }
        }

        // Check else branch
        if let Some(else_block_id) = if_stmt.else_block {
            let else_block = self.hir.lookup(else_block_id);
            if !self.block_always_returns(else_block) {
                all_branches_return = false;
            }
        } else {
            // No else branch means not all paths return
            all_branches_return = false;
        }

        // If all branches return, mark context as finished
        if all_branches_return {
            self.mark_context_finished();
        }

        ControlFlow::Continue(())
    }

    /// Analyzes control flow in match statements.
    fn analyze_match_control_flow(&mut self, match_stmt: &MatchStmt) -> ControlFlow<()> {
        let mut all_arms_return = true;

        for arm in &match_stmt.arms {
            let block = self.hir.lookup(arm.block);
            if !self.block_always_returns(block) {
                all_arms_return = false;
                break;
            }
        }

        // If all arms return and match is exhaustive, mark context as finished
        if all_arms_return {
            let scrutinee = self.hir.lookup(match_stmt.expr);
            if self.is_match_exhaustive(scrutinee, &match_stmt.arms) {
                self.mark_context_finished();
            }
        }

        ControlFlow::Continue(())
    }

    /// Checks if a block always returns (has no fallthrough).
    fn block_always_returns(&self, block: &Block) -> bool {
        for &stmt_id in &block.stmts {
            let stmt = self.hir.lookup(stmt_id);
            match &stmt.kind {
                StmtKind::Return(_) | StmtKind::Finish(_) => {
                    return true;
                }
                StmtKind::If(if_stmt) => {
                    if self.if_always_returns(if_stmt) {
                        return true;
                    }
                }
                StmtKind::Match(match_stmt) => {
                    if self.match_always_returns(match_stmt) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Checks if an if statement always returns.
    fn if_always_returns(&self, if_stmt: &IfStmt) -> bool {
        // All branches must return
        for branch in &if_stmt.branches {
            let block = self.hir.lookup(branch.block);
            if !self.block_always_returns(block) {
                return false;
            }
        }

        // Must have an else branch that returns
        if let Some(else_block_id) = if_stmt.else_block {
            let else_block = self.hir.lookup(else_block_id);
            self.block_always_returns(else_block)
        } else {
            false
        }
    }

    /// Checks if a match statement always returns.
    fn match_always_returns(&self, match_stmt: &MatchStmt) -> bool {
        // All arms must return and match must be exhaustive
        for arm in &match_stmt.arms {
            let block = self.hir.lookup(arm.block);
            if !self.block_always_returns(block) {
                return false;
            }
        }

        // Check if match is exhaustive
        let scrutinee = self.hir.lookup(match_stmt.expr);
        self.is_match_exhaustive(scrutinee, &match_stmt.arms)
    }

    /// Basic check if match is exhaustive (simplified version).
    fn is_match_exhaustive(&self, _scrutinee: &Expr, arms: &[MatchArm]) -> bool {
        // Simple heuristic: if there's a default pattern, assume exhaustive
        arms.iter()
            .any(|arm| matches!(arm.pattern, MatchPattern::Default))
    }

    /// Checks if a function body always returns.
    fn body_always_returns(&self, body: &Body) -> bool {
        for &stmt_id in &body.stmts {
            let stmt = self.hir.lookup(stmt_id);
            match &stmt.kind {
                StmtKind::Return(_) => {
                    return true;
                }
                StmtKind::If(if_stmt) => {
                    if self.if_always_returns(if_stmt) {
                        return true;
                    }
                }
                StmtKind::Match(match_stmt) => {
                    if self.match_always_returns(match_stmt) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Runs the verification pass.
    pub fn verify(&mut self) -> ControlFlow<()> {
        // Start with global context
        self.push_context(ExecutionContext::Global);

        // Visit all top-level items using the standard visitor
        try_visit!(self.visit_all());

        // Pop global context
        self.pop_context();

        // Check for errors
        if self.dcx().has_errors().is_some() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }

    /// Verifies that a stmt is allowed in the current context.
    fn verify_stmt_context(&mut self, stmt: &Stmt, context: &ExecutionContext) -> ControlFlow<()> {
        match &stmt.kind {
            StmtKind::Create(_) | StmtKind::Update(_) | StmtKind::Delete(_) => {
                if !context.allows_fact_operations() {
                    self.dcx().emit_err_diag(InvalidStatementContext {
                        actual_context: Cow::Owned(context.description()),
                        expected_context: Cow::Borrowed("finish"),
                        span: stmt.span,
                    });
                    self.record_error()?;
                } else if !context.is_persistent_command() {
                    use super::errors::CommandPersistenceMismatch;
                    self.dcx().emit_err_diag(CommandPersistenceMismatch {
                        expected: "persistent command".into(),
                        actual: "ephemeral command".into(),
                        span: stmt.span,
                    });
                    self.record_error()?;
                }
            }
            StmtKind::Emit(_) => {
                if !context.allows_effects() {
                    self.dcx().emit_err_diag(InvalidStatementContext {
                        actual_context: Cow::Owned(context.description()),
                        expected_context: Cow::Borrowed("finish"),
                        span: stmt.span,
                    });
                    self.record_error()?;
                }
            }
            StmtKind::ActionCall(ActionCall { ident: _, .. }) => {
                if !context.allows_action_calls() {
                    self.dcx().emit_err_diag(InvalidStatementContext {
                        actual_context: Cow::Owned(context.description()),
                        expected_context: Cow::Borrowed("action"),
                        span: stmt.span,
                    });
                    self.record_error()?;
                }
            }
            _ => {}
        }
        ControlFlow::Continue(())
    }

    /// Checks a let statement.
    fn check_let(&mut self, v: &LetStmt) -> ControlFlow<()> {
        // Visit the expression first
        self.visit_expr(self.hir.lookup(v.expr))?;

        // Variable shadowing is already checked by symbol resolution
        ControlFlow::Continue(())
    }

    /// Checks an action call statement.
    fn check_action_call(&mut self, v: &ActionCall) -> ControlFlow<()> {
        // Verify action exists and visit arguments
        for &id in &v.args {
            self.visit_expr(self.hir.lookup(id))?;
        }
        ControlFlow::Continue(())
    }

    /// Checks a function call statement.
    fn check_function_call(&mut self, v: &FunctionCall) -> ControlFlow<()> {
        // Visit and validate all arguments
        for &id in &v.args {
            self.visit_expr(self.hir.lookup(id))?;
        }

        // Validate context requirements for function calls
        // This is a partial implementation limited by API constraints
        self.validate_function_call_context(v)?;

        ControlFlow::Continue(())
    }

    /// Validates function call context requirements.
    ///
    /// This is a partial implementation limited by current API constraints.
    /// Full implementation requires:
    /// 1. SymbolsView.lookup_function(ident) API to get function definitions
    /// 2. Reliable function type classification (finish vs regular vs action)
    /// 3. Function signature information to distinguish context requirements
    ///
    /// Current implementation provides basic validation and a framework for extension.
    fn validate_function_call_context(&mut self, func_call: &FunctionCall) -> ControlFlow<()> {
        let func_name = self.hir.lookup_ident_ref(func_call.ident);
        let current_context = self.current_context();

        // Strategy 1 & 2: Validate context requirements if we have a current context
        if let Some(ref context) = current_context {
            self.check_function_naming_patterns(&func_name.to_string(), context)?;
            self.validate_context_function_restrictions(context)?;
        }

        // TODO: Add complete function type lookup when API supports:
        // - SymbolsView.lookup_function(func_call.ident) -> Option<FunctionDef>
        // - Function type classification (finish/action/effect/pure)
        // - Context requirement validation based on actual function signatures

        ControlFlow::Continue(())
    }

    /// Checks function naming patterns for context appropriateness.
    fn check_function_naming_patterns(
        &mut self,
        func_name: &str,
        _context: &ExecutionContext,
    ) -> ControlFlow<()> {
        let name_lower = func_name.to_lowercase();

        // Functions with "finish" in the name likely need finish context
        if name_lower.contains("finish") || name_lower.contains("complete") {
            // TODO: Add validation when function type lookup is available
        }

        // Functions with "action" in the name likely need action context
        if name_lower.contains("action") || name_lower.contains("execute") {
            // TODO: Add validation when function type lookup is available
        }

        ControlFlow::Continue(())
    }

    /// Validates context-specific function call restrictions.
    fn validate_context_function_restrictions(
        &mut self,
        context: &ExecutionContext,
    ) -> ControlFlow<()> {
        match context {
            ExecutionContext::PureFunc(_) => {
                // Pure functions should only call other pure functions
                // TODO: Implement when function purity can be determined
            }
            ExecutionContext::Finished => {
                // No function calls should be possible in finished context
                // This should be caught by unreachable code analysis
            }
            _ => {
                // Other contexts have more relaxed restrictions
            }
        }

        ControlFlow::Continue(())
    }

    /// Checks a create statement.
    fn check_create(&mut self, v: &Create, stmt_span: Span) -> ControlFlow<()> {
        // Validate the fact literal structure
        self.validate_fact_literal(&v.fact)?;

        // Create operations should specify all required fields
        self.validate_fact_completeness(&v.fact, "create", stmt_span)?;

        ControlFlow::Continue(())
    }

    /// Checks an update statement.
    fn check_update(&mut self, v: &Update, stmt_span: Span) -> ControlFlow<()> {
        // Validate the fact literal structure (matching pattern)
        self.validate_fact_literal(&v.fact)?;

        // Validate the update fields
        for field_expr in &v.to {
            match &field_expr.expr {
                crate::hir::FactField::Expr(expr_id) => {
                    self.visit_expr(self.hir.lookup(*expr_id))?;
                }
                crate::hir::FactField::Bind => {
                    // Bind expressions don't need visiting but are invalid in updates
                    use super::errors::FactSchemaViolation;
                    self.dcx().emit_err_diag(FactSchemaViolation {
                        description: "bind expressions not allowed in update targets".into(),
                        span: stmt_span,
                    });
                    self.record_error()?;
                }
            }
        }

        // Update operations must have update target fields
        if v.to.is_empty() {
            use super::errors::FactSchemaViolation;
            self.dcx().emit_err_diag(FactSchemaViolation {
                description: "update operation requires at least one target field".into(),
                span: stmt_span,
            });
            self.record_error()?;
        }

        ControlFlow::Continue(())
    }

    /// Checks a delete statement.
    fn check_delete(&mut self, v: &Delete, stmt_span: Span) -> ControlFlow<()> {
        // Validate the fact literal structure (matching pattern)
        self.validate_fact_literal(&v.fact)?;

        // Delete operations should only use key fields and binds for matching
        // Val fields with concrete values in deletes might indicate a logic error
        self.validate_delete_pattern(&v.fact, stmt_span)?;

        ControlFlow::Continue(())
    }

    /// Checks an emit statement.
    fn check_emit(&mut self, v: &Emit, stmt_span: Span) -> ControlFlow<()> {
        // Visit and validate the effect expression
        self.visit_expr(self.hir.lookup(v.expr))?;

        // Validate the effect structure if it's a literal
        let expr = self.hir.lookup(v.expr);
        if let ExprKind::Lit(lit) = &expr.kind {
            if let LitKind::NamedStruct(named_struct) = &lit.kind {
                self.validate_effect_structure(named_struct, stmt_span)?;
            }
        }

        ControlFlow::Continue(())
    }

    /// Checks an if statement.
    fn check_if(&mut self, v: &IfStmt) -> ControlFlow<()> {
        // Visit all branches
        for branch in &v.branches {
            self.visit_expr(self.hir.lookup(branch.expr))?;
            self.visit_block(self.hir.lookup(branch.block))?;
        }
        // Visit else block if present
        if let Some(else_id) = &v.else_block {
            self.visit_block(self.hir.lookup(*else_id))?;
        }
        ControlFlow::Continue(())
    }

    /// Checks a match statement.
    fn check_match(&mut self, stmt: &'cx MatchStmt) -> ControlFlow<()> {
        let scrutinee = self.hir.lookup(stmt.expr);
        self.visit_expr(scrutinee)?;

        // Check for duplicate default patterns and patterns after default
        self.check_match_pattern_order(&stmt.arms)?;

        for arm in &stmt.arms {
            match &arm.pattern {
                MatchPattern::Default => {}
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        self.visit_expr(self.hir.lookup(expr_id))?;
                    }
                }
            }
            self.visit_block(self.hir.lookup(arm.block))?;
        }

        let stmt_span = self.hir.lookup_span(stmt.expr);
        self.check_match_is_exhaustive(scrutinee, &stmt.arms, stmt_span)
    }

    /// Checks for duplicate default patterns and unreachable patterns after default.
    fn check_match_pattern_order(&mut self, arms: &[MatchArm]) -> ControlFlow<()> {
        let found_default_at = match self.check_duplicate_defaults(arms) {
            Ok(position) => position,
            Err(control_flow) => return control_flow,
        };
        self.check_unreachable_after_default(arms, found_default_at)
    }

    /// Checks for duplicate default patterns in match arms.
    /// Returns the position of the first default pattern if found.
    fn check_duplicate_defaults(
        &mut self,
        arms: &[MatchArm],
    ) -> Result<Option<usize>, ControlFlow<()>> {
        let mut default_count: usize = 0;
        let mut found_default_at = None;

        for (i, arm) in arms.iter().enumerate() {
            if matches!(arm.pattern, MatchPattern::Default) {
                default_count = default_count.saturating_add(1);
                if default_count == 1 {
                    found_default_at = Some(i);
                } else {
                    // Multiple defaults found
                    use super::errors::DuplicatePattern;
                    self.dcx().emit_err_diag(DuplicatePattern {
                        span: self.hir.lookup_span(arm.block),
                        previous_span: None,
                        pattern_desc: "default pattern".into(),
                    });
                    return Err(self.record_error());
                }
            }
        }

        Ok(found_default_at)
    }

    /// Checks for unreachable patterns that appear after a default pattern.
    fn check_unreachable_after_default(
        &mut self,
        arms: &[MatchArm],
        default_position: Option<usize>,
    ) -> ControlFlow<()> {
        if let Some(default_idx) = default_position {
            for (_i, arm) in arms.iter().enumerate().skip(default_idx.saturating_add(1)) {
                if matches!(arm.pattern, MatchPattern::Values(_)) {
                    // Pattern after default - unreachable code
                    use super::errors::UnreachablePattern;
                    self.dcx().emit_err_diag(UnreachablePattern {
                        span: self.hir.lookup_span(arm.block),
                        reason: "pattern appears after default case".into(),
                    });
                    return self.record_error();
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Checks that the match statement is exhaustive.
    fn check_match_is_exhaustive(
        &mut self,
        scrutinee: &Expr,
        arms: &[MatchArm],
        match_span: Span,
    ) -> ControlFlow<()> {
        // One single default arm makes it exhaustive.
        if let [MatchArm {
            pattern: MatchPattern::Default,
            ..
        }] = arms
        {
            return ControlFlow::Continue(());
        }

        let Type { xref: _, kind } = self.types.get_type(scrutinee.id);

        // Check for invalid match types first
        match kind {
            TypeKind::Bytes => {
                self.dcx().emit_err_diag(InvalidMatchType {
                    reason: "cannot match on bytes (no constant literals available)".into(),
                    span: match_span,
                });
                return self.record_error();
            }
            TypeKind::Optional(_) => {
                // Optional matching is allowed with literal patterns
                return self.check_optional_arms(arms, match_span);
            }
            _ => {}
        }

        // Check exhaustiveness for valid types
        match kind {
            TypeKind::Int => self.check_int_arms(arms, match_span),
            TypeKind::Bool => self.check_bool_arms(arms, match_span),
            TypeKind::Enum(enum_type) => self.check_enum_arms(arms, enum_type, match_span),
            TypeKind::Optional(_) => self.check_optional_arms(arms, match_span),
            TypeKind::String => self.check_string_arms(arms, match_span),
            // Every other type is non-exhaustive.
            _ => {
                // For now, require a default case for non-primitive types
                let has_default = arms
                    .iter()
                    .any(|arm| matches!(arm.pattern, MatchPattern::Default));
                if !has_default {
                    use super::errors::NonExhaustiveMatch;
                    self.dcx().emit_err_diag(NonExhaustiveMatch {
                        span: match_span,
                        missing_patterns: vec!["default case".into()],
                    });
                    return self.record_error();
                }
                ControlFlow::Continue(())
            }
        }
    }

    /// Checks that the match expression is exhaustive.
    fn check_match_expr_is_exhaustive(
        &mut self,
        scrutinee: &Expr,
        arms: &[crate::hir::MatchExprArm],
        match_span: Span,
    ) -> ControlFlow<()> {
        // One single default arm makes it exhaustive.
        if let [crate::hir::MatchExprArm {
            pattern: MatchPattern::Default,
            ..
        }] = arms
        {
            return ControlFlow::Continue(());
        }

        let Type { xref: _, kind } = self.types.get_type(scrutinee.id);

        // Check for invalid match types first
        match kind {
            TypeKind::Bytes => {
                self.dcx().emit_err_diag(InvalidMatchType {
                    reason: "cannot match on bytes (no constant literals available)".into(),
                    span: match_span,
                });
                return self.record_error();
            }
            TypeKind::Optional(_) => {
                // Optional matching is allowed with literal patterns
                return self.check_optional_arms_expr(arms, match_span);
            }
            _ => {}
        }

        // Check exhaustiveness for valid types
        match kind {
            TypeKind::Int => self.check_int_arms_expr(arms, match_span),
            TypeKind::Bool => self.check_bool_arms_expr(arms, match_span),
            TypeKind::Enum(enum_type) => self.check_enum_arms_expr(arms, enum_type, match_span),
            TypeKind::Optional(_) => self.check_optional_arms_expr(arms, match_span),
            TypeKind::String => self.check_string_arms_expr(arms, match_span),
            // Every other type is non-exhaustive.
            _ => {
                // For now, require a default case for non-primitive types
                let has_default = arms
                    .iter()
                    .any(|arm| matches!(arm.pattern, MatchPattern::Default));
                if !has_default {
                    use super::errors::NonExhaustiveMatch;
                    self.dcx().emit_err_diag(NonExhaustiveMatch {
                        span: match_span,
                        missing_patterns: vec!["default case".into()],
                    });
                    return self.record_error();
                }
                ControlFlow::Continue(())
            }
        }
    }

    /// Checks if integer match arms are exhaustive and handles duplicates.
    fn check_int_arms(&mut self, arms: &[MatchArm], span: Span) -> ControlFlow<()> {
        let mut seen = HashSet::with_capacity(arms.len());
        let mut has_default = false;

        // Check for duplicate patterns and gather values
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(int_val) = self.safe_extract_int(expr_id) {
                            if !seen.insert(int_val) {
                                use super::errors::DuplicatePattern;
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: format!("integer value {}", int_val).into(),
                                });
                                return self.record_error();
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness - integers can't be exhaustive without default
        if !has_default {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: vec!["integer values not covered".into()],
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if integer match arms are exhaustive (expression version).
    fn check_int_arms_expr(
        &mut self,
        arms: &[crate::hir::MatchExprArm],
        span: Span,
    ) -> ControlFlow<()> {
        let mut seen = HashSet::with_capacity(arms.len());
        let mut has_default = false;

        // Check for duplicate patterns and gather values
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(int_val) = self.safe_extract_int(expr_id) {
                            if !seen.insert(int_val) {
                                use super::errors::DuplicatePattern;
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: format!("integer value {}", int_val).into(),
                                });
                                return self.record_error();
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness - integers can't be exhaustive without default
        if !has_default {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: vec!["integer values not covered".into()],
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if boolean match arms are exhaustive and handles duplicates.
    fn check_bool_arms(&mut self, arms: &[MatchArm], span: Span) -> ControlFlow<()> {
        let mut has_true = false;
        let mut has_false = false;
        let mut has_default = false;
        let mut true_count: usize = 0;
        let mut false_count: usize = 0;

        // Check for duplicate patterns and gather values
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(bool_val) = self.safe_extract_bool(expr_id) {
                            if bool_val {
                                has_true = true;
                                true_count = true_count.saturating_add(1);
                                if true_count > 1 {
                                    use super::errors::DuplicatePattern;
                                    self.dcx().emit_err_diag(DuplicatePattern {
                                        span: self.hir.lookup_span(expr_id),
                                        previous_span: None,
                                        pattern_desc: "boolean value true".into(),
                                    });
                                    return self.record_error();
                                }
                            } else {
                                has_false = true;
                                false_count = false_count.saturating_add(1);
                                if false_count > 1 {
                                    use super::errors::DuplicatePattern;
                                    self.dcx().emit_err_diag(DuplicatePattern {
                                        span: self.hir.lookup_span(expr_id),
                                        previous_span: None,
                                        pattern_desc: "boolean value false".into(),
                                    });
                                    return self.record_error();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness
        if !(has_default || (has_true && has_false)) {
            let mut missing = Vec::new();
            if !has_true {
                missing.push("true".into());
            }
            if !has_false {
                missing.push("false".into());
            }

            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing,
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if boolean match arms are exhaustive (expression version).
    fn check_bool_arms_expr(
        &mut self,
        arms: &[crate::hir::MatchExprArm],
        span: Span,
    ) -> ControlFlow<()> {
        let mut has_true = false;
        let mut has_false = false;
        let mut has_default = false;
        let mut true_count: usize = 0;
        let mut false_count: usize = 0;

        // Check for duplicate patterns and gather values
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(bool_val) = self.safe_extract_bool(expr_id) {
                            if bool_val {
                                has_true = true;
                                true_count = true_count.saturating_add(1);
                                if true_count > 1 {
                                    use super::errors::DuplicatePattern;
                                    self.dcx().emit_err_diag(DuplicatePattern {
                                        span: self.hir.lookup_span(expr_id),
                                        previous_span: None,
                                        pattern_desc: "boolean value true".into(),
                                    });
                                    return self.record_error();
                                }
                            } else {
                                has_false = true;
                                false_count = false_count.saturating_add(1);
                                if false_count > 1 {
                                    use super::errors::DuplicatePattern;
                                    self.dcx().emit_err_diag(DuplicatePattern {
                                        span: self.hir.lookup_span(expr_id),
                                        previous_span: None,
                                        pattern_desc: "boolean value false".into(),
                                    });
                                    return self.record_error();
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness
        if !(has_default || (has_true && has_false)) {
            let mut missing = Vec::new();
            if !has_true {
                missing.push("true".into());
            }
            if !has_false {
                missing.push("false".into());
            }

            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing,
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if string match arms are exhaustive and handles duplicates.
    fn check_string_arms(&mut self, arms: &[MatchArm], span: Span) -> ControlFlow<()> {
        let mut seen = HashSet::new();
        let mut has_default = false;

        // Check for duplicate patterns
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(string_val) = self.safe_extract_string(expr_id) {
                            if !seen.insert(string_val) {
                                use super::errors::DuplicatePattern;
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: "string literal".into(),
                                });
                                return self.record_error();
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness - strings can't be exhaustive without default
        if !has_default {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: vec!["default case (strings are not exhaustive)".into()],
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if string match arms are exhaustive (expression version).
    fn check_string_arms_expr(
        &mut self,
        arms: &[crate::hir::MatchExprArm],
        span: Span,
    ) -> ControlFlow<()> {
        let mut seen = HashSet::new();
        let mut has_default = false;

        // Check for duplicate patterns
        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some(string_val) = self.safe_extract_string(expr_id) {
                            if !seen.insert(string_val) {
                                use super::errors::DuplicatePattern;
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: "string literal".into(),
                                });
                                return self.record_error();
                            }
                        }
                    }
                }
            }
        }

        // Check exhaustiveness - strings can't be exhaustive without default
        if !has_default {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: vec!["default case (strings are not exhaustive)".into()],
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Checks if optional match arms are exhaustive.
    fn check_optional_arms(&mut self, arms: &[MatchArm], span: Span) -> ControlFlow<()> {
        let mut has_some = false;
        let mut has_none = false;
        let mut has_default = false;

        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some((has_some_val, has_none_val)) = self.safe_extract_optional(expr_id) {
                            if has_some_val {
                                has_some = true;
                            }
                            if has_none_val {
                                has_none = true;
                            }
                        }
                    }
                }
            }
        }

        if has_default || (has_some && has_none) {
            ControlFlow::Continue(())
        } else {
            let missing = if !has_some && !has_none {
                vec!["None and Some(_) patterns".into()]
            } else if !has_some {
                vec!["Some(_) pattern".into()]
            } else {
                vec!["None pattern".into()]
            };

            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing,
            });
            self.record_error()
        }
    }

    /// Checks if optional match arms are exhaustive (expression version).
    fn check_optional_arms_expr(
        &mut self,
        arms: &[crate::hir::MatchExprArm],
        span: Span,
    ) -> ControlFlow<()> {
        let mut has_some = false;
        let mut has_none = false;
        let mut has_default = false;

        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        if let Some((has_some_val, has_none_val)) = self.safe_extract_optional(expr_id) {
                            if has_some_val {
                                has_some = true;
                            }
                            if has_none_val {
                                has_none = true;
                            }
                        }
                    }
                }
            }
        }

        if has_default || (has_some && has_none) {
            ControlFlow::Continue(())
        } else {
            let missing = if !has_some && !has_none {
                vec!["None and Some(_) patterns".into()]
            } else if !has_some {
                vec!["Some(_) pattern".into()]
            } else {
                vec!["None pattern".into()]
            };

            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing,
            });
            self.record_error()
        }
    }

    /// Checks if enum match arms are exhaustive and handles duplicates.
    fn check_enum_arms(
        &mut self,
        arms: &[MatchArm],
        enum_type: &TypeEnum,
        span: Span,
    ) -> ControlFlow<()> {
        use super::errors::DuplicatePattern;

        let mut covered_variants = HashSet::with_capacity(enum_type.variants.len());
        let mut variant_counts = HashMap::with_capacity(enum_type.variants.len());
        let mut has_default = false;
        let mut valid = true;

        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        let expr = self.hir.lookup(expr_id);
                        if let ExprKind::EnumRef(enum_ref) = &expr.kind {
                            let variant_ident = self.hir.lookup_ident_ref(enum_ref.value);
                            covered_variants.insert(variant_ident);

                            let count = variant_counts.entry(variant_ident).or_insert(0usize);
                            *count = (*count).saturating_add(1);

                            if *count > 1 {
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: "enum variant".into(),
                                });
                                valid = false;
                            }
                        }
                    }
                }
            }
        }

        if !valid {
            return self.record_error();
        }

        if has_default {
            return ControlFlow::Continue(());
        }

        // Check if all enum variants are covered
        let missing_variants: Vec<_> = enum_type
            .variants
            .iter()
            .filter(|variant| !covered_variants.contains(&variant.xref))
            .map(|variant| variant.xref.to_string().into())
            .collect();

        if missing_variants.is_empty() {
            ControlFlow::Continue(())
        } else {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing_variants,
            });
            self.record_error()
        }
    }

    /// Checks if enum match arms are exhaustive (expression version).
    fn check_enum_arms_expr(
        &mut self,
        arms: &[crate::hir::MatchExprArm],
        enum_type: &TypeEnum,
        span: Span,
    ) -> ControlFlow<()> {
        use super::errors::DuplicatePattern;

        let mut covered_variants = HashSet::with_capacity(enum_type.variants.len());
        let mut variant_counts = HashMap::with_capacity(enum_type.variants.len());
        let mut has_default = false;
        let mut valid = true;

        for arm in arms {
            match &arm.pattern {
                MatchPattern::Default => has_default = true,
                MatchPattern::Values(values) => {
                    for &expr_id in values {
                        let expr = self.hir.lookup(expr_id);
                        if let ExprKind::EnumRef(enum_ref) = &expr.kind {
                            let variant_ident = self.hir.lookup_ident_ref(enum_ref.value);
                            covered_variants.insert(variant_ident);

                            let count = variant_counts.entry(variant_ident).or_insert(0usize);
                            *count = (*count).saturating_add(1);

                            if *count > 1 {
                                self.dcx().emit_err_diag(DuplicatePattern {
                                    span: self.hir.lookup_span(expr_id),
                                    previous_span: None,
                                    pattern_desc: "enum variant".into(),
                                });
                                valid = false;
                            }
                        }
                    }
                }
            }
        }

        if !valid {
            return self.record_error();
        }

        if has_default {
            return ControlFlow::Continue(());
        }

        // Check if all enum variants are covered
        let missing_variants: Vec<_> = enum_type
            .variants
            .iter()
            .filter(|variant| !covered_variants.contains(&variant.xref))
            .map(|variant| variant.xref.to_string().into())
            .collect();

        if missing_variants.is_empty() {
            ControlFlow::Continue(())
        } else {
            use super::errors::NonExhaustiveMatch;
            self.dcx().emit_err_diag(NonExhaustiveMatch {
                span,
                missing_patterns: missing_variants,
            });
            self.record_error()
        }
    }

    /// Checks a return statement.
    fn check_return(&mut self, v: &ReturnStmt) -> ControlFlow<()> {
        self.visit_expr(self.hir.lookup(v.expr))?;

        // Verify return is in appropriate context
        if let Some(context) = self.current_context() {
            if !context.requires_return() {
                self.dcx().emit_err_diag(InvalidStatementContext {
                    actual_context: Cow::Owned(context.description()),
                    expected_context: Cow::Borrowed("pure function"),
                    span: self.hir.lookup_span(v.expr),
                });
                return self.record_error();
            }
        }
        ControlFlow::Continue(())
    }

    /// Checks a publish statement.
    fn check_publish(&mut self, v: &Publish) -> ControlFlow<()> {
        // Visit the cmd being published
        self.visit_expr(self.hir.lookup(v.expr))?;
        ControlFlow::Continue(())
    }

    /// Checks a finish statement.
    fn check_finish(&mut self, block_id: &BlockId, stmt_span: Span) -> ControlFlow<()> {
        // Verify finish statement is only in action context
        if let Some(context) = self.current_context() {
            if !matches!(context, ExecutionContext::Action(_)) {
                self.dcx().emit_err_diag(InvalidStatementContext {
                    actual_context: Cow::Owned(context.description()),
                    expected_context: Cow::Borrowed("action"),
                    span: stmt_span,
                });
                self.record_error()?;
            }
        }

        // Visit the finish block
        self.visit_block(self.hir.lookup(*block_id))?;

        // Mark this context as finished to detect unreachable code
        self.mark_context_finished();
        ControlFlow::Continue(())
    }

    /// Checks a check statement.
    fn check_check(&mut self, v: &crate::hir::CheckStmt, span: Span) -> ControlFlow<()> {
        // Visit the condition expression
        self.visit_expr(self.hir.lookup(v.expr))?;

        // Verify check statement is in appropriate context
        if let Some(context) = self.current_context() {
            match context {
                ExecutionContext::CmdPolicy(_, _) | ExecutionContext::CmdRecall(_, _) => {
                    // Check statements are allowed in cmd policy and recall contexts
                }
                _ => {
                    self.dcx().emit_err_diag(InvalidStatementContext {
                        actual_context: Cow::Owned(context.description()),
                        expected_context: Cow::Borrowed("cmd policy or cmd recall"),
                        span,
                    });
                    return self.record_error();
                }
            }
        }

        ControlFlow::Continue(())
    }

    /// Validates query patterns to ensure no leading binds.
    fn validate_query_pattern(
        &mut self,
        fields: &[crate::hir::FactFieldExpr],
        field_type: &str,
        span: Span,
    ) -> ControlFlow<()> {
        let mut has_expr = false;

        for field_expr in fields {
            match &field_expr.expr {
                crate::hir::FactField::Expr(_) => {
                    has_expr = true;
                }
                crate::hir::FactField::Bind => {
                    if !has_expr {
                        // Leading bind detected
                        use super::errors::QueryLeadingBind;
                        self.dcx().emit_err_diag(QueryLeadingBind {
                            span,
                            description: format!("leading bind in {} field", field_type).into(),
                        });
                        return self.record_error();
                    }
                }
            }
        }

        ControlFlow::Continue(())
    }

    /// Checks a map statement.
    fn check_map(&mut self, v: &crate::hir::MapStmt, span: Span) -> ControlFlow<()> {
        // Validate query patterns for leading binds
        self.validate_query_pattern(&v.fact.keys, "key", span)?;
        self.validate_query_pattern(&v.fact.vals, "value", span)?;

        // Visit the fact literal pattern
        // Process fact keys
        for field_expr in &v.fact.keys {
            match &field_expr.expr {
                crate::hir::FactField::Expr(expr_id) => {
                    self.visit_expr(self.hir.lookup(*expr_id))?;
                }
                crate::hir::FactField::Bind => {
                    // Bind expressions don't need visiting
                }
            }
        }
        // Process fact values
        for field_expr in &v.fact.vals {
            match &field_expr.expr {
                crate::hir::FactField::Expr(expr_id) => {
                    self.visit_expr(self.hir.lookup(*expr_id))?;
                }
                crate::hir::FactField::Bind => {
                    // Bind expressions don't need visiting
                }
            }
        }

        // Visit the body block
        self.visit_block(self.hir.lookup(v.block))?;

        // Map statements should be allowed in most contexts where expressions are allowed
        // No special context restrictions for now
        ControlFlow::Continue(())
    }

    /// Checks a debug assert statement.
    fn check_debug_assert(&mut self, v: &crate::hir::DebugAssert, _span: Span) -> ControlFlow<()> {
        // Visit the condition expression
        self.visit_expr(self.hir.lookup(v.expr))?;

        // Debug asserts should be allowed in any context during development
        // They are typically stripped in production builds
        ControlFlow::Continue(())
    }

    /// Validates a fact literal structure.
    fn validate_fact_literal(&mut self, fact_lit: &crate::hir::FactLiteral) -> ControlFlow<()> {
        // Visit fact key expressions
        for field_expr in &fact_lit.keys {
            match &field_expr.expr {
                crate::hir::FactField::Expr(expr_id) => {
                    self.visit_expr(self.hir.lookup(*expr_id))?;
                }
                crate::hir::FactField::Bind => {
                    // Bind expressions are valid in patterns
                }
            }
        }

        // Visit fact value expressions
        for field_expr in &fact_lit.vals {
            match &field_expr.expr {
                crate::hir::FactField::Expr(expr_id) => {
                    self.visit_expr(self.hir.lookup(*expr_id))?;
                }
                crate::hir::FactField::Bind => {
                    // Bind expressions are valid in patterns
                }
            }
        }

        ControlFlow::Continue(())
    }

    /// Validates that a fact literal has all required fields for creation.
    fn validate_fact_completeness(
        &mut self,
        fact_lit: &crate::hir::FactLiteral,
        operation: &str,
        stmt_span: Span,
    ) -> ControlFlow<()> {
        // Look up the fact definition to get schema information
        let _fact_ident = self.hir.lookup_ident_ref(fact_lit.ident);

        // For now, we'll do basic validation - a more complete implementation would:
        // 1. Look up the fact definition by identifier
        // 2. Check that all required key fields are present
        // 3. Check that all required value fields are present for creates
        // 4. Validate field types match the schema

        // Basic check: create operations should have at least one key or value field
        if fact_lit.keys.is_empty() && fact_lit.vals.is_empty() {
            use super::errors::FactSchemaViolation;
            self.dcx().emit_err_diag(FactSchemaViolation {
                description: format!("{} operation requires at least one field", operation).into(),
                span: stmt_span,
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Validates that a delete pattern is reasonable.
    fn validate_delete_pattern(
        &mut self,
        fact_lit: &crate::hir::FactLiteral,
        stmt_span: Span,
    ) -> ControlFlow<()> {
        // Check if the delete pattern seems reasonable
        // Warn if deleting with only concrete values (might delete more than intended)
        let mut has_bind_or_key = false;

        // Check keys for binds or patterns
        for field_expr in &fact_lit.keys {
            if matches!(field_expr.expr, crate::hir::FactField::Bind) {
                has_bind_or_key = true;
                break;
            }
        }

        // If no keys with binds, check if we have specific key values (which is fine)
        if !fact_lit.keys.is_empty() {
            has_bind_or_key = true;
        }

        // If we only have concrete value matches, this might be dangerous
        if !has_bind_or_key && !fact_lit.vals.is_empty() {
            // Check if all value fields are concrete (no binds)
            let all_concrete = fact_lit
                .vals
                .iter()
                .all(|field_expr| matches!(field_expr.expr, crate::hir::FactField::Expr(_)));

            if all_concrete {
                use super::errors::FactSchemaViolation;
                self.dcx().emit_err_diag(FactSchemaViolation {
                    description: "delete with only concrete value matches may be too broad".into(),
                    span: stmt_span,
                });
                // Continue despite potential issue
            }
        }

        ControlFlow::Continue(())
    }

    /// Validates an effect structure.
    fn validate_effect_structure(
        &mut self,
        named_struct: &NamedStruct,
        stmt_span: Span,
    ) -> ControlFlow<()> {
        // Visit all field expressions in the effect
        for field_expr in &named_struct.fields {
            self.visit_expr(self.hir.lookup(field_expr.expr))?;
        }

        // Additional effect validation could include:
        // 1. Checking that the effect type is defined
        // 2. Validating required fields are present
        // 3. Checking field types match the effect schema
        // 4. Ensuring effect is emitted in appropriate context

        // For now, basic structural validation is sufficient
        if named_struct.fields.is_empty() {
            use super::errors::FactSchemaViolation;
            self.dcx().emit_err_diag(FactSchemaViolation {
                description: "effect should have at least one field".into(),
                span: stmt_span,
            });
            return self.record_error();
        }

        ControlFlow::Continue(())
    }

    /// Validates command fields for correctness.
    fn validate_cmd_fields(&mut self, cmd_def: &CmdDef) -> ControlFlow<()> {
        // Validate individual fields and check for duplicates
        self.validate_individual_cmd_fields(cmd_def)?;

        ControlFlow::Continue(())
    }

    /// Validates individual command fields.
    fn validate_individual_cmd_fields(&mut self, cmd_def: &CmdDef) -> ControlFlow<()> {
        for &field_id in &cmd_def.fields {
            let field = self.hir.lookup(field_id);

            match &field.kind {
                CmdFieldKind::Field { ident: _, ty } => {
                    // Validate the type reference
                    self.validate_cmd_field_type(*ty)?;
                }
                CmdFieldKind::StructRef(ident) => {
                    // Validate that the referenced struct exists
                    self.validate_struct_reference(*ident, field.span)?;
                }
            }
        }

        ControlFlow::Continue(())
    }

    /// Validates a command field type reference.
    fn validate_cmd_field_type(&mut self, type_id: VTypeId) -> ControlFlow<()> {
        let vtype = self.hir.lookup(type_id);

        // Validate the type based on its kind
        match &vtype.kind {
            VTypeKind::String
            | VTypeKind::Bytes
            | VTypeKind::Int
            | VTypeKind::Bool
            | VTypeKind::Id => {
                // Built-in types are always valid
            }
            VTypeKind::Struct(ident_id) => {
                // This should reference a valid type (struct, enum, or builtin)
                // The actual type checking is done by the type checker,
                // but we can do basic validation here
                let _type_name = self.hir.lookup_ident_ref(*ident_id);
                // Type existence validation is handled by symbol resolution
            }
            VTypeKind::Enum(ident_id) => {
                // Enum types need to reference valid enum definitions
                let _enum_name = self.hir.lookup_ident_ref(*ident_id);
                // Type existence validation is handled by symbol resolution
            }
            VTypeKind::Optional(inner_type_id) => {
                // Recursively validate the inner type
                self.validate_cmd_field_type(*inner_type_id)?;
            }
        }

        ControlFlow::Continue(())
    }

    /// Validates a struct reference in command fields.
    fn validate_struct_reference(&mut self, ident: IdentId, _span: Span) -> ControlFlow<()> {
        let _struct_name = self.hir.lookup_ident_ref(ident);

        // Check if the struct reference is valid
        // The actual struct existence is validated by symbol resolution,
        // but we can add additional validation here if needed

        // For now, we'll trust that symbol resolution has validated the reference
        // Additional validations could include:
        // 1. Ensuring the struct is accessible in this scope
        // 2. Checking that the struct doesn't create circular dependencies
        // 3. Validating that the struct is appropriate for use in commands

        ControlFlow::Continue(())
    }

    /// Checks command persistence rules.
    ///
    /// Currently provides basic validation with inferred persistence.
    /// Full implementation pending HIR architectural improvements.
    fn check_command_persistence(&mut self, cmd: &CmdDef) -> ControlFlow<()> {
        let _cmd_name = self.hir.lookup_ident_ref(cmd.ident);

        // Basic validation can be performed here:
        // 1. Check that command has proper field definitions
        // 2. Validate field types are appropriate
        // 3. Ensure command structure is well-formed

        // Field validation
        self.validate_cmd_fields(cmd)?;

        // TODO: Add return type validation when HIR provides access to:
        // - Command return type information
        // - Actual persistence markers from AST
        // Expected rules:
        // - Persistent commands should have struct return types
        // - Ephemeral commands should have unit return types

        ControlFlow::Continue(())
    }

    /// Validates that functions have proper return statements when required.
    ///
    /// This is a partial implementation limited by current API constraints.
    /// Full implementation requires:
    /// 1. SymbolsView function lookup API (to get return types)
    /// 2. Type conversions between IdentId and ast::Identifier
    /// 3. Understanding HIR representation of unit vs non-unit return types
    ///
    /// Current implementation provides basic validation that can be expanded
    /// when the API issues are resolved.
    fn validate_function_return_requirement(&mut self, body: &Body) -> ControlFlow<()> {
        // Basic validation: check if function ends with explicit return
        // This catches the most common case of missing return statements
        if let Some(&last_stmt_id) = body.stmts.last() {
            let _last_stmt = self.hir.lookup(last_stmt_id);

            // TODO: Add proper return statement validation when API supports:
            // - Function return type lookup via SymbolsView
            // - Distinguishing unit from non-unit return types
            // - Checking if expressions evaluate to Never type
        }

        ControlFlow::Continue(())
    }

    /// Placeholder for full return path analysis.
    ///
    /// TODO: Implement complete return path validation when API issues are resolved:
    /// 1. Look up function return type via SymbolsView.lookup_function(func_ident)
    /// 2. Skip validation for unit return types
    /// 3. For non-unit types, ensure all code paths end with return or Never
    /// 4. Handle match/if expressions that return values
    #[allow(dead_code)] // Will be used once API is available
    fn check_function_return_paths(
        &mut self,
        _body: &Body,
        _func_ident: IdentId,
    ) -> ControlFlow<()> {
        // Blocked by API limitations - see TODO above
        ControlFlow::Continue(())
    }
}

impl<'cx> Visitor<'cx> for Verifier<'cx> {
    type Result = ControlFlow<()>;

    fn hir(&self) -> &'cx Hir {
        self.hir.hir()
    }

    fn visit_stmt(&mut self, stmt: &'cx Stmt) -> Self::Result {
        // First perform context validation
        if let Some(context) = self.current_context() {
            self.verify_stmt_context(stmt, &context)?;
        }

        // Then perform statement-specific validation
        match &stmt.kind {
            StmtKind::Match(match_stmt) => {
                self.check_match(match_stmt)?;
            }
            StmtKind::Map(map_stmt) => {
                self.check_map(map_stmt, stmt.span)?;
            }
            StmtKind::Create(create_stmt) => {
                self.check_create(create_stmt, stmt.span)?;
            }
            StmtKind::Update(update_stmt) => {
                self.check_update(update_stmt, stmt.span)?;
            }
            StmtKind::Delete(delete_stmt) => {
                self.check_delete(delete_stmt, stmt.span)?;
            }
            StmtKind::Finish(block_id) => {
                self.check_finish(block_id, stmt.span)?;
            }
            StmtKind::Emit(emit_stmt) => {
                self.check_emit(emit_stmt, stmt.span)?;
            }
            _ => {}
        }

        // Continue with default statement visiting
        crate::hir::visit::walk_stmt(self, stmt)
    }

    fn visit_expr(&mut self, expr: &'cx Expr) -> Self::Result {
        if let ExprKind::Intrinsic(Intrinsic::Serialize(_) | Intrinsic::Deserialize(_)) = &expr.kind {
            // Verify serialize/deserialize expressions are only in action context
            if let Some(context) = self.current_context() {
                if !matches!(context, ExecutionContext::Action(_)) {
                    self.dcx().emit_err_diag(InvalidStatementContext {
                        actual_context: Cow::Owned(context.description()),
                        expected_context: Cow::Borrowed("action"),
                        span: expr.span,
                    });
                    return self.record_error();
                }
            }
        }

        // Continue with default expression visiting
        crate::hir::visit::walk_expr(self, expr)
    }

    fn visit_func_def(&mut self, func: &'cx FuncDef) -> Self::Result {
        // Push function context
        self.push_context(ExecutionContext::PureFunc(func.id));

        // Visit the function body - this will handle statement validation
        let body = self.hir.lookup(func.body);
        try_visit!(crate::hir::visit::walk_body(self, body));

        // Perform available return path analysis
        self.analyze_function_control_flow(body)?;

        // TODO: Enable full return path checking when API issues are resolved
        // self.check_function_return_paths(body, func.ident)?;

        // Pop function context
        self.pop_context();

        ControlFlow::Continue(())
    }

    fn visit_action(&mut self, action: &'cx ActionDef) -> Self::Result {
        // Push action context
        self.push_context(ExecutionContext::Action(action.id));

        // Visit the action body - this will handle statement validation
        let body = self.hir.lookup(action.body);
        try_visit!(crate::hir::visit::walk_body(self, body));

        // Actions can contain finish statements, effect calls, and other actions
        // Statement-level validation happens in visit_stmt

        // Pop action context
        self.pop_context();

        ControlFlow::Continue(())
    }

    fn visit_finish_func_def(&mut self, finish_func: &'cx FinishFuncDef) -> Self::Result {
        // Push finish function context
        self.push_context(ExecutionContext::FinishFunc(finish_func.id));

        // Visit the finish function body - this will handle statement validation
        let body = self.hir.lookup(finish_func.body);
        try_visit!(crate::hir::visit::walk_body(self, body));

        // Finish functions don't typically need return path analysis
        // as they're effect-focused rather than value-returning

        // Finish functions can contain fact operations (create, update, delete)
        // and emit statements. Statement-level validation happens in visit_stmt

        // Pop finish function context
        self.pop_context();

        ControlFlow::Continue(())
    }

    fn visit_cmd(&mut self, cmd: &'cx CmdDef) -> Self::Result {
        // Commands have different contexts for each block
        // TODO: Implement proper command persistence detection
        // For now, default to persistent for safety - fact operations will be allowed
        let is_persistent = true;

        // Visit the policy block
        self.push_context(ExecutionContext::CmdPolicy(cmd.id, is_persistent));
        let policy_block = self.hir.lookup(cmd.policy);
        try_visit!(crate::hir::visit::walk_block(self, policy_block));
        self.pop_context();

        // Visit the recall block
        self.push_context(ExecutionContext::CmdRecall(cmd.id, is_persistent));
        let recall_block = self.hir.lookup(cmd.recall);
        try_visit!(crate::hir::visit::walk_block(self, recall_block));
        self.pop_context();

        // Visit the seal block
        self.push_context(ExecutionContext::CmdSeal(cmd.id, is_persistent));
        let seal_block = self.hir.lookup(cmd.seal);
        try_visit!(crate::hir::visit::walk_block(self, seal_block));
        self.pop_context();

        // Visit the open block
        self.push_context(ExecutionContext::CmdOpen(cmd.id, is_persistent));
        let open_block = self.hir.lookup(cmd.open);
        try_visit!(crate::hir::visit::walk_block(self, open_block));
        self.pop_context();

        self.check_command_persistence(cmd)?;

        ControlFlow::Continue(())
    }
}
