//! NOTE FOR AI: IGNORE THIS FILE.

use std::{collections::HashMap, mem};

use slotmap::SlotMap;

use crate::hir::{
    ActionArg, ActionArgId, ActionDef, ActionId, Block, BlockId, CmdDef, CmdField, CmdFieldId,
    CmdId, EffectDef, EffectField, EffectFieldId, EffectId, EnumDef, EnumId, Expr, ExprId,
    ExprKind, FactDef, FactField, FactId, FactKey, FactKeyId, FactLiteral, FactVal, FactValId,
    FfiEnumDef, FfiEnumId, FfiFuncDef, FfiFuncId, FfiImportDef, FfiImportId, FfiModuleDef,
    FfiModuleId, FfiStructDef, FfiStructId, FinishFuncArg, FinishFuncArgId, FinishFuncDef,
    FinishFuncId, FuncArg, FuncArgId, FuncDef, FuncId, GlobalId, GlobalLetDef, Hir, Ident, IdentId,
    IfBranch, IfStmt, Intrinsic, LetStmt, MatchArm, MatchExpr, MatchExprArm, MatchPattern,
    MatchStmt, ReturnStmt, Span, Stmt, StmtId, StmtKind, StructDef, StructField, StructFieldId,
    StructId, Ternary, VType, VTypeId,
};

impl Hir {
    /// Normalizes the HIR.
    pub fn normalize(self) -> NormalizedHir {
        let normalizer = Normalizer::new();
        normalizer.walk_hir(self)
    }
}

/// A normalizer that walks the HIR and applies transformations.
struct Normalizer {
    hir: NormalizedHir,
}

/// Analysis result for a block's return structure.
#[derive(Debug)]
struct ReturnShape {
    /// Whether all paths through the block return.
    all_paths_return: bool,
    /// Whether the block can be converted to a pure expression.
    expressionizable: bool,
    /// Index of the first return statement, if any.
    first_return_index: Option<usize>,
}

/// Reasons why a block cannot be converted to an expression.
#[derive(Debug)]
enum NotExpressionizable {
    /// Block contains a check statement.
    HasCheck,
    /// Block contains other non-pure statements.
    HasNonPureStatement,
    /// Block has no return statement.
    NoReturn,
    /// Branch analysis failed.
    BranchAnalysisFailed,
}

impl Normalizer {
    fn new() -> Self {
        Self {
            hir: NormalizedHir::default(),
        }
    }

    /// Walk the entire HIR and apply normalizations.
    fn walk_hir(mut self, mut old: Hir) -> NormalizedHir {
        // Transfer HIR nodes that
        // 1. Do not have any `Expr`, `Stmt`, or `Block`
        //    references.
        // 2. Do not reference any HIR nodes that have `Expr`,
        //    `Stmt`, or `Block` references.
        self.hir.effect_fields = mem::take(&mut old.effect_fields);
        self.hir.effects = mem::take(&mut old.effects);
        self.hir.enums = mem::take(&mut old.enums);
        self.hir.fact_keys = mem::take(&mut old.fact_keys);
        self.hir.fact_vals = mem::take(&mut old.fact_vals);
        self.hir.facts = mem::take(&mut old.facts);
        self.hir.ffi_enums = mem::take(&mut old.ffi_enums);
        self.hir.ffi_funcs = mem::take(&mut old.ffi_funcs);
        self.hir.ffi_imports = mem::take(&mut old.ffi_imports);
        self.hir.ffi_modules = mem::take(&mut old.ffi_modules);
        self.hir.ffi_structs = mem::take(&mut old.ffi_structs);
        self.hir.idents = mem::take(&mut old.idents);
        self.hir.struct_fields = mem::take(&mut old.struct_fields);
        self.hir.structs = mem::take(&mut old.structs);
        self.hir.types = mem::take(&mut old.types);

        // Move the remaining items we need to walk
        let actions = mem::take(&mut old.actions);
        let action_args = mem::take(&mut old.action_args);
        let cmds = mem::take(&mut old.cmds);
        let cmd_fields = mem::take(&mut old.cmd_fields);
        let finish_funcs = mem::take(&mut old.finish_funcs);
        let finish_func_args = mem::take(&mut old.finish_func_args);
        let funcs = mem::take(&mut old.funcs);
        let func_args = mem::take(&mut old.func_args);
        let global_lets = mem::take(&mut old.global_lets);

        for def in global_lets.values() {
            let expr = self.walk_expr(def.expr, &mut old);
            self.hir.global_lets.insert_with_key(|id| GlobalLetDef {
                id,
                span: def.span,
                ident: def.ident,
                expr,
            });
        }

        // Transfer arg collections
        self.hir.action_args = action_args;
        self.hir.cmd_fields = cmd_fields;
        self.hir.finish_func_args = finish_func_args;
        self.hir.func_args = func_args;

        // Process actions
        for (_id, mut action) in actions {
            action.block = self.walk_block(action.block, &mut old);
            self.hir.actions.insert(action);
        }

        // Process commands
        for (_id, mut cmd) in cmds {
            cmd.seal = self.walk_block(cmd.seal, &mut old);
            cmd.open = self.walk_block(cmd.open, &mut old);
            cmd.policy = self.walk_block(cmd.policy, &mut old);
            cmd.recall = self.walk_block(cmd.recall, &mut old);
            self.hir.cmds.insert(cmd);
        }

        // Process finish functions
        for (_id, mut func) in finish_funcs {
            func.block = self.walk_block(func.block, &mut old);
            self.hir.finish_funcs.insert(func);
        }

        // Process regular functions with return normalization
        for (_id, mut func) in funcs {
            func.block = self.normalize_function_returns(func.block, func.result, &mut old);
            self.hir.funcs.insert(func);
        }

        self.hir
    }

    /// Normalize returns in a function block.
    fn normalize_function_returns(
        &mut self,
        block_id: BlockId,
        result_type: VTypeId,
        old: &mut Hir,
    ) -> BlockId {
        // First walk the block normally
        let new_block_id = self.walk_block(block_id, old);

        // Now check if normalization is needed
        let needs_normalization = self.block_needs_return_normalization(new_block_id);

        if needs_normalization {
            self.transform_block_returns(new_block_id, result_type)
        } else {
            new_block_id
        }
    }

    /// Check if a block needs return normalization.
    fn block_needs_return_normalization(&self, block_id: BlockId) -> bool {
        let block = &self.hir.blocks[block_id];

        // Check if there are any early returns (returns before the last statement)
        for (i, &stmt_id) in block.stmts.iter().enumerate() {
            let stmt = &self.hir.stmts[stmt_id];
            if matches!(stmt.kind, StmtKind::Return(_)) && i < block.stmts.len() - 1 {
                return true;
            }

            // Also check nested blocks for early returns
            match &stmt.kind {
                StmtKind::If(if_stmt) => {
                    for branch in &if_stmt.branches {
                        if self.block_has_return(branch.block) {
                            return true;
                        }
                    }
                    if let Some(else_block) = if_stmt.else_block {
                        if self.block_has_return(else_block) {
                            return true;
                        }
                    }
                }
                StmtKind::Map(map_stmt) => {
                    if self.block_has_return(map_stmt.block) {
                        return true;
                    }
                }
                StmtKind::Finish(block) => {
                    if self.block_has_return(*block) {
                        return true;
                    }
                }
                _ => {}
            }
        }

        // Check if the last statement is not a return
        if let Some(&last_stmt_id) = block.stmts.last() {
            let last_stmt = &self.hir.stmts[last_stmt_id];
            !matches!(last_stmt.kind, StmtKind::Return(_))
        } else {
            true // Empty block needs a return
        }
    }

    /// Check if a block contains any return statements.
    fn block_has_return(&self, block_id: BlockId) -> bool {
        let block = &self.hir.blocks[block_id];
        block.stmts.iter().any(|&stmt_id| {
            let stmt = &self.hir.stmts[stmt_id];
            matches!(stmt.kind, StmtKind::Return(_))
        })
    }

    /// Transform a block to have a single return at the end.
    fn transform_block_returns(&mut self, block_id: BlockId, _result_type: VTypeId) -> BlockId {
        // Analyze the block to determine which tier to use
        let shape = self.analyze_block(block_id);

        // Try Tier 1: Expression synthesis
        if shape.expressionizable {
            let mut env = HashMap::new();
            if let Ok(expr) = self.build_return_expr(block_id, &mut env) {
                // Create a new block with a single return
                let return_stmt = self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: Span::dummy(),
                    kind: StmtKind::Return(ReturnStmt { expr }),
                });

                return self.hir.blocks.insert_with_key(|id| Block {
                    id,
                    span: Span::dummy(),
                    stmts: vec![return_stmt],
                });
            }
        }

        // Fall back to Tier 2: Structural transformation
        self.structure_tail_returns(block_id)
    }

    /// Analyze a block to determine its return shape.
    fn analyze_block(&self, block_id: BlockId) -> ReturnShape {
        let block = &self.hir.blocks[block_id];
        let mut all_paths_return = false;
        let mut expressionizable = true;
        let mut first_return_index = None;

        for (i, &stmt_id) in block.stmts.iter().enumerate() {
            let stmt = &self.hir.stmts[stmt_id];

            match &stmt.kind {
                StmtKind::Return(_) => {
                    if first_return_index.is_none() {
                        first_return_index = Some(i);
                    }
                    all_paths_return = true;
                    // A return makes everything after it unreachable
                    break;
                }
                StmtKind::Let(_) => {
                    // Let statements are pure and can be inlined
                }
                StmtKind::Check(_) => {
                    // Check statements cannot be expressed as expressions
                    expressionizable = false;
                }
                StmtKind::If(if_stmt) => {
                    // Analyze all branches
                    let mut all_branches_return = true;
                    let mut all_branches_expressionizable = true;

                    for branch in &if_stmt.branches {
                        let branch_shape = self.analyze_block(branch.block);
                        all_branches_return &= branch_shape.all_paths_return;
                        all_branches_expressionizable &= branch_shape.expressionizable;
                    }

                    if let Some(else_block) = if_stmt.else_block {
                        let else_shape = self.analyze_block(else_block);
                        all_branches_return &= else_shape.all_paths_return;
                        all_branches_expressionizable &= else_shape.expressionizable;
                    } else {
                        // No else block means not all paths return
                        all_branches_return = false;
                    }

                    if all_branches_return {
                        all_paths_return = true;
                        if first_return_index.is_none() {
                            first_return_index = Some(i);
                        }
                        // Everything after is unreachable
                        break;
                    }

                    if !all_branches_expressionizable {
                        expressionizable = false;
                    }
                }
                _ => {
                    // Other statements are not allowed in functions or make it non-expressionizable
                    expressionizable = false;
                }
            }
        }

        // If there are no returns at all, it's not expressionizable
        if first_return_index.is_none() {
            expressionizable = false;
        }

        ReturnShape {
            all_paths_return,
            expressionizable,
            first_return_index,
        }
    }

    /// Build a return expression from a block (Tier 1).
    fn build_return_expr(
        &mut self,
        block_id: BlockId,
        env: &mut HashMap<IdentId, ExprId>,
    ) -> Result<ExprId, NotExpressionizable> {
        // Clone the statements to avoid borrow issues
        let stmts = self.hir.blocks[block_id].stmts.clone();

        for stmt_id in stmts {
            // Clone the statement kind to work with it
            let stmt_kind = self.hir.stmts[stmt_id].kind.clone();

            match stmt_kind {
                StmtKind::Return(ret) => {
                    // Substitute any let bindings in the return expression
                    return Ok(self.substitute_expr(ret.expr, env));
                }
                StmtKind::Let(let_stmt) => {
                    // Add the binding to our substitution environment
                    let substituted_expr = self.substitute_expr(let_stmt.expr, env);
                    env.insert(let_stmt.ident, substituted_expr);
                }
                StmtKind::If(if_stmt) => {
                    // All branches must be expressionizable
                    let mut branches = Vec::new();

                    for branch in &if_stmt.branches {
                        let mut branch_env = env.clone();
                        let branch_expr = self.build_return_expr(branch.block, &mut branch_env)?;
                        let cond = self.substitute_expr(branch.expr, env);
                        branches.push((cond, branch_expr));
                    }

                    let else_expr = if let Some(else_block) = if_stmt.else_block {
                        let mut else_env = env.clone();
                        self.build_return_expr(else_block, &mut else_env)?
                    } else {
                        return Err(NotExpressionizable::BranchAnalysisFailed);
                    };

                    // Build nested ternaries from the branches
                    let result = branches
                        .into_iter()
                        .rev()
                        .fold(else_expr, |acc, (cond, expr)| {
                            self.hir.exprs.insert_with_key(|id| Expr {
                                id,
                                span: Span::dummy(),
                                kind: ExprKind::Ternary(Ternary {
                                    cond,
                                    true_expr: expr,
                                    false_expr: acc,
                                }),
                            })
                        });

                    return Ok(result);
                }
                StmtKind::Check(_) => {
                    return Err(NotExpressionizable::HasCheck);
                }
                _ => {
                    return Err(NotExpressionizable::HasNonPureStatement);
                }
            }
        }

        Err(NotExpressionizable::NoReturn)
    }

    /// Substitute let bindings in an expression.
    fn substitute_expr(&mut self, expr_id: ExprId, env: &HashMap<IdentId, ExprId>) -> ExprId {
        let expr = &self.hir.exprs[expr_id];

        match &expr.kind {
            ExprKind::Identifier(ident) => {
                // If this identifier is in our environment,
                // substitute it
                if let Some(&substituted) = env.get(ident) {
                    substituted
                } else {
                    expr_id
                }
            }
            // For compound expressions, recursively substitute
            ExprKind::Add(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Add(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::Sub(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Sub(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::And(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::And(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::Or(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Or(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::Equal(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Equal(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::NotEqual(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::NotEqual(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::GreaterThan(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::GreaterThan(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::LessThan(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::LessThan(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::GreaterThanOrEqual(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::GreaterThanOrEqual(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::LessThanOrEqual(lhs, rhs) => {
                let new_lhs = self.substitute_expr(*lhs, env);
                let new_rhs = self.substitute_expr(*rhs, env);
                if new_lhs == *lhs && new_rhs == *rhs {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::LessThanOrEqual(new_lhs, new_rhs),
                    })
                }
            }
            ExprKind::Ternary(ternary) => {
                let new_cond = self.substitute_expr(ternary.cond, env);
                let new_true = self.substitute_expr(ternary.true_expr, env);
                let new_false = self.substitute_expr(ternary.false_expr, env);
                if new_cond == ternary.cond
                    && new_true == ternary.true_expr
                    && new_false == ternary.false_expr
                {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Ternary(Ternary {
                            cond: new_cond,
                            true_expr: new_true,
                            false_expr: new_false,
                        }),
                    })
                }
            }
            ExprKind::Not(expr) => {
                let new_expr = self.substitute_expr(*expr, env);
                if new_expr == *expr {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Not(new_expr),
                    })
                }
            }
            ExprKind::Negative(expr) => {
                let new_expr = self.substitute_expr(*expr, env);
                if new_expr == *expr {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Negative(new_expr),
                    })
                }
            }
            ExprKind::Dot(expr, field) => {
                let new_expr = self.substitute_expr(*expr, env);
                if new_expr == *expr {
                    expr_id
                } else {
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::Dot(new_expr, *field),
                    })
                }
            }
            ExprKind::FunctionCall(mut call) => {
                let mut changed = false;
                let new_args = call
                    .args
                    .iter()
                    .map(|&arg| {
                        let new_arg = self.substitute_expr(arg, env);
                        if new_arg != arg {
                            changed = true;
                        }
                        new_arg
                    })
                    .collect();

                if changed {
                    call.args = new_args;
                    self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: expr.span,
                        kind: ExprKind::FunctionCall(call),
                    })
                } else {
                    expr_id
                }
            }
            // For literals and other simple expressions, no substitution needed
            _ => expr_id,
        }
    }

    /// Structure a block to ensure it ends with a return (Tier 2).
    fn structure_tail_returns(&mut self, block_id: BlockId) -> BlockId {
        let shape = self.analyze_block(block_id);

        // Extract necessary data to avoid borrow checker issues
        let (stmts, span, already_ends_with_return) = {
            let block = &self.hir.blocks[block_id];
            let ends_with_return = if let Some(&last_stmt_id) = block.stmts.last() {
                let last_stmt = &self.hir.stmts[last_stmt_id];
                matches!(last_stmt.kind, StmtKind::Return(_))
            } else {
                false
            };
            (block.stmts.clone(), block.span, ends_with_return)
        };

        // If the block already ends with a return, we're done
        if already_ends_with_return {
            return block_id;
        }

        // If there's an if statement that returns on all paths, make it the last statement
        if let Some(index) = shape.first_return_index {
            if index < stmts.len() - 1 {
                // There are unreachable statements after the return
                let mut new_stmts = stmts[..=index].to_vec();

                // Wrap unreachable statements in if false { ... }
                let unreachable_stmts = stmts[index + 1..].to_vec();
                if !unreachable_stmts.is_empty() {
                    let unreachable_block = self.hir.blocks.insert_with_key(|id| Block {
                        id,
                        span: Span::dummy(),
                        stmts: unreachable_stmts,
                    });

                    let false_expr = self.hir.exprs.insert_with_key(|id| Expr {
                        id,
                        span: Span::dummy(),
                        kind: ExprKind::Bool(false),
                    });

                    let if_false = self.hir.stmts.insert_with_key(|id| Stmt {
                        id,
                        span: Span::dummy(),
                        kind: StmtKind::If(IfStmt {
                            branches: vec![IfBranch {
                                expr: false_expr,
                                block: unreachable_block,
                            }],
                            else_block: None,
                        }),
                    });

                    new_stmts.push(if_false);
                }

                return self.hir.blocks.insert_with_key(|id| Block {
                    id,
                    span,
                    stmts: new_stmts,
                });
            }
        }

        // Handle if statements with partial returns
        let mut new_stmts = Vec::new();
        let mut i = 0;

        while i < stmts.len() {
            let stmt_id = stmts[i];
            let has_if = {
                let stmt = &self.hir.stmts[stmt_id];
                matches!(stmt.kind, StmtKind::If(_))
            };

            if has_if {
                // Clone the if statement to work with it
                let if_stmt = {
                    let stmt = &self.hir.stmts[stmt_id];
                    if let StmtKind::If(ref if_stmt) = stmt.kind {
                        if_stmt.clone()
                    } else {
                        unreachable!()
                    }
                };

                if let Some(completed) = self.try_complete_if_returns(&if_stmt, &stmts[i + 1..]) {
                    new_stmts.push(completed);
                    // Everything after this if is now unreachable
                    let remaining = &stmts[i + 1..];
                    if !remaining.is_empty() {
                        let unreachable_block = self.hir.blocks.insert_with_key(|id| Block {
                            id,
                            span: Span::dummy(),
                            stmts: remaining.to_vec(),
                        });

                        let false_expr = self.hir.exprs.insert_with_key(|id| Expr {
                            id,
                            span: Span::dummy(),
                            kind: ExprKind::Bool(false),
                        });

                        let if_false = self.hir.stmts.insert_with_key(|id| Stmt {
                            id,
                            span: Span::dummy(),
                            kind: StmtKind::If(IfStmt {
                                branches: vec![IfBranch {
                                    expr: false_expr,
                                    block: unreachable_block,
                                }],
                                else_block: None,
                            }),
                        });

                        new_stmts.push(if_false);
                    }
                    break;
                }
            }

            new_stmts.push(stmt_id);
            i = i.saturating_add(1);
        }

        if new_stmts != stmts {
            self.hir.blocks.insert_with_key(|id| Block {
                id,
                span,
                stmts: new_stmts,
            })
        } else {
            block_id
        }
    }

    /// Try to complete an if statement so all branches return.
    fn try_complete_if_returns(&mut self, if_stmt: &IfStmt, suffix: &[StmtId]) -> Option<StmtId> {
        // Check which branches return
        let mut branch_returns = Vec::new();
        for branch in &if_stmt.branches {
            let shape = self.analyze_block(branch.block);
            branch_returns.push(shape.all_paths_return);
        }

        let else_returns = if let Some(else_block) = if_stmt.else_block {
            self.analyze_block(else_block).all_paths_return
        } else {
            false
        };

        // If all branches already return, nothing to do
        if branch_returns.iter().all(|&r| r) && else_returns {
            return None;
        }

        // If some branches return and we have a pure suffix, we can duplicate it
        if branch_returns.iter().any(|&r| r) || else_returns {
            // Check if the suffix is pure (only let and check statements)
            let suffix_is_pure = suffix.iter().all(|&stmt_id| {
                let stmt = &self.hir.stmts[stmt_id];
                matches!(stmt.kind, StmtKind::Let(_) | StmtKind::Check(_))
            });

            if suffix_is_pure && !suffix.is_empty() {
                // Duplicate the suffix into non-returning branches
                let mut new_branches = Vec::new();

                for (i, branch) in if_stmt.branches.iter().enumerate() {
                    if branch_returns[i] {
                        new_branches.push(IfBranch {
                            expr: branch.expr,
                            block: branch.block,
                        });
                    } else {
                        // Extract block data to avoid borrow issues
                        let (old_stmts, block_span) = {
                            let block = &self.hir.blocks[branch.block];
                            (block.stmts.clone(), block.span)
                        };

                        let mut new_stmts = old_stmts;
                        new_stmts.extend_from_slice(suffix);

                        let new_block = self.hir.blocks.insert_with_key(|id| Block {
                            id,
                            span: block_span,
                            stmts: new_stmts,
                        });

                        new_branches.push(IfBranch {
                            expr: branch.expr,
                            block: new_block,
                        });
                    }
                }

                let new_else = if let Some(else_block) = if_stmt.else_block {
                    if else_returns {
                        Some(else_block)
                    } else {
                        // Extract block data to avoid borrow issues
                        let (old_stmts, block_span) = {
                            let block = &self.hir.blocks[else_block];
                            (block.stmts.clone(), block.span)
                        };

                        let mut new_stmts = old_stmts;
                        new_stmts.extend_from_slice(suffix);

                        Some(self.hir.blocks.insert_with_key(|id| Block {
                            id,
                            span: block_span,
                            stmts: new_stmts,
                        }))
                    }
                } else {
                    // Create an else branch with the suffix
                    let new_block = self.hir.blocks.insert_with_key(|id| Block {
                        id,
                        span: Span::dummy(),
                        stmts: suffix.to_vec(),
                    });
                    Some(new_block)
                };

                return Some(self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: Span::dummy(),
                    kind: StmtKind::If(IfStmt {
                        branches: new_branches,
                        else_block: new_else,
                    }),
                }));
            }
        }

        None
    }

    /// Walk a block.
    fn walk_block(&mut self, block_id: BlockId, old: &mut Hir) -> BlockId {
        let mut block = old.blocks.remove(block_id).expect("block should exist");
        let new_stmts = block
            .stmts
            .iter()
            .map(|&stmt_id| self.walk_stmt(stmt_id, old))
            .collect();
        block.stmts = new_stmts;
        self.hir.blocks.insert(block)
    }

    /// Walk a statement, applying match normalization.
    fn walk_stmt(&mut self, stmt_id: StmtId, old: &mut Hir) -> StmtId {
        let stmt = old.stmts.remove(stmt_id).expect("stmt should exist");

        match stmt.kind {
            StmtKind::Match(ref match_stmt) => {
                // Transform match to if during the walk
                self.create_if_from_match(&stmt, match_stmt, old)
            }
            StmtKind::Let(mut let_stmt) => {
                let_stmt.expr = self.walk_expr(let_stmt.expr, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Let(let_stmt),
                })
            }
            StmtKind::Check(mut check) => {
                check.expr = self.walk_expr(check.expr, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Check(check),
                })
            }
            StmtKind::If(mut if_stmt) => {
                if_stmt.branches = if_stmt
                    .branches
                    .into_iter()
                    .map(|mut branch| {
                        branch.expr = self.walk_expr(branch.expr, old);
                        branch.block = self.walk_block(branch.block, old);
                        branch
                    })
                    .collect();

                if_stmt.else_block = if_stmt.else_block.map(|b| self.walk_block(b, old));

                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::If(if_stmt),
                })
            }
            StmtKind::Return(mut ret) => {
                ret.expr = self.walk_expr(ret.expr, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Return(ret),
                })
            }
            StmtKind::Finish(block_id) => {
                let new_block = self.walk_block(block_id, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Finish(new_block),
                })
            }
            StmtKind::Map(mut map_stmt) => {
                map_stmt.fact = self.walk_fact_literal(&map_stmt.fact, old);
                map_stmt.block = self.walk_block(map_stmt.block, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Map(map_stmt),
                })
            }
            StmtKind::ActionCall(mut action_call) => {
                action_call.args = action_call
                    .args
                    .into_iter()
                    .map(|arg| self.walk_expr(arg, old))
                    .collect();
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::ActionCall(action_call),
                })
            }
            StmtKind::Publish(mut publish) => {
                publish.exor = self.walk_expr(publish.exor, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Publish(publish),
                })
            }
            StmtKind::Create(mut create) => {
                create.fact = self.walk_fact_literal(&create.fact, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Create(create),
                })
            }
            StmtKind::Update(mut update) => {
                update.fact = self.walk_fact_literal(&update.fact, old);
                update.to = update
                    .to
                    .into_iter()
                    .map(|(ident, field)| (ident, self.walk_fact_field(&field, old)))
                    .collect();
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Update(update),
                })
            }
            StmtKind::Delete(mut delete) => {
                delete.fact = self.walk_fact_literal(&delete.fact, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Delete(delete),
                })
            }
            StmtKind::Emit(mut emit) => {
                emit.expr = self.walk_expr(emit.expr, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::Emit(emit),
                })
            }
            StmtKind::FunctionCall(mut func_call) => {
                func_call.args = func_call
                    .args
                    .into_iter()
                    .map(|arg| self.walk_expr(arg, old))
                    .collect();
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::FunctionCall(func_call),
                })
            }
            StmtKind::DebugAssert(mut debug_assert) => {
                debug_assert.expr = self.walk_expr(debug_assert.expr, old);
                self.hir.stmts.insert_with_key(|id| Stmt {
                    id,
                    span: stmt.span,
                    kind: StmtKind::DebugAssert(debug_assert),
                })
            }
        }
    }

    /// Transform a match statement into an if statement.
    fn create_if_from_match(
        &mut self,
        stmt: &Stmt,
        match_stmt: &MatchStmt,
        old: &mut Hir,
    ) -> StmtId {
        let scrutinee = self.walk_expr(match_stmt.expr, old);
        let mut branches = Vec::new();

        let (arms, default) = split_match_arms(&match_stmt.arms);

        for arm in arms {
            let MatchPattern::Values(values) = &arm.pattern else {
                unreachable!("non-default pattern expected");
            };

            for &value_expr_id in values {
                // Create new equality expression: scrutinee == value
                let value = self.walk_expr(value_expr_id, old);
                let condition = self.hir.exprs.insert_with_key(|id| Expr {
                    id,
                    span: stmt.span,
                    kind: ExprKind::Equal(scrutinee, value),
                });

                branches.push(IfBranch {
                    expr: condition,
                    block: self.walk_block(arm.block, old),
                });
            }
        }

        let else_block = default.map(|arm| self.walk_block(arm.block, old));

        self.hir.stmts.insert_with_key(|id| Stmt {
            id,
            span: stmt.span,
            kind: StmtKind::If(IfStmt {
                branches,
                else_block,
            }),
        })
    }

    /// Walk a fact literal.
    fn walk_fact_literal(&mut self, fact: &FactLiteral, old: &mut Hir) -> FactLiteral {
        FactLiteral {
            ident: fact.ident,
            keys: fact
                .keys
                .iter()
                .map(|(ident, field)| (*ident, self.walk_fact_field(field, old)))
                .collect(),
            vals: fact
                .vals
                .iter()
                .map(|(ident, field)| (*ident, self.walk_fact_field(field, old)))
                .collect(),
        }
    }

    /// Walk a fact field.
    fn walk_fact_field(&mut self, field: &FactField, old: &mut Hir) -> FactField {
        match field {
            FactField::Expr(expr) => FactField::Expr(self.walk_expr(*expr, old)),
            FactField::Bind => FactField::Bind,
        }
    }

    /// Walk an intrinsic.
    fn walk_intrinsic(&mut self, intrinsic: &Intrinsic, old: &mut Hir) -> Intrinsic {
        match intrinsic {
            Intrinsic::Query(fact) => Intrinsic::Query(self.walk_fact_literal(fact, old)),
            Intrinsic::FactCount(count_type, n, fact) => {
                Intrinsic::FactCount(count_type.clone(), *n, self.walk_fact_literal(fact, old))
            }
            Intrinsic::Serialize(expr) => Intrinsic::Serialize(self.walk_expr(*expr, old)),
            Intrinsic::Deserialize(expr) => Intrinsic::Deserialize(self.walk_expr(*expr, old)),
        }
    }

    /// Normalize a match expression into a block with nested ternaries.
    fn normalize_match_expr(&mut self, match_expr: &MatchExpr, old: &mut Hir) -> ExprKind {
        let scrutinee = self.walk_expr(match_expr.scrutinee, old);

        // Build a chain of ternary expressions from the match arms
        let result_expr = self.build_match_expr_chain(&match_expr.arms, scrutinee, old);

        // Create a block to hold the expression
        let block_id = self.hir.blocks.insert_with_key(|id| Block {
            id,
            span: Span::dummy(),
            stmts: Vec::new(),
        });

        ExprKind::Block(block_id, result_expr)
    }

    /// Build a chain of ternary expressions from match arms.
    fn build_match_expr_chain(
        &mut self,
        arms: &[MatchExprArm],
        scrutinee: ExprId,
        old: &mut Hir,
    ) -> ExprId {
        match arms {
            [] => panic!("Match expression must have at least one arm"),
            [arm] => {
                // Last arm - if it's default, just return the expression
                match &arm.pattern {
                    MatchPattern::Default => self.walk_expr(arm.expr, old),
                    MatchPattern::Values(values) => {
                        // Build OR chain for multiple values
                        self.build_or_chain_expr(&values, scrutinee, arm.expr, old)
                    }
                }
            }
            [arm, rest @ ..] => {
                match &arm.pattern {
                    MatchPattern::Default => {
                        // Default should be last
                        panic!("Default pattern must be the last arm in match expression")
                    }
                    MatchPattern::Values(values) => {
                        // Build: if (scrutinee == v1 || scrutinee == v2 || ...) { arm.expr } else { rest }
                        let condition = self.build_or_chain_condition(&values, scrutinee, old);
                        let true_expr = self.walk_expr(arm.expr, old);
                        let false_expr = self.build_match_expr_chain(rest, scrutinee, old);

                        self.hir.exprs.insert_with_key(|id| Expr {
                            id,
                            span: Span::dummy(),
                            kind: ExprKind::Ternary(Ternary {
                                cond: condition,
                                true_expr,
                                false_expr,
                            }),
                        })
                    }
                }
            }
        }
    }

    /// Build an OR chain of equality checks for match pattern values.
    fn build_or_chain_condition(
        &mut self,
        values: &[ExprId],
        scrutinee: ExprId,
        old: &mut Hir,
    ) -> ExprId {
        match values {
            [] => panic!("Match pattern must have at least one value"),
            [value] => {
                let value_expr = self.walk_expr(*value, old);
                self.hir.exprs.insert_with_key(|id| Expr {
                    id,
                    span: Span::dummy(),
                    kind: ExprKind::Equal(scrutinee, value_expr),
                })
            }
            [value, rest @ ..] => {
                let value_expr = self.walk_expr(*value, old);
                let eq_expr = self.hir.exprs.insert_with_key(|id| Expr {
                    id,
                    span: Span::dummy(),
                    kind: ExprKind::Equal(scrutinee, value_expr),
                });
                let rest_expr = self.build_or_chain_condition(rest, scrutinee, old);

                self.hir.exprs.insert_with_key(|id| Expr {
                    id,
                    span: Span::dummy(),
                    kind: ExprKind::Or(eq_expr, rest_expr),
                })
            }
        }
    }

    /// Build an expression that returns the result if any of the values match.
    fn build_or_chain_expr(
        &mut self,
        values: &[ExprId],
        scrutinee: ExprId,
        result: ExprId,
        old: &mut Hir,
    ) -> ExprId {
        let condition = self.build_or_chain_condition(values, scrutinee, old);
        let true_expr = self.walk_expr(result, old);

        // Since this is the last arm, we need a default value for false case
        // This should never happen if the match is exhaustive
        let false_expr = self.hir.exprs.insert_with_key(|id| Expr {
            id,
            span: Span::dummy(),
            kind: ExprKind::Bool(false), // Or panic - this shouldn't be reached
        });

        self.hir.exprs.insert_with_key(|id| Expr {
            id,
            span: Span::dummy(),
            kind: ExprKind::Ternary(Ternary {
                cond: condition,
                true_expr,
                false_expr,
            }),
        })
    }

    /// Walk an expression.
    fn walk_expr(&mut self, expr_id: ExprId, old: &mut Hir) -> ExprId {
        let expr = old.exprs.remove(expr_id).expect("expr should exist");

        let new_kind = match expr.kind {
            ExprKind::Int(n) => ExprKind::Int(n),
            ExprKind::String(s) => ExprKind::String(s),
            ExprKind::Bool(b) => ExprKind::Bool(b),
            ExprKind::Optional(opt) => ExprKind::Optional(opt.map(|e| self.walk_expr(e, old))),
            ExprKind::Identifier(ident) => ExprKind::Identifier(ident),
            ExprKind::Add(lhs, rhs) => {
                ExprKind::Add(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::Sub(lhs, rhs) => {
                ExprKind::Sub(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::And(lhs, rhs) => {
                ExprKind::And(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::Or(lhs, rhs) => {
                ExprKind::Or(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::Equal(lhs, rhs) => {
                ExprKind::Equal(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::NotEqual(lhs, rhs) => {
                ExprKind::NotEqual(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::Block(block_id, result) => {
                ExprKind::Block(self.walk_block(block_id, old), self.walk_expr(result, old))
            }
            ExprKind::Ternary(ternary) => ExprKind::Ternary(Ternary {
                cond: self.walk_expr(ternary.cond, old),
                true_expr: self.walk_expr(ternary.true_expr, old),
                false_expr: self.walk_expr(ternary.false_expr, old),
            }),
            ExprKind::GreaterThan(lhs, rhs) => {
                ExprKind::GreaterThan(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::LessThan(lhs, rhs) => {
                ExprKind::LessThan(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::GreaterThanOrEqual(lhs, rhs) => {
                ExprKind::GreaterThanOrEqual(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::LessThanOrEqual(lhs, rhs) => {
                ExprKind::LessThanOrEqual(self.walk_expr(lhs, old), self.walk_expr(rhs, old))
            }
            ExprKind::Dot(expr, ident) => ExprKind::Dot(self.walk_expr(expr, old), ident),
            ExprKind::Negative(expr) => ExprKind::Negative(self.walk_expr(expr, old)),
            ExprKind::Not(expr) => ExprKind::Not(self.walk_expr(expr, old)),
            ExprKind::Unwrap(expr) => ExprKind::Unwrap(self.walk_expr(expr, old)),
            ExprKind::CheckUnwrap(expr) => ExprKind::CheckUnwrap(self.walk_expr(expr, old)),
            ExprKind::Is(expr, is_some) => ExprKind::Is(self.walk_expr(expr, old), is_some),
            ExprKind::Substruct(expr, ident) => {
                ExprKind::Substruct(self.walk_expr(expr, old), ident)
            }
            ExprKind::NamedStruct(mut named) => {
                named.fields = named
                    .fields
                    .into_iter()
                    .map(|(ident, expr)| (ident, self.walk_expr(expr, old)))
                    .collect();
                ExprKind::NamedStruct(named)
            }
            ExprKind::EnumReference(enum_ref) => ExprKind::EnumReference(enum_ref),
            ExprKind::FunctionCall(mut call) => {
                call.args = call
                    .args
                    .into_iter()
                    .map(|arg| self.walk_expr(arg, old))
                    .collect();
                ExprKind::FunctionCall(call)
            }
            ExprKind::ForeignFunctionCall(mut call) => {
                call.args = call
                    .args
                    .into_iter()
                    .map(|arg| self.walk_expr(arg, old))
                    .collect();
                ExprKind::ForeignFunctionCall(call)
            }
            ExprKind::Intrinsic(intrinsic) => {
                ExprKind::Intrinsic(self.walk_intrinsic(&intrinsic, old))
            }
            ExprKind::Match(match_expr) => self.normalize_match_expr(&match_expr, old),
        };

        self.hir.exprs.insert_with_key(|id| Expr {
            id,
            span: expr.span,
            kind: new_kind,
        })
    }
}

/// Split match arms into regular patterns and the default case.
fn split_match_arms(arms: &[MatchArm]) -> (&[MatchArm], Option<&MatchArm>) {
    match arms {
        [
            arms @ ..,
            default @ MatchArm {
                pattern: MatchPattern::Default,
                ..
            },
        ] => (arms, Some(default)),
        arms => (arms, None),
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NormalizedHir {
    /// Action definitions.
    pub actions: SlotMap<ActionId, ActionDef>,
    /// Arguments for action definitions
    pub action_args: SlotMap<ActionArgId, ActionArg>,
    /// Command definitions.
    pub cmds: SlotMap<CmdId, CmdDef>,
    /// Fields within command definitions
    pub cmd_fields: SlotMap<CmdFieldId, CmdField>,
    /// Effect definitions
    pub effects: SlotMap<EffectId, EffectDef>,
    /// Fields within effect definitions
    pub effect_fields: SlotMap<EffectFieldId, EffectField>,
    /// Enumeration type definitions
    pub enums: SlotMap<EnumId, EnumDef>,
    /// Fact definitions
    pub facts: SlotMap<FactId, FactDef>,
    /// Key fields for fact definitions
    pub fact_keys: SlotMap<FactKeyId, FactKey>,
    /// Value fields for fact definitions
    pub fact_vals: SlotMap<FactValId, FactVal>,
    /// Finish function definitions
    pub finish_funcs: SlotMap<FinishFuncId, FinishFuncDef>,
    /// Arguments for finish function definitions
    pub finish_func_args: SlotMap<FinishFuncArgId, FinishFuncArg>,
    /// Regular function definitions
    pub funcs: SlotMap<FuncId, FuncDef>,
    /// Arguments for function definitions
    pub func_args: SlotMap<FuncArgId, FuncArg>,
    /// Global constant definitions
    pub global_lets: SlotMap<GlobalId, GlobalLetDef>,
    /// Structure type definitions
    pub structs: SlotMap<StructId, StructDef>,
    /// Fields within structure definitions
    pub struct_fields: SlotMap<StructFieldId, StructField>,
    /// All statements
    pub stmts: SlotMap<StmtId, Stmt>,
    /// All expressions
    pub exprs: SlotMap<ExprId, Expr>,
    /// All identifiers
    pub idents: SlotMap<IdentId, Ident>,
    /// Statement blocks (collections of statements)
    pub blocks: SlotMap<BlockId, Block>,
    /// Type definitions and references
    pub types: SlotMap<VTypeId, VType>,
    /// FFI import statements from the policy
    pub ffi_imports: SlotMap<FfiImportId, FfiImportDef>,
    /// FFI module definitions
    pub ffi_modules: SlotMap<FfiModuleId, FfiModuleDef>,
    /// FFI function definitions
    pub ffi_funcs: SlotMap<FfiFuncId, FfiFuncDef>,
    /// FFI struct definitions
    pub ffi_structs: SlotMap<FfiStructId, FfiStructDef>,
    /// FFI enum definitions
    pub ffi_enums: SlotMap<FfiEnumId, FfiEnumDef>,
}

#[cfg(test)]
mod tests {
    use aranya_policy_ast::Version;
    use aranya_policy_lang::lang::parse_policy_str;

    use super::*;
    use crate::hir;

    fn parse_and_normalize(policy_text: &str) -> NormalizedHir {
        let policy = parse_policy_str(policy_text, Version::V1).unwrap();
        let (hir, _) = hir::parse(&policy, &[]);
        hir.normalize()
    }

    #[test]
    fn test_match_stmt_to_if_normalization() {
        let policy = r#"
            enum Color { Red, Green, Blue }

            action test_match(c Color) {
                match c {
                    Color::Red => { publish Effect1 { color: "red" } },
                    Color::Green => { publish Effect1 { color: "green" } },
                    Color::Blue => { publish Effect1 { color: "blue" } },
                }
            }

            effect Effect1 { color string }
        "#;

        let normalized = parse_and_normalize(policy);

        // Check that there are no match statements in the normalized HIR
        for (_, stmt) in &normalized.stmts {
            assert!(
                !matches!(stmt.kind, StmtKind::Match(_)),
                "Found match statement after normalization"
            );
        }

        // Check that we have if statements instead
        let has_if_stmt = normalized
            .stmts
            .iter()
            .any(|(_, stmt)| matches!(stmt.kind, StmtKind::If(_)));
        assert!(
            has_if_stmt,
            "Expected if statement after match normalization"
        );
    }

    #[test]
    fn test_match_expr_normalization() {
        let policy = r#"
            enum Status { Ok, Error }

            function get_message(s Status) string {
                let msg = match s {
                    Status::Ok => { "success" },
                    Status::Error => { "failure" },
                };
                return msg
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Check that match expressions are converted to block with ternary
        let has_ternary = normalized
            .exprs
            .iter()
            .any(|(_, expr)| matches!(expr.kind, ExprKind::Ternary(_)));
        assert!(
            has_ternary,
            "Expected ternary expression after match expression normalization"
        );
    }

    #[test]
    fn test_match_with_default() {
        let policy = r#"
            enum Animal { Dog, Cat, Bird }

            action handle_animal(a Animal) {
                match a {
                    Animal::Dog => { publish Effect1 { sound: "woof" } },
                    Animal::Cat => { publish Effect1 { sound: "meow" } },
                    _ => { publish Effect1 { sound: "unknown" } },
                }
            }

            effect Effect1 { sound string }
        "#;

        let normalized = parse_and_normalize(policy);

        // Check that the if statement has an else block (from the default case)
        let if_with_else = normalized.stmts.iter().find_map(|(_, stmt)| {
            if let StmtKind::If(if_stmt) = &stmt.kind {
                Some(if_stmt.else_block.is_some())
            } else {
                None
            }
        });

        assert_eq!(
            if_with_else,
            Some(true),
            "Expected if statement with else block for default case"
        );
    }

    #[test]
    fn test_preserves_non_match_statements() {
        let policy = r#"
            action test_let() {
                let x = 42;
                check x > 0;
                if x == 42 {
                    publish Effect1 { value: x }
                }
            }

            effect Effect1 { value int }
        "#;

        let normalized = parse_and_normalize(policy);

        // Check that let, check, and if statements are preserved
        let has_let = normalized
            .stmts
            .iter()
            .any(|(_, stmt)| matches!(stmt.kind, StmtKind::Let(_)));
        let has_check = normalized
            .stmts
            .iter()
            .any(|(_, stmt)| matches!(stmt.kind, StmtKind::Check(_)));
        let has_if = normalized
            .stmts
            .iter()
            .any(|(_, stmt)| matches!(stmt.kind, StmtKind::If(_)));

        assert!(has_let, "Let statement should be preserved");
        assert!(has_check, "Check statement should be preserved");
        assert!(has_if, "If statement should be preserved");
    }

    #[test]
    fn test_simple_early_return_normalization() {
        let policy = r#"
            function foo(x int) int {
                if x < 0 { return 42 }
                return x * 2
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "foo")
            .expect("Function foo should exist");

        let block = &normalized.blocks[func.1.block];

        // Should have a single return statement
        assert_eq!(
            block.stmts.len(),
            1,
            "Function should have exactly one statement"
        );

        let stmt = &normalized.stmts[block.stmts[0]];
        assert!(
            matches!(stmt.kind, StmtKind::Return(_)),
            "Statement should be a return"
        );

        // The return should contain a ternary expression
        if let StmtKind::Return(ret) = &stmt.kind {
            let expr = &normalized.exprs[ret.expr];
            assert!(
                matches!(expr.kind, ExprKind::Ternary(_)),
                "Return should contain a ternary expression"
            );
        }
    }

    #[test]
    fn test_multiple_early_returns_normalization() {
        let policy = r#"
            function bar(x int) int {
                if x < 0 { return 42 }
                let y = x + x;
                if y < 3 { return 3 }
                return 1
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "bar")
            .expect("Function bar should exist");

        let block = &normalized.blocks[func.1.block];

        // Should have a single return statement
        assert_eq!(
            block.stmts.len(),
            1,
            "Function should have exactly one statement"
        );

        let stmt = &normalized.stmts[block.stmts[0]];
        assert!(
            matches!(stmt.kind, StmtKind::Return(_)),
            "Statement should be a return"
        );

        // The return should contain nested ternary expressions
        if let StmtKind::Return(ret) = &stmt.kind {
            let expr = &normalized.exprs[ret.expr];
            assert!(
                matches!(expr.kind, ExprKind::Ternary(_)),
                "Return should contain a ternary expression"
            );

            // Check for nested structure
            if let ExprKind::Ternary(ternary) = &expr.kind {
                let false_expr = &normalized.exprs[ternary.false_expr];
                // The false branch should contain a block expression
                assert!(
                    matches!(false_expr.kind, ExprKind::Block(_, _)),
                    "False branch should be a block expression"
                );
            }
        }
    }

    #[test]
    fn test_return_with_let_inlining() {
        let policy = r#"
            function baz(x int) int {
                if x < 0 {
                    let y = x + 1;
                    return y * y
                }
                return 0
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "baz")
            .expect("Function baz should exist");

        let block = &normalized.blocks[func.1.block];

        // Should have a single return statement
        assert_eq!(
            block.stmts.len(),
            1,
            "Function should have exactly one statement"
        );

        let stmt = &normalized.stmts[block.stmts[0]];
        assert!(
            matches!(stmt.kind, StmtKind::Return(_)),
            "Statement should be a return"
        );

        // The return should contain a ternary expression
        if let StmtKind::Return(ret) = &stmt.kind {
            let expr = &normalized.exprs[ret.expr];
            assert!(
                matches!(expr.kind, ExprKind::Ternary(_)),
                "Return should contain a ternary expression"
            );

            // The let binding should be inlined
            let has_let_stmt = normalized.stmts.iter().any(|(_, s)| {
                if let StmtKind::Let(let_stmt) = &s.kind {
                    normalized.idents[let_stmt.ident].ident.as_str() == "y"
                } else {
                    false
                }
            });
            assert!(
                !has_let_stmt,
                "Let binding 'y' should be inlined, not present as a statement"
            );
        }
    }

    #[test]
    fn test_return_normalization_with_check() {
        let policy = r#"
            function qux(x int) int {
                if x < 0 {
                    check x != -1;
                    return 42
                }
                return 0
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "qux")
            .expect("Function qux should exist");

        let block = &normalized.blocks[func.1.block];

        // With check statement, Tier 2 should be used
        // The function should end with an if statement where all branches return
        let last_stmt = &normalized.stmts[*block.stmts.last().unwrap()];

        if let StmtKind::If(if_stmt) = &last_stmt.kind {
            // Check that all branches end with return
            for branch in &if_stmt.branches {
                let branch_block = &normalized.blocks[branch.block];
                let last_branch_stmt = &normalized.stmts[*branch_block.stmts.last().unwrap()];
                assert!(
                    matches!(last_branch_stmt.kind, StmtKind::Return(_)),
                    "Branch should end with return"
                );
            }

            if let Some(else_block_id) = if_stmt.else_block {
                let else_block = &normalized.blocks[else_block_id];
                let last_else_stmt = &normalized.stmts[*else_block.stmts.last().unwrap()];
                assert!(
                    matches!(last_else_stmt.kind, StmtKind::Return(_)),
                    "Else block should end with return"
                );
            }
        } else {
            // If not an if statement, it should be a single return (depends on the specific transformation)
            assert!(
                matches!(last_stmt.kind, StmtKind::Return(_)),
                "Should end with return"
            );
        }
    }

    #[test]
    fn test_unreachable_code_preservation() {
        let policy = r#"
            function unreachable_test(x int) int {
                return 42;
                let y = x + 1;
                check y > 0;
                return y
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "unreachable_test")
            .expect("Function unreachable_test should exist");

        let block = &normalized.blocks[func.1.block];

        // Should have 2 statements: return and if false { ... }
        assert_eq!(
            block.stmts.len(),
            2,
            "Function should have return and if false for unreachable code"
        );

        // First should be return
        let first_stmt = &normalized.stmts[block.stmts[0]];
        assert!(
            matches!(first_stmt.kind, StmtKind::Return(_)),
            "First statement should be return"
        );

        // Second should be if false { ... }
        let second_stmt = &normalized.stmts[block.stmts[1]];
        if let StmtKind::If(if_stmt) = &second_stmt.kind {
            assert_eq!(if_stmt.branches.len(), 1, "Should have one branch");
            let cond_expr = &normalized.exprs[if_stmt.branches[0].expr];
            assert!(
                matches!(cond_expr.kind, ExprKind::Bool(false)),
                "Condition should be false"
            );

            // The unreachable code should be preserved in the if false block
            let unreachable_block = &normalized.blocks[if_stmt.branches[0].block];
            assert!(
                unreachable_block.stmts.len() >= 3,
                "Unreachable block should contain the preserved statements"
            );
        } else {
            panic!("Second statement should be if false");
        }
    }

    #[test]
    fn test_empty_function_normalization() {
        let policy = r#"
            function empty() int {
                return 0
            }
        "#;

        let normalized = parse_and_normalize(policy);

        // Find the function
        let func = normalized
            .funcs
            .iter()
            .find(|(_, f)| normalized.idents[f.ident].ident.as_str() == "empty")
            .expect("Function empty should exist");

        let block = &normalized.blocks[func.1.block];

        // Should still have a single return statement
        assert_eq!(
            block.stmts.len(),
            1,
            "Function should have exactly one statement"
        );

        let stmt = &normalized.stmts[block.stmts[0]];
        assert!(
            matches!(stmt.kind, StmtKind::Return(_)),
            "Statement should be a return"
        );
    }
}
