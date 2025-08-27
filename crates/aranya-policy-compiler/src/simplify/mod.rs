//! Simplification pass: convert HIR into a simplified, lossy IR that is
//! trivial to lower into MIR (SSA form).
//!
//! Overview
//! --------
//! This module defines the "simplify" compiler pass. It takes fully-formed,
//! symbol-resolved, and type-checked HIR and produces a simplified HIR
//! ("sHIR") designed specifically to make MIR lowering straightforward and
//! mechanical. The simplified IR is intentionally lossy: it removes syntactic
//! sugar and normalizes control-flow/expressions into a smaller set of
//! constructs.
//!
//! Non-goal: optimization. This pass does not attempt to optimize or change
//! performance characteristics; it only reduces surface area and normalizes
//! structure to ease the next stage.
//!
//! Assumptions and Error Policy
//! ----------------------------
//! - Input HIR is well-formed, symbol-resolved, and has passed type checking.
//! - Any discrepancy encountered by this pass is an internal compiler error
//!   (ICE). This pass does not emit regular diagnostics; it signals ICEs via
//!   `diag::DiagCtx::emit_bug*` helpers.
//!
//! Dependencies
//! ------------
//! The pass depends on:
//! - `LowerAst` (to obtain HIR)
//! - `TypesPass` (for precise `typecheck::TypeRef` information)
//! - `ConstEval` (for constant folding of expressions)
//!
//! Output
//! ------
//! The output is a simplified IR (defined in `types.rs`) that broadly mirrors
//! HIR's shape where useful but:
//! - Eliminates syntax sugar (`match` → `if/else`, ternary → `if/else`).
//! - Converts all statements into expressions, using `Type::Unit` and
//!   `Type::Never` to represent effectful and early-exit constructs.
//! - Simplifies blocks (flattens nested blocks, removes empty blocks).
//! - Carries precise types on expressions using `typecheck::TypeRef`.
//! - Tracks expression purity so MIR can cheaply determine side-effecting
//!   boundaries.
//!
//! Node/Type Design (high level)
//! -----------------------------
//! - The simplified IR uses arenas and typed IDs, similar to HIR, defined in
//!   `types.rs`. Names are not prefixed (we rely on the `simplify` module for
//!   disambiguation, e.g., `simplify::Expr` vs `hir::Expr`).
//! - Expressions include a `ty: typecheck::TypeRef` and `pure: hir::Pure`.
//!   Purity is propagated bottom-up and combines via logical-AND semantics. The
//!   following are considered impure: actions, finish functions, foreign
//!   functions; plain functions are pure.
//! - Statements are eliminated by representing them as expressions:
//!   - `let x = e;` becomes a unit-typed expression that introduces a binding
//!     in the surrounding block/sequence so subsequent expressions may refer to
//!     `x`.
//!   - `check e;`, `debug_assert e;` become unit-typed expressions.
//!   - Side-effecting statements (`action`, `publish`, `create`, `update`,
//!     `delete`, `emit`) become unit-typed expressions.
//!   - `return e;` becomes an expression of type `Never` to model early exit.
//! - Control flow is normalized to `if/else` expressions; `match` and ternary
//!   are rewritten accordingly.
//! - Spans are not required. Since this pass only emits ICEs, spans are
//!   optional. We may keep some spans in select nodes in the future to aid
//!   debugging, but they are not necessary for correctness.
//!
//! Transformations Performed
//! -------------------------
//! 1) Block Simplification
//!    - Remove empty blocks: a block with neither statements nor an expression
//!      is eliminated.
//!    - Flatten nested blocks: `{ { { e } } }` becomes `{ e }`.
//!    - Resulting blocks are sequences of expressions; the final expression is
//!      the block's value. If a block is used in a context where a value is not
//!      required, the final expression may be unit-typed.
//!
//! 2) Statements to Expressions
//!    - `let` is converted into a unit-typed expression that defines a binding
//!      for the remainder of the containing block.
//!    - `check` and `debug_assert` become unit-typed expressions.
//!    - Effectful statements (`action`, `publish`, `create`, `update`, `delete`,
//!      `emit`) become unit-typed expressions.
//!    - `return e` becomes a `Return(e)` expression of type `Never`.
//!
//! 3) `match` and Ternary Rewriting
//!    - `match` is lowered to a chain of `if/else` expressions comparing the
//!      scrutinee with arm patterns; an `_` (default) arm becomes the final
//!      `else`. Exhaustiveness has already been checked in prior passes.
//!    - Ternary `if` is also lowered into an `if/else` expression.
//!
//! 4) Constant Folding
//!    - Peephole folds for arithmetic and boolean operators, unary negation and
//!      logical not, `is Some`/`is None`, simple option constructions, and
//!      enum-variant equality checks when resolvable.
//!    - Integrates with `ConstEval` to fold global constants and otherwise
//!      constant subexpressions.
//!    - Folding does not cross impure boundaries. Plain functions are pure and
//!      may be folded when all arguments and the function body are constant per
//!      `ConstEval`. Finish functions, actions, and foreign functions are not
//!      considered pure and are not folded across.
//!
//! 5) Purity Propagation
//!    - Each expression has a `pure` flag. Binary/aggregate expressions combine
//!      child purity via logical-AND semantics. Intrinsically impure constructs
//!      (actions, finish functions, foreign functions, and side-effectful
//!      statements now as expressions) are marked impure. Plain function calls
//!      are pure.
//!
//! Invariants after Simplification
//! -------------------------------
//! - No empty blocks remain.
//! - No `match` nodes remain; all are expressed as nested `if/else`.
//! - All statements are represented as expressions.
//! - Every expression carries an accurate `typecheck::TypeRef` and `pure` flag.
//! - Early returns are represented by an expression of type `Never`.
//! - Any violation of these invariants is an ICE.
//!
//! Non-Goals
//! ---------
//! - No control-flow or data-flow optimizations (dead code elimination,
//!   constant propagation beyond local/`ConstEval`-supported cases, CSE, etc.).
//! - No reordering/fusing of effectful operations.
//!
//! Implementation Structure
//! ------------------------
//! - `types.rs`: defines the simplified IR nodes and typed IDs (arenas), with
//!   `Expr` carrying `ty: typecheck::TypeRef` and `pure: hir::Pure`.
//! - `lower.rs`: implements the transformation from `hir` to `simplify`,
//!   applying block simplifications, statement-to-expression conversion, match
//!   and ternary rewriting, constant folding, and purity propagation.
//! - `SimplifyPass`: the pass entrypoint tying together `LowerAst`,
//!   `TypesPass`, and `ConstEval` to produce the simplified IR.
//!
//! Notes on Determinism
//! --------------------
//! This pass is intended to be fully deterministic for a given HIR and type
//! environment. Repeated runs should produce identical simplified IR.
//!
//! Future Work
//! -----------
//! - Optional: retain select spans on nodes to improve ICE diagnostics.
//! - Extend constant folding to additional intrinsics or compile-time-known
//!   values as needed by later stages.
//!
//! Const folding policy
//! --------------------
//! This pass relies on the ConstEval pass to determine constant expressions
//! over the original HIR and materializes simplified literals accordingly.
//! No additional peephole folding is performed here to avoid duplication and
//! ensure a single source of truth for constant evaluation.

mod lower;
mod types;

pub use types::*;

use crate::{
    ctx::Ctx,
    diag::ErrorGuaranteed,
    eval::ConstEval,
    hir::LowerAst,
    pass::{DepList, Pass, View},
    symtab::SymbolResolution,
    typecheck::TypesPass,
};

/// Pass entrypoint for simplification.
pub struct SimplifyPass;

impl Pass for SimplifyPass {
    const NAME: &'static str = "simplify";

    type Deps = (LowerAst, SymbolResolution, TypesPass, ConstEval);

    type Output = Hir;

    type View<'cx> = Simplified<'cx>;

    fn run<'cx>(
        cx: Ctx<'cx>,
        deps: <Self::Deps as DepList>::Refs<'cx>,
    ) -> Result<Self::Output, ErrorGuaranteed> {
        lower::run(cx, deps)
    }
}

/// A simple view wrapper over the simplified IR output.
pub struct Simplified<'cx> {
    _cx: Ctx<'cx>,
    pub hir: &'cx Hir,
}

impl<'cx> View<'cx, Hir> for Simplified<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Hir) -> Self {
        Self { _cx: cx, hir: data }
    }
}

impl<'cx> Simplified<'cx> {
    /// Counts passthrough HIR nodes that remain in the simplified IR.
    /// Useful as a guard to track incomplete lowering coverage.
    pub fn count_passthrough_hir(&self) -> usize {
        self.hir
            .exprs
            .iter()
            .filter(|(_, e)| matches!(e.kind, ExprKind::Hir(_)))
            .count()
    }

    /// Debug helper: emit an ICE if any passthrough `ExprKind::Hir` nodes remain.
    /// This is intended for assertions in tests or debugging; it is not invoked by default.
    pub fn ensure_no_passthrough_hir(&self) {
        let count = self.count_passthrough_hir();
        if count > 0 {
            self._cx.dcx().emit_bug(format!(
                "simplify: {} ExprKind::Hir nodes remained after lowering (incomplete coverage)",
                count
            ));
        }
    }
}
