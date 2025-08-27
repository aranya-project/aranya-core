//! Verification compiler pass for the Aranya policy language.
//!
//! This pass performs semantic verification of Aranya policy programs after
//! type checking and symbol resolution have completed. It ensures that
//! programs conform to the language's semantic rules and restrictions.
//!
//! # Overview
//!
//! The verification pass validates semantic correctness that cannot be
//! expressed through the type system alone. This includes context-sensitive
//! statement validation, control flow analysis, match exhaustiveness checking,
//! and enforcement of language restrictions like the prohibition on recursion.
//!
//! # Verification Rules
//!
//! ## Context-Sensitive Statement Validation
//!
//! Certain statements are only valid within specific execution contexts:
//!
//! - **Create statements**: Only allowed in `action` and `command` contexts
//! - **Update statements**: Only allowed in `action` and `command` contexts
//! - **Delete statements**: Only allowed in `action` and `command` contexts
//! - **Finish expressions**: Only allowed in `action` contexts
//! - **Serialize/Deserialize**: Only allowed in `action` contexts
//!
//! ## Function Call Context Validation
//!
//! Function calls must respect their declared context requirements:
//!
//! - Functions marked with `action` context can only be called from actions
//! - Functions marked with `effect` context can only be called from effects
//! - Functions without context restrictions can be called from anywhere
//!
//! ## Match Statement Exhaustiveness
//!
//! All match statements must be exhaustive. The requirements vary by type:
//!
//! ### Boolean Exhaustiveness
//! - Must cover both `true` and `false` cases
//! - Can use explicit arms or a default `_` pattern
//!
//! ### Enum Exhaustiveness
//! - Must cover all enum variants
//! - Can use explicit variant patterns or a default `_` pattern
//! - Each variant pattern must match the correct number of fields
//!
//! ### Integer Exhaustiveness
//! - Must cover the entire range of the integer type
//! - Uses range merging to verify coverage
//! - Ranges are merged and checked for gaps
//! - Default `_` pattern covers any remaining values
//!
//! ### String Exhaustiveness
//! - Cannot be exhaustive without a default pattern
//! - Must include a `_` pattern to be complete
//!
//! ### Restrictions
//! - Cannot match on `bytes` (no constant literals)
//! - Cannot match on `optional` types
//! - Match patterns must be constant literals, not expressions
//! - Duplicate pattern values are a compile error
//!
//! ## Control Flow Analysis
//!
//! ### Return Path Analysis
//! Functions with return types must ensure all paths return a value:
//! - The last statement must be either a `return` statement or an expression
//!   that evaluates to `Type::Never` (e.g., `panic!()`)
//! - All branches in conditional statements must return if any branch returns
//! - Early returns are allowed, but all paths must eventually return
//!
//! ### Unreachable Code Detection
//! Code after unconditional returns or panic expressions is unreachable:
//! - Statements after `return` in the same block
//! - Statements after expressions of type `Never`
//! - Code in impossible match arms (though exhaustiveness prevents this)
//!
//! ## Recursion Detection
//!
//! The language prohibits all forms of recursion:
//!
//! ### Direct Recursion
//! - Functions cannot call themselves
//! - Actions, commands, and effects cannot invoke themselves
//!
//! ### Indirect Recursion
//! - Cycles in the call graph are prohibited
//! - This includes mutual recursion between multiple functions
//! - Tracked using a call stack during verification
//!
//! ## Variable Initialization
//!
//! Variables must be initialized before use:
//! - Local variables must be assigned before being read
//! - All paths to a use must pass through an initialization
//! - Partial initialization in branches requires all branches to initialize
//!
//! ## Fact Operation Validation
//!
//! ### Query Validation
//! - Leading binds are not permitted in fact queries
//! - All binds must follow at least one concrete match
//! - Query patterns must be valid for the fact schema
//!
//! ### Schema Compliance
//! - Create operations must provide all required fields
//! - Update operations must only modify allowed fields
//! - Field types must match the fact schema
//!
//! ### Uniqueness Constraints
//! - Facts with unique fields must maintain uniqueness
//! - Updates cannot violate uniqueness constraints
//! - Checked at compile time when possible
//!
//! ## Command-Specific Rules
//!
//! ### Persistence Rules
//! - Commands marked `persistent` must return a struct type
//! - Commands marked `ephemeral` must return `()`
//! - The persistence marker must match the return type
//!
//! ### State Modification
//! - Only persistent commands can modify fact state
//! - Ephemeral commands cannot create, update, or delete facts
//!
//! ## Expression Purity
//!
//! Expressions are classified as pure or impure:
//!
//! ### Pure Expressions
//! - Literals, variables, field access
//! - Arithmetic and logical operations
//! - Struct and enum construction
//! - Pure function calls
//!
//! ### Impure Expressions
//! - Fact operations (create, update, delete, query)
//! - Finish expressions
//! - Serialize/deserialize operations
//! - Calls to impure functions
//!
//! ### Usage Restrictions
//! - Match conditions must be pure expressions
//! - Conditional test expressions must be pure
//! - Loop conditions must be pure (though loops are prohibited)
//!
//! ## Additional Restrictions
//!
//! ### No Mutation
//! - Variables are immutable once initialized
//! - No assignment operators beyond initial binding
//! - Struct fields cannot be modified after construction
//!
//! ### No Loops
//! - No `for`, `while`, or `loop` constructs
//! - Iteration must be expressed through higher-order functions
//! - Recursion is also prohibited (see above)
//!
//! ### Type Safety Extensions
//! While type checking handles most type safety, verification ensures:
//! - No integer overflow in constant expressions
//! - String literals are valid UTF-8 (enforced by Text type)
//! - Byte literals are valid sequences
//!
//! # Implementation
//!
//! The verification pass is implemented as a visitor pattern over the HIR
//! (High-level Intermediate Representation). The main components are:
//!
//! - `Verifier`: The main visitor that traverses the HIR
//! - `ExecutionContext`: Tracks the current statement context
//! - `IntRange`: Utilities for integer exhaustiveness checking
//! - Error types for each category of verification failure
//!
//! The pass runs after type checking and symbol resolution, allowing it to
//! assume type correctness and symbol availability.

mod errors;
mod visitor;


use crate::{
    ctx::Ctx,
    diag::ErrorGuaranteed,
    eval::{ConstEval, ConstEvalView},
    hir::{HirView, LowerAst},
    pass::{Pass, View},
    symtab::{SymbolResolution, SymbolsView},
    typecheck::{TypesPass, TypesView},
};

/// The verification compiler pass.
#[derive(Copy, Clone, Debug)]
pub struct VerifyPass;

impl Pass for VerifyPass {
    const NAME: &'static str = "verify";
    type Output = VerificationResult;
    type View<'cx> = VerificationView<'cx>;
    type Deps = (LowerAst, SymbolResolution, TypesPass, ConstEval);

    fn run<'cx>(
        cx: Ctx<'cx>,
        (hir, symbols, types, consts): (
            HirView<'cx>,
            SymbolsView<'cx>,
            TypesView<'cx>,
            ConstEvalView<'cx>,
        ),
    ) -> Result<VerificationResult, ErrorGuaranteed> {
        let mut verifier = visitor::Verifier::new(cx, hir, symbols, consts, types, 10);

        verifier.verify();

        if let Some(err) = verifier.dcx().has_errors() {
            return Err(err);
        }

        Ok(VerificationResult {
            verified: true,
            num_errors: verifier.error_count(),
        })
    }
}

/// The result of the verification pass.
#[derive(Clone, Debug)]
pub struct VerificationResult {
    /// Whether verification passed successfully.
    pub verified: bool,
    /// Number of errors encountered during verification.
    pub num_errors: usize,
}

/// A view of the verification result.
#[derive(Copy, Clone, Debug)]
pub struct VerificationView<'cx> {
    cx: Ctx<'cx>,
    result: &'cx VerificationResult,
}

impl<'cx> VerificationView<'cx> {
    /// Retrieves the verification result.
    pub fn result(&self) -> &'cx VerificationResult {
        self.result
    }
}

impl<'cx> View<'cx, VerificationResult> for VerificationView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx VerificationResult) -> Self {
        Self { cx, result: data }
    }
}
