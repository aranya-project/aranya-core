//! `hir` implements a high-level intermediate representation
//! (HIR) for Aranya policy code.
//!
//! HIR is a semantically lossless representation of the AST.
//!
//! # Transformations
//!
//! HIR is allowed to transform the AST if and only if the
//! resulting transformation has the *exact* same language
//! semantics as the original AST.
//!
//! For example, [`exists`] is semantic sugar for [`at_least
//! 1`][at_least], so it would be **valid** for HIR to perform
//! that transformation.
//!
//! However, it would be **invalid** for HIR to transform
//! [`match`] statements into [`if/else if/else`] statements
//! because `match` statements must be *exhaustive*.
//!
//! # Structure
//!
//! All HIR nodes are stored in flat collections and can be
//! referenced with stable IDs (e.g., [`ActionId`], [`ExprId`]).
//!
//! [`exists`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#exists
//! [`at_least`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#at_least-n-at_most-n-exactly-n
//! [`if/else if/else`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if-else-if-else

#![allow(dead_code)]
#![allow(clippy::module_inception)]

mod arena;
mod dsl;
mod hir;
mod lower;
//mod normalize;
mod snapshot_tests;
pub(crate) mod visit;

use aranya_policy_ast::Policy;
use aranya_policy_module::ffi::ModuleSchema;

use crate::hir::lower::LowerCtx;
pub(crate) use crate::hir::{arena::AstNodes, hir::*};

/// Parses a [`Policy`] into [`Hir`] and [`AstNodes`].
// TODO(eric): Rename this to `lower`.
pub(crate) fn parse<'a>(
    policy: &'a Policy,
    ffi_modules: &'a [ModuleSchema<'a>],
) -> (Hir, AstNodes<'a>) {
    let LowerCtx { hir, ast } = LowerCtx::build(policy, ffi_modules);
    (hir, ast)
}
