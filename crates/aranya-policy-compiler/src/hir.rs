//! A High-level Intermediate Representation (HIR) for Aranya
//! policies.

#![allow(dead_code)]
#![allow(clippy::module_inception)]

mod arena;
mod hir;
mod lower;
mod tests;
mod visit;

use aranya_policy_ast::Policy;

use crate::hir::lower::LowerCtx;
pub(crate) use crate::hir::{arena::AstNodes, hir::Hir};

/// Parses a [`Policy`] into [`Hir`] and [`AstNodes`].
pub(crate) fn parse(policy: &Policy) -> (Hir, AstNodes<'_>) {
    let LowerCtx { ast, arena } = LowerCtx::build(policy);
    (ast, arena)
}
