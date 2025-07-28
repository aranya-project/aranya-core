//! A High-level Intermediate Representation (HIR) for Aranya
//! policies.

#![allow(dead_code)]
#![allow(clippy::module_inception)]

mod arena;
mod dsl;
mod hir;
mod lower;
mod snapshot_tests;
mod visit;

use aranya_policy_ast::Policy;
use aranya_policy_module::ffi::ModuleSchema;

use crate::hir::lower::LowerCtx;
pub(crate) use crate::hir::{arena::AstNodes, hir::*, visit::Visitor};

/// Parses a [`Policy`] into [`Hir`] and [`AstNodes`].
pub(crate) fn parse<'a>(
    policy: &'a Policy,
    ffi_modules: &'a [ModuleSchema<'a>],
) -> (Hir, AstNodes<'a>) {
    let LowerCtx { ast, arena } = LowerCtx::build(policy, ffi_modules);
    (ast, arena)
}
