//! High-level intermediate representation (HIR) for the [AST].
//!
//! HIR makes compiler analysis passes easier and more efficient
//! than they would be if they used the AST directly. HIR is
//! *semantically lossless*, which means that it preserves all of
//! the language semantics present in the original AST.
//!
//! AST is converted into HIR through a process called
//! *lowering*.
//!
//! # Simplifications
//!
//! HIR is allowed to transform the AST if and only if the
//! resulting transformation has the *exact* same language
//! semantics as the original AST.
//!
//! For example, [`exists`] is semantic sugar for [`at_least
//! 1`][at_least], so it would is **valid** for HIR to rewrite
//! [`exists`] as [`at least 1`].
//!
//! However, it would be **invalid** for HIR to transform
//! [`match`] statements into [`if/else if/else`] statements
//! because `match` statements must be *exhaustive*.
//!
//! # Structure
//!
//! HIR nodes are stored in flat collections and can be
//! referenced with stable IDs (e.g., [`ActionId`], [`ExprId`]).
//!
//! [`exists`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#exists
//! [`at_least`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#at_least-n-at_most-n-exactly-n
//! [`if/else if/else`]: https://github.com/aranya-project/aranya-docs/blob/ccf916c97a4112823cb3c29bae0ad61796e97e51/docs/policy-v1.md#if-else-if-else
//! [AST]: https://docs.rs/aranya-policy-ast/latest/aranya_policy_ast/struct.Policy.html

#![allow(dead_code)]
#![allow(clippy::module_inception)]

mod hir;
mod lower;
//mod normalize;
//mod snapshot_tests;
pub(crate) mod visit;

pub(crate) use crate::hir::hir::*;
use crate::{
    ast::{self, Ast},
    ctx::Ctx,
    hir::lower::LowerCtx,
};

pub(crate) mod types {
    pub use crate::hir::*;
}

impl Ctx<'_> {
    pub fn lower_hir(&mut self, ast: Ast<'_>) {
        let mut ctx = LowerCtx {
            hir: Hir::default(),
            idents: &mut self.idents,
            text: &mut self.text,
        };
        let index = ast::index(ast);
        for (_, item) in index {
            ctx.lower_item(&item);
        }
        self.hir = ctx.hir;
    }
}
