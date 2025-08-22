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

#![allow(clippy::module_inception)]

mod hir;
mod lower;
//mod normalize; TODO
//mod snapshot_tests; TODO
pub(crate) mod visit;

use std::ops::Index;

use aranya_policy_ast::Identifier;

pub(crate) use self::hir::*;
use self::lower::LowerCtx;
use crate::{
    ast,
    ctx::Ctx,
    diag::ErrorGuaranteed,
    pass::{Pass, View},
};

pub(crate) mod types {
    pub(crate) use crate::hir::*;
}

/// Lowers the AST into HIR.
#[derive(Copy, Clone, Debug)]
pub struct AstLowering;

impl Pass for AstLowering {
    const NAME: &'static str = "hir_lower";
    type Deps = ();
    type Output = Hir;
    type View<'cx> = HirView<'cx>;

    fn run(cx: Ctx<'_>, _deps: ()) -> Result<Self::Output, ErrorGuaranteed> {
        let ast = &cx.inner.ast;
        let mut ctx = LowerCtx {
            ctx: cx,
            hir: Hir::default(),
            codemap: ast.codemap,
            last_span: Span::default(),
        };
        let index = ast::index(ast);
        for (_, item) in index {
            ctx.lower_item(&item);
        }
        Ok(ctx.hir)
    }
}

impl<'cx> Ctx<'cx> {
    /// Get the HIR lower pass.
    pub fn hir(self) -> Result<HirView<'cx>, ErrorGuaranteed> {
        let hir = self.get::<AstLowering>()?;
        Ok(HirView::new(self, hir))
    }
}

/// A view of the HIR.
#[derive(Copy, Clone, Debug)]
pub struct HirView<'cx> {
    cx: Ctx<'cx>,
    hir: &'cx Hir,
}

impl<'cx> HirView<'cx> {
    /// Retrieves the HIR.
    pub fn hir(&self) -> &'cx Hir {
        self.hir
    }

    /// Retrieves a HIR node.
    pub fn lookup<Id, T>(&self, id: Id) -> &'cx T
    where
        Hir: Index<Id, Output = T>,
    {
        self.hir().index(id)
    }

    /// Retrieves a span.
    pub fn lookup_span<Id, T>(&self, id: Id) -> Span
    where
        Hir: Index<Id, Output = T>,
        T: Spanned,
    {
        self.lookup(id).span()
    }

    /// Retrieves an interned identifier.
    pub fn lookup_ident(&self, id: IdentId) -> Identifier {
        let xref = self.lookup_ident_ref(id);
        self.cx.get_ident(xref)
    }

    /// Retrieves a reference to an interned identifier.
    pub fn lookup_ident_ref(&self, id: IdentId) -> IdentRef {
        self.lookup(id).xref
    }

    /// Retrieves a HIR node.
    pub fn lookup_node(&self, id: NodeId) -> Node<'cx> {
        self.hir().lookup(id)
    }
}

impl<'cx> View<'cx, Hir> for HirView<'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Hir) -> Self {
        Self { cx, hir: data }
    }
}
