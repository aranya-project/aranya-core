//! Compilation session and context.

use std::ops::Deref;

use aranya_policy_ast::{Identifier, Text};

use crate::{
    ast::Ast,
    depgraph::BuildDepGraph,
    diag::{DiagCtx, ErrorGuaranteed, OptionExt},
    eval::{ConstInterner, Value, ValueRef},
    hir::{IdentInterner, IdentRef, LowerAst, TextInterner, TextRef},
    pass::{Access, DepList, Pass, Results, View},
    simplify::SimplifyPass,
    symtab::SymbolResolution,
    typecheck::types::{
        Builtins, ItemInterner, ItemKind, ItemRef, TypeInterner, TypeKind, TypeRef,
    },
};

macro_rules! impl_interner {
    ($field:ident, $intern:ident, $get:ident, $ty:ty, $ref:ty) => {
        /// Interns
        #[doc = concat!("[`", stringify!($ty), "`].")]
        pub fn $intern(&self, value: $ty) -> $ref {
            self.inner.$field.intern(value)
        }

        /// Retrieves an interned
        #[doc = concat!("[`", stringify!($ty), "`]")]
        /// by its reference.
        ///
        /// It is an ICE if `xref` is not found.
        pub fn $get(&self, xref: $ref) -> &'cx $ty {
            self.inner
                .$field
                .get(xref)
                .unwrap_or_bug(self.dcx(), concat!(stringify!($ty), " not found"))
        }
    };
}

macro_rules! add_view {
    ($name:ident => $pass:ty) => {
        /// Returns the view for the
        #[doc = concat!("[`", stringify!($pass), "`]")]
        /// compiler pass.
        pub fn $name(self) -> Result<<$pass as Pass>::View<'cx>, ErrorGuaranteed> {
            let data = self.get::<$pass>()?;
            Ok(<<$pass as Pass>::View<'cx> as View<_>>::new(self, data))
        }
    };
}

/// Compiler context. TODO: more docs
#[derive(Copy, Clone, Debug)]
pub struct Ctx<'cx> {
    #[doc(hidden)]
    pub(crate) inner: &'cx InnerCtx<'cx>,
}

impl<'cx> Ctx<'cx> {
    /// Get the diagnostic context.
    pub fn dcx(&self) -> &'cx DiagCtx {
        self.inner.sess.dcx()
    }

    /// TODO
    pub fn get<P: Pass>(&self) -> Result<&'cx P::Output, ErrorGuaranteed>
    where
        Results: Access<P>,
    {
        let cell = <Results as Access<P>>::cell(&self.inner.results);
        if let Some(result) = cell.get() {
            return Ok(result);
        }
        let deps = <P::Deps as DepList>::fetch(*self)?;
        let output = P::run(*self, deps)?;
        Ok(cell.get_or_init(|| output))
    }

    impl_interner!(idents, intern_ident, get_ident, Identifier, IdentRef);
    impl_interner!(text, intern_text, get_text, Text, TextRef);
    impl_interner!(types, intern_type, get_type, TypeKind, TypeRef);
    impl_interner!(items, intern_item, get_item, ItemKind, ItemRef);
    impl_interner!(consts, intern_const, get_const, Value, ValueRef);

    add_view!(hir => LowerAst);
    add_view!(symbols => SymbolResolution);
    add_view!(deps => BuildDepGraph);
    add_view!(simplified => SimplifyPass);
}

impl<'cx> Deref for Ctx<'cx> {
    type Target = InnerCtx<'cx>;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

/// Compilation session containing all compiler state.
#[derive(Debug)]
pub struct InnerCtx<'cx> {
    /// TODO
    pub sess: &'cx Session,
    /// TODO
    pub ast: Ast<'cx>,
    /// Identifier interner.
    pub idents: IdentInterner,
    /// Text interner.
    pub text: TextInterner,
    /// Type interner.
    pub types: TypeInterner,
    /// Items interner.
    pub items: ItemInterner,
    /// Constant interner.
    pub consts: ConstInterner,
    /// Builtin interned types.
    pub builtins: Builtins,
    /// Results from core passes.
    pub results: Results,
}

impl<'cx> InnerCtx<'cx> {
    /// Create a new compilation session.
    pub fn new(sess: &'cx Session, ast: Ast<'cx>) -> Self {
        let types = TypeInterner::new();
        let builtins = Builtins::new(&types);
        Self {
            sess,
            ast,
            idents: IdentInterner::new(),
            text: TextInterner::new(),
            types,
            items: ItemInterner::new(),
            consts: ConstInterner::new(),
            builtins,
            results: Results::new(),
        }
    }
}

/// Compilation session containing all compiler state.
#[derive(Debug)]
pub(crate) struct Session {
    pub dcx: DiagCtx,
}

impl Session {
    pub fn dcx(&self) -> &DiagCtx {
        &self.dcx
    }
}
