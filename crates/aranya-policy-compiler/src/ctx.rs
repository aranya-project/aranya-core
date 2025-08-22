//! Compilation session and context.

use std::ops::Deref;

use aranya_policy_ast::{Identifier, Text};

use crate::{
    ast::Ast,
    diag::{DiagCtx, ErrorGuaranteed, OptionExt},
    hir::{IdentInterner, IdentRef, TextInterner, TextRef},
    pass::{Access, DepList, Pass, Results},
    typecheck::types::{Builtins, Type, TypeInterner, TypeRef},
};

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

    /// Interns an identifier.
    pub fn intern_ident(&self, ident: Identifier) -> IdentRef {
        self.inner.idents.intern(ident)
    }

    /// Retrieves an identifier by its reference.
    ///
    /// It is an ICE if `xref` is not found.
    pub fn get_ident(&self, xref: IdentRef) -> Identifier {
        self.inner
            .idents
            .get(xref)
            .unwrap_or_bug(self.dcx(), "ident not found")
            .clone()
    }

    /// Interns text.
    pub fn intern_text(&self, text: Text) -> TextRef {
        self.inner.text.intern(text)
    }

    /// Retrieves text by its reference.
    ///
    /// It is an ICE if `xref` is not found.
    pub fn get_text(&self, xref: TextRef) -> Text {
        self.inner
            .text
            .get(xref)
            .unwrap_or_bug(self.dcx(), "text not found")
            .clone()
    }

    /// Interns a type.
    pub fn intern_type(&self, ty: Type) -> TypeRef {
        self.inner.types.intern(ty)
    }

    /// Retrieves a type by its reference.
    ///
    /// It is an ICE if `xref` is not found.
    pub fn get_type(&self, xref: TypeRef) -> &'cx Type {
        self.inner
            .types
            .get(xref)
            .unwrap_or_bug(self.dcx(), "type not found")
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
