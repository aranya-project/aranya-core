//! Compilation session and context.

use std::cell::OnceCell;

use aranya_policy_ast::{Identifier, Text};

use crate::{
    ast::Ast,
    depgraph::{DepGraph, DepsPass},
    diag::{DiagCtx, ErrorGuaranteed, OptionExt},
    hir::{Hir, HirLowerPass, IdentInterner, IdentRef, TextInterner, TextRef},
    pass::{Access, DepList, Pass},
    symbol_resolution::{SymbolTable, SymbolsPass},
};

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

/// Compilation session containing all compiler state.
#[derive(Debug)]
pub struct InnerCtx<'cx> {
    pub sess: &'cx Session,

    /// TODO
    pub ast: Ast<'cx>,

    /// Identifier interner.
    pub idents: IdentInterner,

    /// Text interner.
    pub text: TextInterner,

    /// Results from core passes.
    pub results: Results,
}

impl<'cx> InnerCtx<'cx> {
    /// Create a new compilation session.
    pub fn new(sess: &'cx Session, ast: Ast<'cx>) -> Self {
        Self {
            sess,
            ast,
            idents: IdentInterner::new(),
            text: TextInterner::new(),
            results: Results::new(),
        }
    }
}

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

/// Storage for pass results.
#[derive(Clone, Debug)]
pub struct Results {
    pub hir: OnceCell<Hir>,
    pub symbols: OnceCell<SymbolTable>,
    pub deps: OnceCell<DepGraph>,
    // pub types: OnceCell<TypeInfo>,
}

impl Results {
    pub fn new() -> Self {
        Self {
            hir: OnceCell::new(),
            symbols: OnceCell::new(),
            deps: OnceCell::new(),
            // types: OnceCell::new(),
        }
    }
}

impl Default for Results {
    fn default() -> Self {
        Self::new()
    }
}

impl Access<HirLowerPass> for Results {
    fn cell(&self) -> &OnceCell<Hir> {
        &self.hir
    }
}

impl Access<SymbolsPass> for Results {
    fn cell(&self) -> &OnceCell<SymbolTable> {
        &self.symbols
    }
}

impl Access<DepsPass> for Results {
    fn cell(&self) -> &OnceCell<DepGraph> {
        &self.deps
    }
}

// impl Access<TypesPass> for Results {
//     fn cell(&self) -> &OnceCell<TypeInfo> {
//         &self.types
//     }
// }
