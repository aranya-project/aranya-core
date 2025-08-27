//! Core pass system infrastructure for the compiler.
//!
//! This module provides a statically-typed pass system where
//! each compiler pass declares its output type and dependencies.
//! Passes are evaluated lazily and cached.

use std::{cell::OnceCell, marker::PhantomData};

use crate::{
    ctx::Ctx,
    depgraph::{BuildDepGraph, DepGraph},
    diag::ErrorGuaranteed,
    eval::{ConstEval, Consts},
    hir::{Hir, LowerAst},
    simplify::{Hir as SHir, SimplifyPass},
    symtab::{SymbolResolution, SymbolTable},
    typecheck::{Types, TypesPass},
};

/// A compiler pass with typed output and dependencies.
pub trait Pass: 'static {
    /// The name of this pass.
    const NAME: &'static str;

    /// The dependencies this pass requires.
    type Deps: DepList;

    /// The output type this pass produces.
    type Output: 'static;

    /// A more ergonomic view of [`Output`][Self::Output].
    type View<'cx>: View<'cx, Self::Output>;

    /// Run the pass with the given context and dependencies.
    fn run<'cx>(
        cx: Ctx<'cx>,
        deps: <Self::Deps as DepList>::Refs<'cx>,
    ) -> Result<Self::Output, ErrorGuaranteed>;
}

pub trait View<'cx, Data: 'cx> {
    fn new(cx: Ctx<'cx>, data: &'cx Data) -> Self;
}

/// Access trait for retrieving pass results from storage.
pub trait Access<P: Pass> {
    /// Get the storage cell for this pass's output.
    fn cell(&self) -> &OnceCell<P::Output>;
}

/// An element in a [`DepList`].
pub trait DepElem {
    /// TODO: docs
    type Ref<'cx>;
    /// TODO: docs
    fn fetch(cx: Ctx<'_>) -> Result<Self::Ref<'_>, ErrorGuaranteed>;
}

impl<P> DepElem for P
where
    P: Pass,
    Results: Access<P>,
{
    type Ref<'cx> = P::View<'cx>;
    fn fetch<'cx>(cx: Ctx<'cx>) -> Result<Self::Ref<'cx>, ErrorGuaranteed> {
        let out = cx.get::<P>()?;
        Ok(<P::View<'cx> as View<_>>::new(cx, out))
    }
}

/// TODO: docs
#[derive(Copy, Clone, Debug)]
pub struct Raw<P: Pass>(PhantomData<P>);

impl<P> DepElem for Raw<P>
where
    P: Pass,
    Results: Access<P>,
{
    type Ref<'cx> = &'cx P::Output;
    fn fetch(cx: Ctx<'_>) -> Result<Self::Ref<'_>, ErrorGuaranteed> {
        cx.get::<P>()
    }
}

/// A type-level list of dependencies.
pub trait DepList {
    /// TODO: docs
    type Refs<'cx>;
    /// TODO: docs
    fn fetch(cx: Ctx<'_>) -> Result<Self::Refs<'_>, ErrorGuaranteed>;
}

impl DepList for () {
    type Refs<'cx> = ();
    fn fetch(_cx: Ctx<'_>) -> Result<Self::Refs<'_>, ErrorGuaranteed> {
        Ok(())
    }
}

macro_rules! impl_deplist_tuples {
    () => {};
    ($H:ident $(, $T:ident)*) => {
        impl<$H: DepElem, $($T: DepElem),*> DepList for ($H, $($T,)*) {
            type Refs<'cx> = (
                <$H as DepElem>::Ref<'cx>,
                $(<$T as DepElem>::Ref<'cx>,)*
            );
            #[allow(non_snake_case)]
            fn fetch(cx: Ctx<'_>) -> Result<Self::Refs<'_>, ErrorGuaranteed> {
                Ok((
                    <$H as DepElem>::fetch(cx)?,
                    $(<$T as DepElem>::fetch(cx)?,)*
                ))
            }
        }
        impl_deplist_tuples!($($T),*);
    };
}
impl_deplist_tuples!(A, B, C, D, E, F);

pub type DepsRefs<'cx, P> = <<P as Pass>::Deps as DepList>::Refs<'cx>;

/// Storage for pass results.
#[derive(Clone, Debug)]
pub struct Results {
    pub hir: OnceCell<Hir>,
    pub shir: OnceCell<SHir>,
    pub symbols: OnceCell<SymbolTable>,
    pub deps: OnceCell<DepGraph>,
    pub types: OnceCell<Types>,
    pub consts: OnceCell<Consts>,
}

impl Results {
    pub fn new() -> Self {
        Self {
            hir: OnceCell::new(),
            shir: OnceCell::new(),
            symbols: OnceCell::new(),
            deps: OnceCell::new(),
            types: OnceCell::new(),
            consts: OnceCell::new(),
        }
    }
}

impl Default for Results {
    fn default() -> Self {
        Self::new()
    }
}

impl Access<LowerAst> for Results {
    fn cell(&self) -> &OnceCell<Hir> {
        &self.hir
    }
}

impl Access<SimplifyPass> for Results {
    fn cell(&self) -> &OnceCell<SHir> {
        &self.shir
    }
}

impl Access<SymbolResolution> for Results {
    fn cell(&self) -> &OnceCell<SymbolTable> {
        &self.symbols
    }
}

impl Access<BuildDepGraph> for Results {
    fn cell(&self) -> &OnceCell<DepGraph> {
        &self.deps
    }
}

impl Access<TypesPass> for Results {
    fn cell(&self) -> &OnceCell<Types> {
        &self.types
    }
}

impl Access<ConstEval> for Results {
    fn cell(&self) -> &OnceCell<Consts> {
        &self.consts
    }
}
