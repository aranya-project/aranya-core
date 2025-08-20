mod expand;
mod rewrite;

use std::collections::HashMap;

use bimap::{BiHashMap, hash::LeftValues};
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{Error, Ident, Path, Result};
use tracing::{instrument, trace};

use crate::{
    ctx::Ctx,
    syntax::{self, Item, Node, Type},
    util::{IdentExt, PathExt},
};

/// An AST (for some definition of "AST") for a generated C API.
#[derive(Debug)]
pub struct Ast {
    /// All AST nodes.
    pub nodes: Vec<Node>,
    /// A list of all types (structs, enums, etc.) keyed by their
    /// unmodified identifier.
    pub types: HashMap<Ident, Node>,
    /// Maps old identifiers to the ty/fn prefixed identifiers
    /// and back again.
    pub(super) idents: IdentMap,
    /// Code that should appear inside a `mod __hidden { ... }`.
    pub hidden: TokenStream,
}

impl Ast {
    /// Parses an `Ast` from the module.
    #[instrument(skip_all)]
    pub fn parse(ctx: &mut Ctx, items: Vec<Item>) -> Result<Self> {
        trace!(items = items.len(), "parsing AST");

        let mut ast = {
            let nodes = syntax::parse_items(ctx, items);
            let types = nodes
                .iter()
                .filter_map(|n| {
                    let ident = match n {
                        Node::Alias(a) => &a.ident,
                        Node::Enum(e) => &e.ident,
                        Node::Struct(s) => &s.ident,
                        Node::Union(u) => &u.ident,
                        _ => return None,
                    };
                    Some((ident.clone(), n.clone()))
                })
                .collect();
            let idents = collect_idents(ctx, &nodes);

            // Update spans so that the compiler emits nicer
            // error messages.
            fn set_span(path: &mut Path) -> Result<()> {
                match path.segments.last_mut() {
                    Some(seg) => {
                        seg.ident.set_span(seg.ident.span());
                        Ok(())
                    }
                    None => Err(Error::new_spanned(path, "missing last segment")),
                }
            }
            set_span(&mut ctx.err_ty)?;
            set_span(&mut ctx.ext_err_ty)?;

            Self {
                nodes,
                types,
                idents,
                hidden: TokenStream::new(),
            }
        };

        ast.prune_impls(ctx);
        ast.update_aliases(ctx);
        ast.rewrite_idents(ctx);
        ast.expand_nodes(ctx);
        // Rewrite identifiers first. This misses out on any
        // generated idents (mostly FFI functions), but
        // simplifies the rewriting process.
        ast.rewrite_idents(ctx);
        // Find new identifiers after expansion.
        ast.find_new_idents(ctx);
        ast.rewrite_docs(ctx);
        Ok(ast)
    }

    /// Adds a node to the AST.
    #[instrument(skip_all)]
    pub(super) fn add_node<T: Into<Node>>(&mut self, node: T) {
        let node = node.into();
        trace!(%node, "adding node");
        self.nodes.push(node);
    }

    /// Adds nodes to the AST.
    #[instrument(skip_all)]
    pub(super) fn extend(&mut self, nodes: impl IntoIterator<Item = Node>) {
        for node in nodes {
            self.add_node(node);
        }
    }

    /// Adds code to the `mod __hidden { ... }`.
    #[instrument(skip_all)]
    pub(super) fn add_hidden_node<T: ToTokens>(&mut self, tokens: T) {
        trace!("adding hidden node");

        tokens.to_tokens(&mut self.hidden);
    }

    /// Removes unneeded `impl` blocks.
    #[instrument(skip_all)]
    fn prune_impls(&mut self, ctx: &Ctx) {
        self.nodes.retain_mut(|node| {
            let Node::Other(Item::Impl(imp)) = node else {
                return true;
            };
            let Some(_) = &imp.trait_ else {
                return false;
            };
            let syn::Type::Path(syn::TypePath { path, .. }) = imp.self_ty.as_ref() else {
                return false;
            };
            let Some(ident) = path.get_ident() else {
                return false;
            };
            let Some(ident) = self.idents.get_new(ident) else {
                return false;
            };
            for ty in &[ctx.err_ty.ty_name(), ctx.ext_err_ty.ty_name()] {
                if ident == *ty {
                    return true;
                }
            }
            false
        });
    }

    /// Update type aliases to refer to the "defs" type.
    ///
    /// For example, rewrite
    ///
    /// ```ignore
    /// // mod defs
    /// type Foo = ::capi::Safe<X>;
    /// ```
    ///
    /// as
    ///
    /// ```ignore
    /// // mod generated
    /// type OsFoo = super::defs::Foo;
    /// ```
    fn update_aliases(&mut self, ctx: &Ctx) {
        for node in &mut self.nodes {
            if let Node::Alias(a) = node {
                *a.ty = Type::named(ctx.defs.join(a.ident.clone()));
            }
        }
    }

    /// Finds new identifiers.
    fn find_new_idents(&mut self, ctx: &Ctx) {
        for node in &self.nodes {
            let (old, new) = match node {
                n @ (Node::Alias(_) | Node::Enum(_) | Node::Struct(_) | Node::Union(_)) => {
                    let Some(ident) = n.ident() else {
                        ctx.error(n, "node should have an ident");
                        continue;
                    };
                    trace!(%ident, "skipping alias/enum/struct/union node");
                    continue;
                }
                Node::FfiFn(f) => {
                    let old = f.sig.ident.clone();
                    let new = old.with_prefix(&ctx.fn_prefix);
                    (old, new)
                }
                _ => continue,
            };
            if !self.idents.contains_new(&new) {
                trace!(%old, %new, "found new ident");
                self.idents.insert(old, new);
            }
        }
    }
}

/// Collects all top-level identifiers.
fn collect_idents(ctx: &Ctx, nodes: &[Node]) -> IdentMap {
    let idents = nodes
        .iter()
        .filter_map(|node| match node {
            n @ (Node::Alias(_) | Node::Enum(_) | Node::Struct(_) | Node::Union(_)) => {
                let Some(ident) = n.ident() else {
                    ctx.error(n, "node should have an ident");
                    return None;
                };
                let old = ident.clone();
                let new = old.with_prefix(&ctx.ty_prefix);
                Some((old, new))
            }
            Node::FfiFn(f) => {
                let old = f.sig.ident.clone();
                let new = old.with_prefix(&ctx.fn_prefix);
                Some((old, new))
            }
            Node::RustFn(f) => {
                let old = f.sig.ident.clone();
                let new = old.with_prefix(&ctx.fn_prefix);
                Some((old, new))
            }
            Node::Other(_) => None,
        })
        .inspect(|(old, new)| trace!(%old, %new, "found ident"))
        .collect();
    IdentMap(idents)
}

/// Maps old identifiers to the prefixes identifiers.
#[derive(Debug)]
pub struct IdentMap(pub BiHashMap<OldIdent, NewIdent>);

impl IdentMap {
    pub(super) fn get_new(&self, old: &OldIdent) -> Option<&NewIdent> {
        self.0.get_by_left(old)
    }

    pub(super) fn get_old(&self, new: &NewIdent) -> Option<&OldIdent> {
        self.0.get_by_right(new)
    }

    pub(super) fn old_values(&self) -> LeftValues<'_, OldIdent, NewIdent> {
        self.0.left_values()
    }

    pub(super) fn insert(&mut self, old: OldIdent, new: NewIdent) {
        self.0.insert(old, new);
    }

    pub(super) fn contains_new(&self, new: &NewIdent) -> bool {
        self.0.contains_right(new)
    }
}

pub type OldIdent = Ident;
pub type NewIdent = Ident;
