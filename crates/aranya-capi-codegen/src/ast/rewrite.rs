use std::{fmt::Write, mem};

use aho_corasick::{AhoCorasick, MatchKind};
use syn::{
    Ident, LitStr, Path,
    visit_mut::{self, VisitMut},
};
use tracing::{debug, instrument, trace};

use super::{Ast, IdentMap};
use crate::{
    ctx::Ctx,
    syntax::{Doc, Item, Node, ReturnType, Trimmed, Type},
};

impl Ast {
    /// An AST pass that rewrites identifiers according to `ctx`.
    ///
    /// It rewrites identifiers located in:
    ///
    /// - Top level items (struct Foo, enum Bar, etc.)
    /// - Types (recursively and only where possible)
    /// - Function inputs and outputs
    ///
    /// It does not inspect function bodies.
    ///
    /// It returns a mapping of old to new identifiers.
    ///
    /// BUG(eric): We totally ignore generics here.
    #[instrument(skip_all)]
    pub(super) fn rewrite_idents(&mut self, ctx: &mut Ctx) {
        /// Rewrites `ident` using `idents`.
        fn rewrite_ident(ident: &mut Ident, idents: &IdentMap) {
            if let Some(new) = idents.get_new(ident) {
                debug!(old = %ident, %new, "rewriting ident");
                *ident = new.clone();
            } else {
                // `trace` instead of `debug` because
                // `trace` can be very noisy.
                trace!(%ident, "skipping unknown ident");
            }
        }

        /// Rewrites [`Path`]s.
        struct Visitor<'a> {
            idents: &'a IdentMap,
            ctx: &'a Ctx,
            prefix: bool,
        }
        impl VisitMut for Visitor<'_> {
            #[instrument(skip_all, fields(path = %Trimmed(path)))]
            fn visit_path_mut(&mut self, path: &mut Path) {
                if path.get_ident().is_some() {
                    rewrite_ident(&mut path.segments[0].ident, self.idents);
                } else if self.prefix
                    && !path.segments.is_empty()
                    && path.segments[0].ident != "self"
                    && path.segments[0].ident != "crate"
                    && path.segments[0].ident != "super"
                    && path.segments[0].ident != "core"
                    && path.segments[0].ident != self.ctx.imports
                    && path.segments[0].ident != self.ctx.hidden
                    && path.segments[0].ident != self.ctx.capi
                    && path.segments[0].ident != self.ctx.conv.segments[0].ident
                    && path.segments[0].ident != self.ctx.util.segments[0].ident
                    && path.segments[0].ident != self.ctx.error.segments[0].ident
                {
                    debug!(hello = %quote::quote!(#path));
                    let old = mem::take(&mut path.segments);
                    path.segments.push(self.ctx.imports.clone().into());
                    path.segments.extend(old);
                } else {
                    debug!("not an ident");
                }
                visit_mut::visit_path_mut(self, path);
            }
        }

        #[instrument(skip_all, fields(%ty))]
        fn rewrite_ty(ctx: &Ctx, ty: &mut Type, idents: &IdentMap) {
            match ty {
                // Cannot rewrite `CBytes`.
                Type::CBytes(_) => {}
                // Cannot rewrite `CStr`.
                Type::CStr(_) => {}
                Type::FnPtr(v) => {
                    for arg in &mut v.inputs {
                        rewrite_ty(ctx, &mut arg.ty, idents);
                    }
                    if let ReturnType::Type(_, ref mut ty) = v.output {
                        rewrite_ty(ctx, ty, idents);
                    }
                }
                Type::MaybeUninit(v) => rewrite_ty(ctx, &mut v.elem, idents),
                Type::Named(named) => {
                    if let Some(qself) = &mut named.qself {
                        rewrite_ty(ctx, &mut qself.ty, idents);
                    }
                    let mut visitor = Visitor {
                        idents,
                        ctx,
                        prefix: true,
                    };
                    visitor.visit_path_mut(&mut named.path);
                }
                Type::Option(opt) => rewrite_ty(ctx, &mut opt.elem, idents),
                Type::OwnedPtr(ptr) => rewrite_ty(ctx, &mut ptr.elem, idents),
                Type::Ptr(ptr) => rewrite_ty(ctx, &mut ptr.elem, idents),
                Type::Ref(xref) => rewrite_ty(ctx, &mut xref.elem, idents),
                Type::Result(res) => {
                    rewrite_ty(ctx, &mut res.ok, idents);
                    rewrite_ty(ctx, &mut res.err, idents)
                }
                Type::Safe(v) => rewrite_ty(ctx, &mut v.elem, idents),
                // Cannot rewrite `Scalar`.
                Type::Scalar(_) => {}
                Type::Slice(slice) => rewrite_ty(ctx, &mut slice.elem, idents),
                // Cannot rewrite `Str`.
                Type::Str(_) => {}
                // Cannot rewrite `Unit`.
                Type::Unit(_) => {}
                Type::Writer(writer) => rewrite_ty(ctx, &mut writer.elem, idents),
                // Not much we can do here.
                Type::Verbatim(_) => {
                    debug!("skipping `Verbatim`")
                }
            }
        }

        #[instrument(skip_all, fields(%node))]
        fn rewrite_node(node: &mut Node, ctx: &mut Ctx, idents: &IdentMap) {
            match node {
                Node::Alias(a) => {
                    rewrite_ty(ctx, &mut a.ty, idents);
                }
                Node::Enum(_e) => {
                    // TODO(eric): Walk enum fields? We should
                    // only have unit-only enums, though.
                }
                Node::FfiFn(f) => {
                    for arg in &mut f.sig.inputs {
                        rewrite_ty(ctx, &mut arg.ty, idents);
                    }
                    if let ReturnType::Type(_, ty) = &mut f.sig.output {
                        rewrite_ty(ctx, ty, idents);
                    }
                    let mut visitor = Visitor {
                        idents,
                        ctx,
                        prefix: false,
                    };
                    visitor.visit_block_mut(&mut f.block);
                }
                Node::RustFn(f) => {
                    for arg in &mut f.sig.inputs {
                        rewrite_ty(ctx, &mut arg.ty, idents);
                    }
                    if let ReturnType::Type(_, ty) = &mut f.sig.output {
                        rewrite_ty(ctx, ty, idents);
                    }
                    let mut visitor = Visitor {
                        idents,
                        ctx,
                        prefix: false,
                    };
                    visitor.visit_block_mut(&mut f.block);
                }
                Node::Struct(s) => {
                    for field in &mut s.fields {
                        rewrite_ty(ctx, &mut field.ty, idents);
                    }
                }
                Node::Union(u) => {
                    for field in &mut u.fields.named {
                        rewrite_ty(ctx, &mut field.ty, idents);
                    }
                }
                Node::Other(item) => {
                    let mut visitor = Visitor {
                        idents,
                        ctx,
                        prefix: false,
                    };
                    match item {
                        Item::Const(v) => visitor.visit_item_const_mut(v),
                        Item::Impl(v) => visitor.visit_item_impl_mut(v),
                        Item::Other(syn::Item::Mod(v)) => visitor.visit_item_mod_mut(v),
                        // TODO(eric): Should we do all `Item`s?
                        _ => {}
                    }
                }
            };
        }

        for node in &mut self.nodes {
            rewrite_node(node, ctx, &self.idents)
        }
    }

    /// Rewrite idents in `#[doc = "..."]`s, among other things.
    #[instrument(skip_all)]
    pub(super) fn rewrite_docs(&mut self, ctx: &mut Ctx) {
        fn rewrite_docs(ctx: &mut Ctx, docs: &mut Doc, ac: &AhoCorasick, idents: &IdentMap) {
            for doc in docs {
                let old = doc.value();
                let mut new = String::new();
                ac.replace_all_with(&old, &mut new, |_, text, dst| {
                    let Some(text) = text.strip_prefix("[`") else {
                        // False positive for `doc`.
                        #[allow(clippy::needless_borrows_for_generic_args)]
                        ctx.error(&doc, "missing `[`");
                        return true;
                    };
                    let Some(text) = text.strip_suffix("`]") else {
                        // False positive for `doc`.
                        #[allow(clippy::needless_borrows_for_generic_args)]
                        ctx.error(&doc, "missing `]`");
                        return true;
                    };
                    let Ok(ident) = syn::parse_str::<Ident>(text) else {
                        // False positive for `doc`.
                        #[allow(clippy::needless_borrows_for_generic_args)]
                        ctx.error(&doc, "invalid identifier");
                        return true;
                    };
                    if let Some(ident) = idents.get_new(&ident) {
                        let _ = write!(dst, "[`{ident}`](@ref {ident})");
                    } else {
                        let _ = write!(dst, "[`{text}`]");
                    }
                    true
                });
                *doc = LitStr::new(&new, doc.span());
            }
        }

        // Nothing else we can do here.
        #[allow(clippy::unwrap_used)]
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(self.idents.old_values().map(|v| format!("[`{v}`]")))
            .unwrap();

        fn rewrite_node(ctx: &mut Ctx, ac: &AhoCorasick, node: &mut Node, idents: &IdentMap) {
            match node {
                Node::Alias(a) => rewrite_docs(ctx, &mut a.doc, ac, idents),
                Node::Enum(e) => rewrite_docs(ctx, &mut e.doc, ac, idents),
                Node::FfiFn(f) => rewrite_docs(ctx, &mut f.doc, ac, idents),
                Node::RustFn(f) => rewrite_docs(ctx, &mut f.doc, ac, idents),
                Node::Struct(s) => rewrite_docs(ctx, &mut s.doc, ac, idents),
                Node::Union(u) => rewrite_docs(ctx, &mut u.doc, ac, idents),
                Node::Other(_) => {}
            }
        }

        for node in &mut self.nodes {
            rewrite_node(ctx, &ac, node, &self.idents)
        }

        rewrite_docs(ctx, &mut self.doc.0, &ac, &self.idents);
    }
}
