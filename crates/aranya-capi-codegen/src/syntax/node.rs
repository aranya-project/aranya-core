use std::fmt;

use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, TokenStreamExt, quote};
pub use syn::Abi;
use syn::{
    Attribute, Block, Error, Expr, GenericParam, Generics, Ident, ItemEnum, ItemFn, ItemStruct,
    ItemType, ItemUnion, LifetimeParam, Lit, LitInt, Pat, PatIdent, PatType, Result, Signature,
    Token, Visibility,
    punctuated::{self, Punctuated},
    spanned::Spanned,
    token::{Brace, Paren},
};
use tracing::{debug, instrument, trace};

use super::{
    attrs::{self, AttrsExt, ExtError, Generated, NoExtError, NoMangle, Parser, Repr},
    builds::Builds,
    derive::Derives,
    doc::Doc,
    file::Item,
    opaque::Opaque,
    types::{ReturnType, Scalar, ScalarType, Type},
    util::TokensOrDefault,
};
use crate::ctx::Ctx;

/// Parses [`Item`]s into [`Node`]s.
#[instrument(skip_all)]
pub(crate) fn parse_items(ctx: &Ctx, items: Vec<Item>) -> Vec<Node> {
    trace!(items = items.len(), "parsing items");

    let mut nodes = Vec::new();
    for item in items {
        match item {
            Item::Enum(e) => match Enum::parse(ctx, e) {
                Ok(e) => nodes.push(e.into()),
                Err(err) => ctx.push(err),
            },
            Item::Fn(f) => match RustFn::parse(ctx, f) {
                Ok(e) => nodes.push(e.into()),
                Err(err) => ctx.push(err),
            },
            Item::Struct(s) => match Struct::parse(ctx, s) {
                Ok(s) => nodes.push(s.into()),
                Err(err) => ctx.push(err),
            },
            Item::Type(t) => match Alias::parse(ctx, t) {
                Ok(t) => nodes.push(t.into()),
                Err(err) => ctx.push(err),
            },
            Item::Union(u) => match Union::parse(ctx, u) {
                Ok(u) => nodes.push(u.into()),
                Err(err) => ctx.push(err),
            },

            Item::Const(item) => nodes.push(item.into()),
            Item::Use(item) => nodes.push(item.into()),
            Item::Other(syn::Item::Use(v)) => nodes.push(v.into()),
            // TODO(eric): Do we need any other items?
            item => {
                debug!(?item, "skipping item");
            }
        }
    }
    nodes
}

/// An AST node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// A type alias.
    Alias(Alias),
    /// An enumeration.
    Enum(Enum),
    /// A freestanding generated FFI function.
    FfiFn(FfiFn),
    /// A freestanding Rust function.
    RustFn(RustFn),
    /// A struct.
    Struct(Struct),
    /// A union.
    Union(Union),
    /// Something else.
    Other(Item),
}

impl Node {
    /// Returns the node's identifier, if any.
    pub fn ident(&self) -> Option<&Ident> {
        match self {
            Self::Alias(a) => Some(&a.ident),
            Self::Enum(e) => Some(&e.ident),
            Self::FfiFn(f) => Some(&f.sig.ident),
            Self::RustFn(f) => Some(&f.sig.ident),
            Self::Struct(s) => Some(&s.ident),
            Self::Union(u) => Some(&u.ident),
            Self::Other(_) => None,
        }
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alias(v) => write!(f, "Alias({})", v.ident),
            Self::Enum(v) => write!(f, "Enum({})", v.ident),
            Self::FfiFn(v) => write!(f, "FfiFn({})", v.sig.ident),
            Self::RustFn(v) => write!(f, "RustFn({})", v.sig.ident),
            Self::Struct(v) => write!(f, "Struct({})", v.ident),
            Self::Union(v) => write!(f, "Union({})", v.ident),
            Self::Other(_) => write!(f, "Other(...)"),
        }
    }
}

impl ToTokens for Node {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Alias(a) => a.to_tokens(tokens),
            Self::Enum(e) => e.to_tokens(tokens),
            Self::FfiFn(f) => f.to_tokens(tokens),
            Self::RustFn(f) => f.to_tokens(tokens),
            Self::Struct(s) => s.to_tokens(tokens),
            Self::Union(u) => u.to_tokens(tokens),
            Self::Other(o) => o.to_tokens(tokens),
        }
    }
}

impl<T: Into<Item>> From<T> for Node {
    fn from(v: T) -> Self {
        Self::Other(v.into())
    }
}

macro_rules! from_impl {
    ($($from:ty => $variant:ident),+ $(,)?) => {
        $(
            impl From<$from> for Node {
                fn from(v: $from) -> Self {
                    Self::$variant(v)
                }
            }
        )+
    };
}
from_impl! {
    Alias => Alias,
    Enum => Enum,
    FfiFn => FfiFn,
    RustFn => RustFn,
    Struct => Struct,
    Union => Union,
}

macro_rules! fmt_impl {
    ($($name:ident => $($ident:tt).+),+ $(,)?) => {
        $(
            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    let ident = &self.$($ident).+;
                    write!(f, "{}({ident})", stringify!($name))
                }
            }
        )+
    };
}
fmt_impl! {
    Alias => ident,
    Enum => ident,
    FfiFn => sig.ident,
    RustFn => sig.ident,
    Struct => ident,
    Union => ident,
}

macro_rules! attrs_impl {
    ($($name:ident),+ $(,)?) => {
        $(
            impl AttrsExt for $name {
                fn get(&self) -> &[Attribute] {
                    &self.attrs
                }
            }
        )+
    };
}
attrs_impl! {
    Alias,
    Enum,
    FfiFn,
    RustFn,
    Struct,
    Union,
}

/// A `type = ...` definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Alias {
    pub doc: Doc,
    pub derives: Derives,
    pub ext_error: Option<ExtError>,
    pub opaque: Option<Opaque>,
    pub builds: Option<Builds>,
    /// Other attrs.
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub type_token: Token![type],
    pub ident: Ident,
    pub lifetimes: Lifetimes,
    pub eq_token: Token![=],
    pub ty: Box<Type>,
    pub semi_token: Token![;],
}

impl Alias {
    #[instrument(skip_all, fields(name = %t.ident))]
    pub(super) fn parse(ctx: &Ctx, t: ItemType) -> Result<Self> {
        trace!("parsing `Alias`");

        let mut doc = Doc::new();
        let mut derives = Derives::new();
        let mut ext_error = None;
        let mut opaque = None;
        let mut builds = None;
        let attrs = attrs::parse(
            ctx,
            t.attrs,
            Parser {
                doc: Some(&mut doc),
                derives: Some(&mut derives),
                capi_ext_error: Some(&mut ext_error),
                capi_opaque: Some(&mut opaque),
                capi_builds: Some(&mut builds),
                ..Default::default()
            },
        );

        Ok(Self {
            doc,
            derives,
            ext_error,
            opaque,
            builds,
            attrs,
            vis: t.vis,
            type_token: t.type_token,
            ident: t.ident,
            lifetimes: Lifetimes::parse(ctx, t.generics)?,
            eq_token: t.eq_token,
            ty: Box::new(Type::parse(ctx, *t.ty)?),
            semi_token: t.semi_token,
        })
    }
}

impl ToTokens for Alias {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // NB: We do not emit `capi::` attributes.

        self.doc.to_tokens(tokens);
        tokens.append_all(self.attrs.outer());
        self.opaque.to_tokens(tokens);
        self.vis.to_tokens(tokens);
        self.type_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        self.lifetimes.to_tokens(tokens);
        self.eq_token.to_tokens(tokens);
        self.ty.to_tokens(tokens);
        self.semi_token.to_tokens(tokens);
    }
}

/// A `struct` definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Struct {
    pub doc: Doc,
    pub derives: Derives,
    pub repr: Repr,
    pub ext_error: Option<ExtError>,
    pub opaque: Option<Opaque>,
    pub builds: Option<Builds>,
    /// Other attrs.
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub struct_token: Token![struct],
    pub ident: Ident,
    pub fields: Fields,
    pub semi_token: Option<Token![;]>,
}

impl Struct {
    #[instrument(skip_all, fields(name = %s.ident))]
    pub(crate) fn parse(ctx: &Ctx, s: ItemStruct) -> Result<Self> {
        trace!("parsing `Struct`");

        let span = s.span();
        let mut doc = Doc::new();
        let mut derives = Derives::new();
        let mut repr = None;
        let mut ext_error = None;
        let mut opaque = None;
        let mut builds = None;
        let attrs = attrs::parse(
            ctx,
            s.attrs,
            Parser {
                doc: Some(&mut doc),
                repr: Some(&mut repr),
                derives: Some(&mut derives),
                capi_ext_error: Some(&mut ext_error),
                capi_opaque: Some(&mut opaque),
                capi_builds: Some(&mut builds),
                ..Default::default()
            },
        );

        let repr = match repr {
            Some(repr @ (Repr::C | Repr::Transparent)) => repr,
            Some(repr) => {
                return Err(Error::new_spanned(
                    repr,
                    format!("invalid `#[repr(...)]` for `struct`: `{repr}`"),
                ));
            }
            None => return Err(Error::new(span, "missing `#[repr(...)]`")),
        };

        Ok(Self {
            doc,
            repr,
            derives,
            ext_error,
            opaque,
            builds,
            attrs,
            vis: s.vis,
            struct_token: s.struct_token,
            ident: s.ident,
            fields: Fields::parse(ctx, s.fields)?,
            semi_token: s.semi_token,
        })
    }
}

impl ToTokens for Struct {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // NB: We do not emit `capi::` attributes.

        self.doc.to_tokens(tokens);
        self.derives.to_tokens(tokens);
        self.repr.to_tokens(tokens);
        tokens.append_all(self.attrs.outer());
        self.opaque.to_tokens(tokens);
        self.vis.to_tokens(tokens);
        self.struct_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        match &self.fields {
            Fields::Named(fields) => fields.to_tokens(tokens),
            Fields::Unnamed(fields) => {
                fields.to_tokens(tokens);
                self.semi_token.to_tokens(tokens);
            }
            Fields::Unit => self.semi_token.to_tokens(tokens),
        }
    }
}

/// [`Struct`] fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Fields {
    /// `Foo { ... }`.
    Named(FieldsNamed),
    /// `Bar( ... )`.
    Unnamed(FieldsUnnamed),
    /// `None`.
    Unit,
}

impl Fields {
    #[instrument(skip_all)]
    pub(crate) fn parse(ctx: &Ctx, fields: syn::Fields) -> Result<Self> {
        trace!("parsing `Fields`");

        let fields = match fields {
            syn::Fields::Named(v) => Self::Named(FieldsNamed::parse(ctx, v)?),
            syn::Fields::Unnamed(v) => Self::Unnamed(FieldsUnnamed::parse(ctx, v)?),
            syn::Fields::Unit => Self::Unit,
        };
        Ok(fields)
    }

    /// Returns an iterator over the [`Field`]s.
    pub fn iter(&self) -> Iter<'_, Field> {
        match self {
            Self::Named(f) => f.named.iter(),
            Self::Unnamed(f) => f.unnamed.iter(),
            Self::Unit => {
                const EMPTY: &Punctuated<Field, Token![,]> = &Punctuated::new();
                EMPTY.iter()
            }
        }
    }

    /// Returns an iterator over the [`Field`]s.
    pub fn iter_mut(&mut self) -> IterMut<'_, Field> {
        match self {
            Self::Named(f) => IterMut(Some(f.named.iter_mut())),
            Self::Unnamed(f) => IterMut(Some(f.unnamed.iter_mut())),
            Self::Unit => IterMut(None),
        }
    }

    /// Returns the number of fields.
    pub fn len(&self) -> usize {
        match self {
            Self::Named(f) => f.named.len(),
            Self::Unnamed(f) => f.unnamed.len(),
            Self::Unit => 0,
        }
    }
}

impl IntoIterator for Fields {
    type IntoIter = IntoIter<Field>;
    type Item = Field;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Self::Named(v) => v.named.into_iter(),
            Self::Unnamed(v) => v.unnamed.into_iter(),
            Self::Unit => Punctuated::<Field, Token![,]>::new().into_iter(),
        }
    }
}

impl<'a> IntoIterator for &'a Fields {
    type Item = &'a Field;
    type IntoIter = Iter<'a, Field>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut Fields {
    type Item = &'a mut Field;
    type IntoIter = IterMut<'a, Field>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl ToTokens for Fields {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Named(v) => v.to_tokens(tokens),
            Self::Unnamed(v) => v.to_tokens(tokens),
            Self::Unit => {}
        }
    }
}

/// Named [`Struct`] or [`Union`] fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldsNamed {
    pub brace_token: Brace,
    pub named: Punctuated<Field, Token![,]>,
}

impl FieldsNamed {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, fields: syn::FieldsNamed) -> Result<Self> {
        trace!("parsing `FieldsNamed`");

        Ok(Self {
            brace_token: fields.brace_token,
            named: fields
                .named
                .into_iter()
                .map(|f| Field::parse_named(ctx, f))
                .collect::<Result<_>>()?,
        })
    }
}

impl ToTokens for FieldsNamed {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.brace_token.surround(tokens, |tokens| {
            self.named.to_tokens(tokens);
        });
    }
}

/// Unnamed [`Struct`] fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldsUnnamed {
    pub paren_token: Paren,
    pub unnamed: Punctuated<Field, Token![,]>,
}

impl FieldsUnnamed {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, fields: syn::FieldsUnnamed) -> Result<Self> {
        trace!("parsing `FieldsUnnamed`");

        Ok(Self {
            paren_token: fields.paren_token,
            unnamed: fields
                .unnamed
                .into_iter()
                .map(|f| Field::parse_unnamed(ctx, f))
                .collect::<Result<_>>()?,
        })
    }
}

impl ToTokens for FieldsUnnamed {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.paren_token.surround(tokens, |tokens| {
            self.unnamed.to_tokens(tokens);
        });
    }
}

/// A [`Struct`] or [`Union`] field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub doc: Doc,
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub ident: Option<Ident>,
    pub colon_token: Option<Token![:]>,
    pub ty: Type,
}

impl Field {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, f: syn::Field) -> Result<Self> {
        trace!("parsing `Field`");

        let mut doc = Doc::new();
        let attrs = attrs::parse(
            ctx,
            f.attrs,
            Parser {
                doc: Some(&mut doc),
                ..Default::default()
            },
        );

        Ok(Self {
            doc,
            attrs,
            vis: f.vis,
            ident: f.ident,
            colon_token: f.colon_token,
            ty: Type::parse(ctx, f.ty)?,
        })
    }

    /// Parse a field for [`FieldsNamed`].
    #[instrument(skip_all)]
    fn parse_named(ctx: &Ctx, f: syn::Field) -> Result<Self> {
        trace!("parsing named `Field`");

        if f.ident.is_none() {
            ctx.error(&f, "missing ident");
        }
        if f.colon_token.is_none() {
            ctx.error(&f, "missing colon");
        }

        let mut doc = Doc::new();
        let attrs = attrs::parse(
            ctx,
            f.attrs,
            Parser {
                doc: Some(&mut doc),
                ..Default::default()
            },
        );

        Ok(Self {
            doc,
            attrs,
            vis: f.vis,
            ident: f.ident,
            colon_token: f.colon_token,
            ty: Type::parse(ctx, f.ty)?,
        })
    }

    /// Parse a field for [`FieldsUnnamed`].
    #[instrument(skip_all)]
    fn parse_unnamed(ctx: &Ctx, f: syn::Field) -> Result<Self> {
        trace!("parsing unnamed `Field`");

        if f.ident.is_some() {
            ctx.error(&f, "must not have ident");
        }
        if f.colon_token.is_some() {
            ctx.error(&f, "must not have colon");
        }

        let mut doc = Doc::new();
        let attrs = attrs::parse(
            ctx,
            f.attrs,
            Parser {
                doc: Some(&mut doc),
                ..Default::default()
            },
        );

        Ok(Self {
            doc,
            attrs,
            vis: f.vis,
            ident: f.ident,
            colon_token: f.colon_token,
            ty: Type::parse(ctx, f.ty)?,
        })
    }
}

impl ToTokens for Field {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.doc.to_tokens(tokens);
        tokens.append_all(&self.attrs);
        self.vis.to_tokens(tokens);
        if let Some(ident) = &self.ident {
            ident.to_tokens(tokens);
            self.colon_token.unwrap_or_default().to_tokens(tokens);
        }
        self.ty.to_tokens(tokens);
    }
}

/// An `enum` definition.
///
/// Enums must be unit-only with a specified `#[repr(...)]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enum {
    pub doc: Doc,
    pub derives: Derives,
    pub repr: Repr,
    pub error: Option<attrs::Error>,
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub enum_token: Token![enum],
    pub ident: Ident,
    pub brace_token: Brace,
    pub variants: Punctuated<Variant, Token![,]>,
}

impl Enum {
    #[instrument(skip_all, fields(name = %e.ident))]
    pub(super) fn parse(ctx: &Ctx, e: ItemEnum) -> Result<Self> {
        trace!("parsing `Enum`");

        let mut doc = Doc::new();
        let mut derives = Derives::new();
        let mut repr = None;
        let mut error = None;
        let attrs = attrs::parse(
            ctx,
            e.attrs,
            Parser {
                doc: Some(&mut doc),
                repr: Some(&mut repr),
                derives: Some(&mut derives),
                capi_error: Some(&mut error),
                ..Default::default()
            },
        );

        let repr = match repr {
            Some(
                repr @ (Repr::U8
                | Repr::U16
                | Repr::U32
                | Repr::U64
                | Repr::Usize
                | Repr::I8
                | Repr::I16
                | Repr::I32
                | Repr::I64
                | Repr::Isize),
            ) => repr,
            Some(_) => return Err(Error::new_spanned(repr, "invalid `#[repr(...)]`")),
            None => {
                return Err(Error::new_spanned(
                    &e.ident,
                    "`enum`s must have `#[repr(...)]`",
                ));
            }
        };

        Ok(Self {
            doc,
            derives,
            repr,
            error,
            attrs,
            vis: e.vis,
            enum_token: e.enum_token,
            ident: e.ident,
            brace_token: e.brace_token,
            variants: e
                .variants
                .into_iter()
                .map(|v| Variant::parse(ctx, v))
                .collect::<Result<_>>()?,
        })
    }

    /// Returns the enum's repr type.
    pub fn to_repr(&self) -> Type {
        let ty = match self.repr {
            Repr::U8 => ScalarType::U8,
            Repr::U16 => ScalarType::U16,
            Repr::U32 => ScalarType::U32,
            Repr::U64 => ScalarType::U64,
            Repr::Usize => ScalarType::Usize,
            Repr::I8 => ScalarType::I8,
            Repr::I16 => ScalarType::I16,
            Repr::I32 => ScalarType::I32,
            Repr::I64 => ScalarType::I64,
            Repr::Isize => ScalarType::Isize,
            // This is checked by `Enum::parse`.
            _ => unreachable!("`Enum` can only have int reprs"),
        };
        Type::Scalar(Scalar {
            ty,
            span: self.repr.span(),
        })
    }
}

impl ToTokens for Enum {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // NB: We do not emit `capi::` attributes.

        self.doc.to_tokens(tokens);
        self.derives.to_tokens(tokens);
        self.repr.to_tokens(tokens);
        tokens.append_all(self.attrs.outer());
        self.vis.to_tokens(tokens);
        self.enum_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        self.brace_token.surround(tokens, |tokens| {
            self.variants.to_tokens(tokens);
        });
    }
}

/// An [`Enum`] variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Variant {
    pub doc: Doc,
    pub attrs: Vec<Attribute>,
    pub ident: Ident,
    // TODO(eric): disallow anything other than unit fields.
    pub fields: Fields,
    pub discriminant: Option<(Token![=], LitInt)>,
}

impl Variant {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, v: syn::Variant) -> Result<Self> {
        trace!("parsing `Variant`");

        let mut doc = Doc::new();
        let mut attrs = attrs::parse(
            ctx,
            v.attrs,
            Parser {
                doc: Some(&mut doc),
                ..Default::default()
            },
        );

        // TODO
        if false {
            attrs.retain(|a| {
                // Exclude `#[capi(...)]`.
                !a.path().is_ident("capi")
            });
        }

        // TODO(eric): disallow anything other than unit fields.

        let discriminant = match v.discriminant {
            None => None,
            Some((token, expr)) => {
                let expr: Expr = expr;
                let Expr::Lit(lit) = expr else {
                    return Err(Error::new_spanned(
                        expr,
                        "discriminants must be integer literals",
                    ));
                };
                let Lit::Int(int) = lit.lit else {
                    return Err(Error::new_spanned(
                        lit,
                        "discriminants must be integer literals",
                    ));
                };
                Some((token, int))
            }
        };

        Ok(Self {
            doc,
            attrs,
            ident: v.ident,
            fields: Fields::parse(ctx, v.fields)?,
            discriminant,
        })
    }
}

impl ToTokens for Variant {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.doc.to_tokens(tokens);
        tokens.append_all(&self.attrs);
        self.ident.to_tokens(tokens);
        self.fields.to_tokens(tokens);
        if let Some((eq_token, disc)) = &self.discriminant {
            eq_token.to_tokens(tokens);
            disc.to_tokens(tokens);
        }
    }
}

/// Either a [`RustFn`] or [`FfiFn`].
#[derive(Clone, Debug)]
pub enum Fn {
    Rust(RustFn),
    Ffi(FfiFn),
}

impl ToTokens for Fn {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Rust(f) => f.to_tokens(tokens),
            Self::Ffi(f) => f.to_tokens(tokens),
        }
    }
}

impl From<FfiFn> for Fn {
    fn from(f: FfiFn) -> Self {
        Self::Ffi(f)
    }
}

impl From<RustFn> for Fn {
    fn from(f: RustFn) -> Self {
        Self::Rust(f)
    }
}

/// A freestanding FFI `fn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FfiFn {
    pub doc: Doc,
    pub no_mangle: Option<NoMangle>,
    /// Other attrs.
    pub attrs: Vec<Attribute>,
    pub vis: Token![pub],
    pub sig: FfiFnSig,
    pub block: Box<Block>,
}

impl FfiFn {
    #[instrument(skip_all, fields(name = %f.sig.ident))]
    pub(crate) fn parse(ctx: &Ctx, f: ItemFn) -> Result<Self> {
        trace!("parsing `FfiFn`");

        let mut doc = Doc::new();
        let mut no_mangle = None;
        let attrs = attrs::parse(
            ctx,
            f.attrs,
            Parser {
                doc: Some(&mut doc),
                no_mangle: Some(&mut no_mangle),
                ..Default::default()
            },
        );

        let name = &f.sig.ident;
        if no_mangle.is_none() {
            return Err(Error::new_spanned(
                &f.sig,
                format!("BUG: FFI fn must be `#[unsafe(no_mangle)]`: `{name}`"),
            ));
        }
        if !matches!(f.vis, Visibility::Public(_)) {
            return Err(Error::new_spanned(
                &f.vis,
                format!("BUG: FFI fn must be `pub`: `{name}`"),
            ));
        }

        let sig = FfiFnSig::parse(ctx, f.sig)?;

        Ok(Self {
            doc,
            no_mangle,
            attrs,
            vis: Token![pub](f.vis.span()),
            sig,
            block: f.block,
        })
    }
}

impl ToTokens for FfiFn {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // NB: We do not emit `capi::` attributes.

        self.doc.to_tokens(tokens);
        self.no_mangle.to_tokens(tokens);
        tokens.append_all(self.attrs.outer());
        self.vis.to_tokens(tokens);
        self.sig.to_tokens(tokens);
        self.block.brace_token.surround(tokens, |tokens| {
            tokens.append_all(self.attrs.inner());
            tokens.append_all(&self.block.stmts);
        });
    }
}

/// A [`FfiFn`] signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FfiFnSig {
    pub unsafety: Option<Token![unsafe]>,
    pub abi: Abi,
    pub fn_token: Token![fn],
    pub ident: Ident,
    pub lifetimes: Lifetimes,
    pub paren_token: Paren,
    pub inputs: Punctuated<FnArg, Token![,]>,
    pub output: ReturnType,
}

impl FfiFnSig {
    #[instrument(skip_all, fields(ident = %sig.ident))]
    fn parse(ctx: &Ctx, sig: Signature) -> Result<Self> {
        trace!("parsing `FfiFnSig`");

        let Some(abi) = sig.abi else {
            return Err(Error::new_spanned(
                sig.abi,
                format!("BUG: FFI functions must specify an ABI: `{}`", sig.ident),
            ));
        };
        if abi.name.as_ref().is_none_or(|name| name.value() != "C") {
            ctx.error(
                &abi,
                format!(
                    "BUG: FFI functions must use the \"C\" ABI: `{}` (got `{}`)",
                    sig.ident,
                    quote!(#abi)
                ),
            );
        }

        Ok(Self {
            unsafety: sig.unsafety,
            abi,
            fn_token: sig.fn_token,
            ident: sig.ident,
            lifetimes: Lifetimes::parse(ctx, sig.generics)?,
            paren_token: sig.paren_token,
            inputs: sig
                .inputs
                .into_iter()
                .map(|arg| FnArg::parse_ffi(ctx, arg))
                .collect::<Result<_>>()?,
            output: ReturnType::parse(ctx, sig.output)?,
        })
    }
}

impl ToTokens for FfiFnSig {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.unsafety.to_tokens(tokens);
        self.abi.to_tokens(tokens);
        self.fn_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        self.lifetimes.to_tokens(tokens);
        self.paren_token.surround(tokens, |tokens| {
            self.inputs.to_tokens(tokens);
        });
        self.output.to_tokens(tokens);
    }
}

/// A freestanding Rust `fn`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustFn {
    pub doc: Doc,
    // TODO(eric): Get rid of this. It's a hack used by the
    // expand passes.
    pub generated: Option<Generated>,
    pub no_ext_error: Option<NoExtError>,
    pub no_mangle: Option<NoMangle>,
    /// Other attrs.
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub sig: RustFnSig,
    pub block: Box<Block>,
}

impl RustFn {
    #[instrument(skip_all, fields(name = %f.sig.ident))]
    pub(crate) fn parse(ctx: &Ctx, f: ItemFn) -> Result<Self> {
        trace!(f = %quote!(#f), "parsing `RustFn`");

        let mut doc = Doc::new();
        let mut generated = None;
        let mut no_ext_error = None;
        let mut no_mangle = None;
        let attrs = attrs::parse(
            ctx,
            f.attrs,
            Parser {
                doc: Some(&mut doc),
                capi_generated: Some(&mut generated),
                capi_no_ext_error: Some(&mut no_ext_error),
                no_mangle: Some(&mut no_mangle),
                ..Default::default()
            },
        );

        let sig = RustFnSig::parse(ctx, f.sig)?;

        Ok(Self {
            doc,
            generated,
            no_ext_error,
            no_mangle,
            attrs,
            vis: f.vis,
            sig,
            block: f.block,
        })
    }

    /// Reports whether the fn is `pub`.
    pub const fn is_pub(&self) -> bool {
        matches!(self.vis, Visibility::Public(_))
    }
}

impl ToTokens for RustFn {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        // NB: We do not emit `capi::` attributes.

        // Docs are only needed if this is `pub`. Otherwise,
        // they're just noise.
        if self.is_pub() {
            self.doc.to_tokens(tokens);
        }
        self.no_mangle.to_tokens(tokens);
        tokens.append_all(self.attrs.outer());
        self.vis.to_tokens(tokens);
        self.sig.to_tokens(tokens);
        self.block.brace_token.surround(tokens, |tokens| {
            tokens.append_all(self.attrs.inner());
            tokens.append_all(&self.block.stmts);
        });
    }
}

/// A [`Fn`] signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RustFnSig {
    pub unsafety: Option<Token![unsafe]>,
    pub abi: Option<Abi>,
    pub fn_token: Token![fn],
    pub ident: Ident,
    pub lifetimes: Lifetimes,
    pub paren_token: Paren,
    pub inputs: Punctuated<FnArg, Token![,]>,
    pub output: ReturnType,
}

impl RustFnSig {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, sig: Signature) -> Result<Self> {
        trace!("parsing `RustFnSig`");

        Ok(Self {
            unsafety: sig.unsafety,
            abi: sig.abi,
            fn_token: sig.fn_token,
            ident: sig.ident,
            lifetimes: Lifetimes::parse(ctx, sig.generics)?,
            paren_token: sig.paren_token,
            inputs: sig
                .inputs
                .into_iter()
                .map(|arg| FnArg::parse_rust(ctx, arg))
                .collect::<Result<_>>()?,
            output: ReturnType::parse(ctx, sig.output)?,
        })
    }
}

impl ToTokens for RustFnSig {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.unsafety.to_tokens(tokens);
        self.abi.to_tokens(tokens);
        self.fn_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        self.lifetimes.to_tokens(tokens);
        self.paren_token.surround(tokens, |tokens| {
            self.inputs.to_tokens(tokens);
        });
        self.output.to_tokens(tokens);
    }
}

/// A [`Fn`] argument.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FnArg {
    pub attrs: Vec<Attribute>,
    pub name: Ident,
    pub colon_token: Token![:],
    pub ty: Type,
}

impl FnArg {
    pub(crate) fn parse_rust(ctx: &Ctx, arg: syn::FnArg) -> Result<Self> {
        trace!("parsing Rust `FnArg`");

        Self::parse(ctx, arg, false)
    }

    pub(crate) fn parse_ffi(ctx: &Ctx, arg: syn::FnArg) -> Result<Self> {
        trace!("parsing FFI `FnArg`");

        Self::parse(ctx, arg, true)
    }

    /// Creates a single `usize` argument.
    pub(crate) fn usize(name: Ident) -> Self {
        let span = Span::call_site();
        Self {
            attrs: Vec::new(),
            name,
            // TODO(eric): use a better span?
            colon_token: Token![:](span),
            ty: Type::usize(span),
        }
    }

    fn parse(ctx: &Ctx, arg: syn::FnArg, ffi: bool) -> Result<Self> {
        let syn::FnArg::Typed(PatType {
            attrs,
            pat,
            colon_token,
            ty,
        }) = arg
        else {
            return Err(Error::new_spanned(
                arg,
                "only typed function arguments are allowed",
            ));
        };

        let attrs = attrs::parse(ctx, attrs, Default::default());

        // TODO(eric): What about mut, ref, etc?
        let Pat::Ident(PatIdent { ident, .. }) = *pat else {
            return Err(Error::new_spanned(
                pat,
                "only plain identifier fn arg names are allowed",
            ));
        };

        let ty = Type::parse(ctx, *ty)?;
        if ffi && matches!(ty, Type::Ref(_)) {
            return Err(Error::new_spanned(ty, "type not allowed in FFI function"));
        }
        if !ffi && matches!(ty, Type::Unit(_)) {
            return Err(Error::new_spanned(ty, "type not allowed in Rust function"));
        }
        // TODO(eric): what about other types? Like `MaybeUninit`
        // is only allowed behind a mut pointer/ref.

        Ok(Self {
            attrs,
            name: ident,
            colon_token,
            ty,
        })
    }
}

impl ToTokens for FnArg {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(self.attrs.outer());
        self.name.to_tokens(tokens);
        self.colon_token.to_tokens(tokens);
        self.ty.to_tokens(tokens);
    }
}

/// A `union` definition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Union {
    pub doc: Doc,
    pub attrs: Vec<Attribute>,
    pub vis: Visibility,
    pub union_token: Token![union],
    pub ident: Ident,
    pub fields: FieldsNamed,
}

impl Union {
    #[instrument(skip_all, fields(name = %u.ident))]
    pub(super) fn parse(ctx: &Ctx, u: ItemUnion) -> Result<Self> {
        trace!("parsing `Union`");

        let mut doc = Doc::new();
        let attrs = attrs::parse(
            ctx,
            u.attrs,
            Parser {
                doc: Some(&mut doc),
                ..Default::default()
            },
        );

        Ok(Self {
            doc,
            attrs,
            vis: u.vis,
            union_token: u.union_token,
            ident: u.ident,
            fields: FieldsNamed::parse(ctx, u.fields)?,
        })
    }
}

impl ToTokens for Union {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(self.attrs.outer());
        self.doc.to_tokens(tokens);
        self.vis.to_tokens(tokens);
        self.union_token.to_tokens(tokens);
        self.ident.to_tokens(tokens);
        self.fields.to_tokens(tokens);
    }
}

/// Lifetime parameters.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Lifetimes {
    pub lt_token: Option<Token![<]>,
    pub params: Punctuated<LifetimeParam, Token![,]>,
    pub gt_token: Option<Token![>]>,
}

impl Lifetimes {
    pub(crate) fn parse(_ctx: &Ctx, g: Generics) -> Result<Self> {
        Ok(Self {
            lt_token: g.lt_token,
            params: g
                .params
                .into_iter()
                .map(|p| {
                    if let GenericParam::Lifetime(lp) = p {
                        Ok(lp)
                    } else {
                        Err(Error::new_spanned(
                            &p,
                            "only lifetime parameters are allowed",
                        ))
                    }
                })
                .collect::<Result<_>>()?,
            gt_token: g.gt_token,
        })
    }

    pub(crate) fn none() -> Self {
        Self {
            lt_token: None,
            params: Punctuated::new(),
            gt_token: None,
        }
    }
}

impl ToTokens for Lifetimes {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        if self.params.is_empty() {
            return;
        }
        TokensOrDefault(&self.lt_token).to_tokens(tokens);
        self.params.to_tokens(tokens);
        TokensOrDefault(&self.gt_token).to_tokens(tokens);
    }
}

// TODO(eric): move these iters somewhere else

/// See [`punctuated::Iter`].
pub type Iter<'a, T> = punctuated::Iter<'a, T>;

/// See [`punctuated::IterMut`].
pub struct IterMut<'a, T>(Option<punctuated::IterMut<'a, T>>);

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = <punctuated::IterMut<'a, T> as Iterator>::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.as_mut()?.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.as_ref().map_or((0, Some(0)), |v| v.size_hint())
    }
}

impl<T> DoubleEndedIterator for IterMut<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.as_mut()?.next_back()
    }
}

impl<T> ExactSizeIterator for IterMut<'_, T> {
    fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |v| v.len())
    }
}

/// See [`punctuated::IntoIter`].
pub type IntoIter<T> = punctuated::IntoIter<T>;

// TODO
/*
#[cfg(test)]
mod tests {
    use proc_macro2::Span;
    use syn::parse_quote;

    use super::*;

    #[test]
    fn test_parse_node_ffi_fn() {
        let span = Span::call_site();
        let got: Node = parse_quote! {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn foo() {}
        };
        let want = Node::FfiFn(FfiFn {
            no_mangle: NoMangle(span),
            vis: Token![pub](span),
            attrs: vec![parse_quote! {
                #[unsafe(no_mangle)],
            }],
            sig: parse_quote! {
                unsafe extern "C" fn foo()
            },
            block: parse_quote! {{}},
        });
        assert_eq!(got, want);
    }
}

*/
