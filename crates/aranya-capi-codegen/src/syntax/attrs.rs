use std::fmt;

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, quote_spanned, ToTokens};
use syn::{
    parse::{Parse, ParseStream, Result},
    spanned::Spanned,
    AttrStyle, Attribute, Expr, Ident, Lit, LitStr, Meta, Path,
};
use tracing::{debug, instrument};

use super::{builds::Builds, derive::Derives, doc::Doc, opaque::Opaque, util::Trimmed};
use crate::ctx::Ctx;

mod kw {
    use syn::custom_keyword;

    custom_keyword!(Init);
    custom_keyword!(Cleanup);
    custom_keyword!(hidden);
}

/// Parses [`Attribute`]s.
///
/// Taken from [`cxx`].
///
/// [`cxx`]: https://github.com/dtolnay/cxx/blob/afd4aa3f3d4e5d5e9a3a41d09df3408f5f86a469/syntax/attrs.rs#L30
#[derive(Default)]
pub(crate) struct Parser<'a> {
    /// `#[doc(...)]` or `#[doc = ...]`
    pub doc: Option<&'a mut Doc>,
    /// `#[repr(...)]`
    pub repr: Option<&'a mut Option<Repr>>,
    /// `#[derive(...)]`
    pub derives: Option<&'a mut Derives>,
    /// `#[no_mangle]`
    pub no_mangle: Option<&'a mut Option<NoMangle>>,
    /// `#[capi::builds(...)]`
    pub capi_builds: Option<&'a mut Option<Builds>>,
    /// `#[capi::opaque(...)]`
    pub capi_opaque: Option<&'a mut Option<Opaque>>,
    /// `#[capi::error]`
    pub capi_error: Option<&'a mut Option<Error>>,
    /// `#[capi::ext_error]`
    pub capi_ext_error: Option<&'a mut Option<ExtError>>,
    /// `#[capi::no_ext_error]`
    pub capi_no_ext_error: Option<&'a mut Option<NoExtError>>,
    /// `#[capi::generated]`
    pub capi_generated: Option<&'a mut Option<Generated>>,
}

/// Parses attributes.
///
/// It returns the remaining "other" attributes.
///
/// # Example
///
/// ```ignore
/// let mut doc = Doc::new();
/// let mut repr = None;
/// let mut derives = Derives::new();
/// let mut error = None;
/// let attrs = attrs::parse(
///     ctx,
///     e.attrs,
///     Parser {
///         doc: Some(&mut doc),
///         repr: Some(&mut repr),
///         derives: Some(&mut derives),
///         capi_error: Some(&mut error),
///         ..Default::default()
///     },
/// );
/// ```
#[instrument(skip_all)]
pub(crate) fn parse(ctx: &Ctx, attrs: Vec<Attribute>, mut parser: Parser<'_>) -> Vec<Attribute> {
    let n = attrs.len();

    let mut passthru = Vec::new();
    for (i, attr) in attrs.into_iter().enumerate() {
        let path = attr.path();

        debug!(
            path = %Trimmed(path),
            "parsing attr {}/{n}",
            i.saturating_add(1)
        );

        // `#[aranya_capi_core::xxx]`
        // `#[capi::xxx]`
        if path.segments.len() == 2
            && (path.segments[0].ident == ctx.capi
                || path.segments[0].ident == "aranya_capi_core"
                || path.segments[0].ident == "capi")
        {
            if !parse_capi_attr(ctx, &attr, &mut parser) {
                passthru.push(attr);
            }
            continue;
        }

        // `#[derive(...)]`
        if path.is_ident("derive") {
            match attr.parse_args_with(|attr: ParseStream<'_>| Derives::parse(ctx, attr)) {
                Ok(attrs) => {
                    if let Some(derives) = &mut parser.derives {
                        derives.append(attrs);
                        continue;
                    }
                }
                Err(err) => {
                    ctx.push(err);
                    break;
                }
            }
        }

        // `#[doc(...)]` or `#[doc = ...]`
        if path.is_ident("doc") {
            match parse_doc_attr(&attr.meta) {
                Ok(attr) => {
                    if let Some(doc) = &mut parser.doc {
                        match attr {
                            DocAttr::Doc(lit) => doc.push(lit),
                            DocAttr::Hidden => doc.hidden = true,
                        }
                        continue;
                    }
                }
                Err(err) => {
                    ctx.push(err);
                    break;
                }
            }
        }

        // `#[no_mangle]`
        if path.is_ident("no_mangle") {
            if let Some(v) = &mut parser.no_mangle {
                **v = Some(NoMangle(attr.span()));
                continue;
            }
        }

        // `#[repr(...)]`
        if path.is_ident("repr") {
            match attr.parse_args::<Repr>() {
                Ok(attr) => {
                    if let Some(v) = &mut parser.repr {
                        **v = Some(attr);
                        continue;
                    }
                }
                Err(err) => {
                    ctx.push(err);
                    break;
                }
            }
        }

        passthru.push(attr);
    }
    passthru
}

/// Parses a `#[capi::xxx]` attribute.
///
/// Returns `false` if the attribute should be passed through.
#[instrument(skip_all)]
fn parse_capi_attr(ctx: &Ctx, attr: &Attribute, parser: &mut Parser<'_>) -> bool {
    assert_eq!(attr.path().segments.len(), 2);
    assert!(
        attr.path().segments[0].ident == ctx.capi
            || attr.path().segments[0].ident == "capi"
            || attr.path().segments[0].ident == "aranya_capi_core"
    );

    let span = attr.span();
    let ident = &attr.path().segments[1].ident;
    if ident == "builds" {
        match attr.parse_args_with(|attr: ParseStream<'_>| Builds::parse(attr)) {
            Ok(builds) => {
                if let Some(v) = &mut parser.capi_builds {
                    **v = Some(builds);
                    return true;
                }
            }
            Err(err) => {
                ctx.push(err);
                return true;
            }
        }
    } else if ident == "derive" {
        match attr.parse_args_with(|attr: ParseStream<'_>| Derives::parse(ctx, attr)) {
            Ok(attrs) => {
                if let Some(derives) = &mut parser.derives {
                    derives.append(attrs);
                    return true;
                }
            }
            Err(err) => {
                ctx.push(err);
                return true;
            }
        }
    } else if ident == "error" {
        if let Some(v) = &mut parser.capi_error {
            **v = Some(Error(span));
            return true;
        }
    } else if ident == "ext_error" {
        if let Some(v) = &mut parser.capi_ext_error {
            **v = Some(ExtError(span));
            return true;
        }
    } else if ident == "generated" {
        if let Some(v) = &mut parser.capi_generated {
            **v = Some(Generated(span));
            return true;
        }
    } else if ident == "opaque" {
        match attr.parse_args_with(|attr: ParseStream<'_>| Opaque::parse(Some(ctx), attr)) {
            Ok(attr) => {
                if let Some(v) = &mut parser.capi_opaque {
                    **v = Some(attr);
                    return true;
                }
            }
            Err(err) => {
                ctx.push(err);
                return false; // passthrough
            }
        }
    } else if ident == "no_ext_error" {
        if let Some(v) = &mut parser.capi_no_ext_error {
            **v = Some(NoExtError(span));
            return true;
        }
    } else {
        ctx.error(ident, format!("unknown `capi::` attribute: {ident}"));
        return true;
    }

    ctx.error(ident, "invalid `capi::` attribute for context");
    true
}

/// A `#[doc]` attribute.
enum DocAttr {
    /// `#[doc = "..."]`.
    Doc(LitStr),
    /// `#[doc(hidden)]`
    Hidden,
}

/// Taken from [`cxx`].
///
/// [`cxx`]: https://github.com/dtolnay/cxx/blob/afd4aa3f3d4e5d5e9a3a41d09df3408f5f86a469/syntax/attrs.rs#L196C1-L212C2
fn parse_doc_attr(meta: &Meta) -> Result<DocAttr> {
    match meta {
        Meta::NameValue(meta) => {
            if let Expr::Lit(expr) = &meta.value {
                if let Lit::Str(lit) = &expr.lit {
                    return Ok(DocAttr::Doc(lit.clone()));
                }
            }
        }
        Meta::List(meta) => {
            meta.parse_args::<kw::hidden>()?;
            return Ok(DocAttr::Hidden);
        }
        Meta::Path(_) => {}
    }
    Err(syn::Error::new_spanned(meta, "unsupported doc attribute"))
}

/// `#[repr(...)]`.
#[derive(
    Copy, Clone, Debug, Eq, PartialEq, strum::AsRefStr, strum::EnumString, strum::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum Repr {
    #[strum(serialize = "C")]
    C,
    Transparent,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
}

impl Repr {
    /// Returns the repr as a string.
    pub fn to_str(self) -> &'static str {
        self.into()
    }
}

impl PartialEq<Repr> for &Ident {
    fn eq(&self, repr: &Repr) -> bool {
        *self == repr
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#[repr({})]", self.to_str())
    }
}

impl Parse for Repr {
    fn parse(input: ParseStream<'_>) -> Result<Repr> {
        // Taken from [`cxx`].
        // https://github.com/dtolnay/cxx/blob/afd4aa3f3d4e5d5e9a3a41d09df3408f5f86a469/syntax/attrs.rs#L230
        let begin = input.cursor();
        let ident = input.parse::<Ident>()?;
        ident
            .to_string()
            .parse()
            .map_err(|_| syn::Error::new_spanned(begin.token_stream(), "unrecognized repr"))
    }
}

impl ToTokens for Repr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ident = format_ident!("{}", self.to_str());
        tokens.extend(quote! {
            #[repr(#ident)]
        })
    }
}

/// Extension trait for accessing attributes.
pub trait AttrsExt {
    /// Returns a shared ref to the attrs.
    fn get(&self) -> &[Attribute];

    /// Dumps all attributes.
    #[allow(dead_code)] // for debugging
    fn dump(&self) {
        println!("found {} attrs:", self.get().len());
        for attr in self.get() {
            println!("\t{}", quote!(#attr));
        }
    }

    /// Returns an iterator over the outer attributes.
    fn outer(&self) -> impl Iterator<Item = &Attribute> {
        fn is_outer(attr: &&Attribute) -> bool {
            match attr.style {
                AttrStyle::Outer => true,
                AttrStyle::Inner(_) => false,
            }
        }
        self.get().iter().filter(is_outer)
    }

    /// Returns an iterator over the inner attributes.
    fn inner(&self) -> impl Iterator<Item = &Attribute> {
        fn is_inner(attr: &&Attribute) -> bool {
            match attr.style {
                AttrStyle::Inner(_) => true,
                AttrStyle::Outer => false,
            }
        }
        self.get().iter().filter(is_inner)
    }

    /// Returns the `#[repr(...)]` attribute, if any.
    fn repr(&self) -> Option<&Attribute> {
        self.get().iter().find(|attr| attr.path().is_ident("repr"))
    }
}

impl AttrsExt for Vec<Attribute> {
    /// Returns a shared ref to the attrs.
    fn get(&self) -> &[Attribute] {
        self
    }
}

macro_rules! simple_outer_attr {
    ($name:ident, $value:literal) => {
        #[doc = concat!("The `#[", $value, "]` attribute.")]
        #[derive(Clone)]
        pub(crate) struct $name(pub Span);

        impl $name {
            /// Creates an attribute with a specific span.
            #[allow(dead_code)] // not always used
            pub fn with_span(span: Span) -> Self {
                Self(span)
            }

            #[allow(dead_code)] // not always used
            fn parse(_ctx: &Ctx, input: ParseStream<'_>) -> Result<Self> {
                Ok(Self(input.span()))
            }
        }

        impl Eq for $name {}
        impl PartialEq for $name {
            fn eq(&self, _other: &Self) -> bool {
                true
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", $value)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", $value)
            }
        }

        impl TryFrom<Attribute> for $name {
            type Error = syn::Error;
            fn try_from(attr: Attribute) -> Result<Self> {
                Ok(Self(attr.span()))
            }
        }

        impl ToTokens for $name {
            fn to_tokens(&self, tokens: &mut TokenStream) {
                // TODO(eric): Avoid calling unwrawp.
                let path = syn::parse_str::<Path>($value).unwrap();
                tokens.extend(quote_spanned! {self.0=>
                    #[#path]
                })
            }
        }
    };
}
simple_outer_attr!(Error, "capi::error");
simple_outer_attr!(ExtError, "capi::ext_error");
simple_outer_attr!(Generated, "capi::generated");
simple_outer_attr!(NoExtError, "capi::no_ext_error");
simple_outer_attr!(NoMangle, "no_mangle");
