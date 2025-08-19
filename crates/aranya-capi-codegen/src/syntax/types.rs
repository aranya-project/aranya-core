use std::{borrow::Cow, cmp, fmt};

use proc_macro2::{Delimiter, Group, Span, TokenStream};
use quote::{ToTokens, TokenStreamExt, format_ident, quote};
use syn::{
    Abi, Attribute, BareFnArg, BareVariadic, Error, GenericArgument, Ident, Lifetime, Path,
    PathArguments, PathSegment, Result, Token, TypeBareFn, TypePath, TypeSlice,
    parse_quote_spanned,
    punctuated::Punctuated,
    spanned::Spanned,
    token::{Bracket, Paren},
};
use tracing::{debug, instrument, trace};

use super::{
    attrs::AttrsExt,
    util::{TokensOrDefault, Trimmed},
};
use crate::ctx::Ctx;

mod kw {
    syn::custom_keyword!(CBytes);
    syn::custom_keyword!(CStr);
    syn::custom_keyword!(MaybeUninit);
    syn::custom_keyword!(Option);
    syn::custom_keyword!(OwnedPtr);
    syn::custom_keyword!(Result);
    syn::custom_keyword!(Safe);
    syn::custom_keyword!(Writer);
    syn::custom_keyword!(str);
}

#[derive(Clone, Debug)]
pub enum Type {
    /// `CBytes`.
    CBytes(CBytes),
    /// `CStr`.
    CStr(CStr),
    /// `extern "C" fn(...)`.
    FnPtr(Box<FnPtr>),
    /// `MaybeUninit<T>`.
    MaybeUninit(Box<MaybeUninit>),
    /// Some other named type.
    Named(Named),
    /// `Option<T>`.
    Option(Box<Opt>),
    /// `OwnedPtr<T>`.
    OwnedPtr(Box<OwnedPtr>),
    /// `*const T` or `*mut T`.
    Ptr(Box<Ptr>),
    /// `&T` or `&mut T`, but `T` cannot be `[U]`.
    Ref(Box<Ref>),
    /// `Result<T, E>`.
    Result(Box<ResultType>),
    /// `u8`, `f32`, etc.
    Scalar(Scalar),
    /// `Safe<T>`.
    Safe(Box<Safe>),
    /// `[T]`.
    Slice(Box<Slice>),
    /// `str`.
    Str(Str),
    /// `()`.
    Unit(Unit),
    /// `Writer<T>`.
    Writer(Box<Writer>),
    /// Verbatim tokens.
    Verbatim(TokenStream),
}

impl Type {
    /// Creates [`Type::Named`] from `ident`.
    pub fn named(path: Path) -> Self {
        Self::Named(Named { qself: None, path })
    }

    /// Returns a `usize` type.
    pub(crate) fn usize(span: Span) -> Self {
        Self::Scalar(Scalar {
            ty: ScalarType::Usize,
            span,
        })
    }

    /// Converts `self` to `*mut self`.
    pub(crate) fn into_mut_ptr(self) -> Self {
        let span = Span::call_site();
        Self::Ptr(Box::new(Ptr {
            star_token: Token![*](span),
            const_token: None,
            mutability: Some(Token![mut](span)),
            elem: self,
        }))
    }

    /// Returns the "unknown" generic type.
    pub(crate) fn unknown() -> Self {
        Self::Named(Named::unknown())
    }

    /// Returns `self` with [`Named`] types mapped to `_`.
    pub(crate) fn generify(&self) -> Cow<'_, Self> {
        macro_rules! do_match {
            ($ty:ident, $inner:ident) => {
                match $inner.elem.generify() {
                    Cow::Owned(elem) => {
                        let mut v = $inner.clone();
                        v.elem = elem;
                        Cow::Owned(Self::$ty(v))
                    }
                    Cow::Borrowed(_) => Cow::Borrowed(self),
                }
            };
        }

        match self {
            Self::CBytes(_) => Cow::Borrowed(self),
            Self::CStr(_) => Cow::Borrowed(self),
            Self::FnPtr(_f) => todo!(),
            Self::MaybeUninit(uninit) => do_match!(MaybeUninit, uninit),
            Self::Named(_) => Cow::Owned(Self::unknown()),
            Self::Option(opt) => do_match!(Option, opt),
            Self::OwnedPtr(ptr) => do_match!(OwnedPtr, ptr),
            Self::Ptr(ptr) => do_match!(Ptr, ptr),
            Self::Ref(xref) => do_match!(Ref, xref),
            Self::Result(res) => match (res.ok.generify(), res.err.generify()) {
                (Cow::Borrowed(_), Cow::Borrowed(_)) => Cow::Borrowed(self),
                (Cow::Owned(ok), Cow::Borrowed(_)) => {
                    let mut res = res.clone();
                    res.ok = ok;
                    Cow::Owned(Self::Result(res))
                }
                (Cow::Borrowed(_), Cow::Owned(err)) => {
                    let mut res = res.clone();
                    res.err = err;
                    Cow::Owned(Self::Result(res))
                }
                (Cow::Owned(lhs), Cow::Owned(rhs)) => {
                    let mut res = res.clone();
                    res.ok = lhs;
                    res.err = rhs;
                    Cow::Owned(Self::Result(res))
                }
            },
            Self::Scalar(_) => Cow::Borrowed(self),
            Self::Safe(safe) => do_match!(Safe, safe),
            Self::Slice(slice) => do_match!(Slice, slice),
            Self::Str(_) => Cow::Borrowed(self),
            Self::Unit(_) => Cow::Borrowed(self),
            Self::Writer(writer) => do_match!(Writer, writer),
            Self::Verbatim(_) => Cow::Borrowed(self),
        }
    }

    #[instrument(skip_all)]
    pub(crate) fn parse(ctx: &Ctx, ty: syn::Type) -> Result<Self> {
        match ty {
            syn::Type::BareFn(f) => {
                // NB: use `parse_opt`
                ctx.error(&f, "function pointer must be wrapped in `Option<...>`");
                Ok(Self::Verbatim(quote!(#f)))
            }
            syn::Type::Group(_) => Err(Error::new(
                ty.span(),
                "cannot parse `None`-delimited groups",
            )),
            // TODO(eric): prevent `Option` and `Result` in
            // results.
            syn::Type::Path(path) => parse_type_path(ctx, path),
            syn::Type::Ptr(ptr) => Ptr::parse(ctx, ptr).map(Box::new).map(Type::Ptr),
            syn::Type::Reference(xref) => Ref::parse(ctx, xref).map(Box::new).map(Type::Ref),
            syn::Type::Slice(slice) => Slice::parse(ctx, slice).map(Box::new).map(Type::Slice),
            syn::Type::Tuple(tuple) => {
                if tuple.elems.is_empty() {
                    ctx.error(&tuple, "`()` can only be used with `Result<(), ...>`");
                } else {
                    ctx.error(&tuple, "non-unit tuples are not allowed");
                }
                Unit::parse(ctx, tuple).map(Type::Unit)
            }
            syn::Type::Verbatim(tokens) => Ok(Self::Verbatim(tokens)),
            _ => Ok(Self::Verbatim(quote!(#ty))),
        }
    }

    /// Like [`parse`][Self::parse], but for [`Opt`].
    #[instrument(skip_all, fields())]
    pub(crate) fn parse_opt(ctx: &Ctx, ty: syn::Type) -> Result<Self> {
        match ty {
            syn::Type::BareFn(f) => FnPtr::parse(ctx, f).map(Box::new).map(Type::FnPtr),
            ty => {
                let ty = Self::parse(ctx, ty)?;
                if !matches!(ty, Self::OwnedPtr(_) | Self::Ref(_)) {
                    ctx.error(
                        &ty,
                        "`Option` can only be used with references, function pointers, and `OwnedPtr`",
                    );
                }
                Ok(ty)
            }
        }
    }

    /// Like [`parse`][Self::parse], but for [`ReturnType`].
    #[instrument(skip_all, fields())]
    pub(crate) fn parse_ret_ty(ctx: &Ctx, ty: syn::Type) -> Result<Self> {
        match ty {
            syn::Type::Tuple(tuple) if tuple.elems.is_empty() => {
                Unit::parse(ctx, tuple).map(Type::Unit)
            }
            ty => Type::parse(ctx, ty),
        }
    }

    /// Like [`parse`][Self::parse], but for [`ResultType`]'s
    /// `ok` field.
    #[instrument(skip_all, fields())]
    pub(crate) fn parse_res_ok(ctx: &Ctx, ty: syn::Type) -> Result<Self> {
        match ty {
            syn::Type::Tuple(tuple) => Unit::parse(ctx, tuple).map(Type::Unit),
            ty => Self::parse(ctx, ty),
        }
    }
}

/// Parse [`TypePath`] into [`Type`].
#[instrument(skip_all, fields(path = %Trimmed(&ty)))]
fn parse_type_path(ctx: &Ctx, ty: TypePath) -> Result<Type> {
    // Is this a scalar?
    if let Some(ident) = ty.path.get_ident() {
        if let Ok(ty) = Scalar::parse(ctx, ident) {
            return Ok(Type::Scalar(ty));
        }
    }
    if CBytes::matches(&ty) {
        CBytes::parse(ctx, ty).map(Type::CBytes)
    } else if CStr::matches(&ty) {
        CStr::parse(ctx, ty).map(Type::CStr)
    } else if MaybeUninit::matches(&ty) {
        MaybeUninit::parse(ctx, ty)
            .map(Box::new)
            .map(Type::MaybeUninit)
    } else if Opt::matches(&ty) {
        Opt::parse(ctx, ty).map(Box::new).map(Type::Option)
    } else if OwnedPtr::matches(&ty) {
        OwnedPtr::parse(ctx, ty).map(Box::new).map(Type::OwnedPtr)
    } else if ResultType::matches(&ty) {
        ResultType::parse(ctx, ty).map(Box::new).map(Type::Result)
    } else if Safe::matches(&ty) {
        Safe::parse(ctx, ty).map(Box::new).map(Type::Safe)
    } else if Str::matches(&ty) {
        Str::parse(ctx, ty).map(Type::Str)
    } else if Writer::matches(&ty) {
        Writer::parse(ctx, ty).map(Box::new).map(Type::Writer)
    } else {
        Named::parse(ctx, ty).map(Type::Named)
    }
}

/// Reports whether the two paths are the same.
#[instrument(skip_all, fields(candidate = %Trimmed(path), target = want))]
fn type_path_matches(path: &TypePath, want: &str) -> bool {
    if want.starts_with("::") != path.path.leading_colon.is_some() {
        debug!("mismatched leading colon");
        return false;
    }
    let want = want.strip_prefix("::").unwrap_or(want);

    let mut segments = path.path.segments.iter();
    for elem in want.split("::") {
        assert!(!elem.is_empty());

        let Some(seg) = segments.next() else {
            debug!(elem, "missing segment");
            return false;
        };

        let args = match &seg.arguments {
            // Match `Foo`.
            PathArguments::None => {
                if seg.ident != elem {
                    debug!(got = %seg.ident, want = elem, "different idents");
                    return false;
                }
                continue;
            }
            // Match `Foo<T>`.
            PathArguments::AngleBracketed(args) => args,
            PathArguments::Parenthesized(_) => {
                // TODO(eric): Is this even possible?
                unreachable!("parenthesized")
            }
        };

        // Match `Foo<T, ...>`.
        let Some((ident, inner)) = elem.split_once('<') else {
            debug!(
                got = %quote!(#seg),
                want = elem,
                "unexpected generic segment",
            );
            return false;
        };
        let inner = inner.strip_suffix('>').expect("malformed path element");

        if seg.ident != ident {
            debug!(got = %seg.ident, want = ident, "different idents");
            return false;
        }

        let n = inner
            .split(',')
            .inspect(|v| {
                assert_eq!(v.trim(), "*");
            })
            .count();
        if args.args.len() != n {
            debug!(
                got = args.args.len(),
                want = n,
                "different number of segments",
            );
            return false;
        }
    }
    if segments.next().is_some() {
        debug!("too many segments");
        return false;
    }
    true
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CBytes(_) => "CBytes",
            Self::CStr(_) => "CStr",
            Self::FnPtr(_) => "FnPtr",
            Self::MaybeUninit(_) => "MaybeUninit",
            Self::Named(_) => "Named",
            Self::Option(_) => "Option",
            Self::OwnedPtr(_) => "OwnedPtr",
            Self::Ptr(_) => "Ptr",
            Self::Ref(_) => "Ref",
            Self::Result(_) => "Result",
            Self::Safe(_) => "Safe",
            Self::Scalar(_) => "Scalar",
            Self::Slice(_) => "Slice",
            Self::Str(_) => "Str",
            Self::Unit(_) => "Unit",
            Self::Writer(_) => "Writer",
            Self::Verbatim(_) => "Verbatim",
        };

        let mut code = quote!(const _: #self = ();).to_string();
        if let Ok(file) = syn::parse_file(&code) {
            code = prettyplease::unparse(&file);
        }
        let code = code
            .trim()
            .strip_prefix("const _: ")
            .unwrap_or(&code)
            .strip_suffix(" = ();")
            .unwrap_or(&code);

        let mut s = String::new();
        for c in code.chars() {
            if c == '\n' || c == '\t' {
                continue;
            }
            if c.is_whitespace() {
                if !s.ends_with(char::is_whitespace) {
                    s.push(' ');
                }
            } else {
                s.push(c);
            }
        }
        write!(f, "{name}({s})")
    }
}

impl Eq for Type {}
impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::FnPtr(lhs), Self::FnPtr(rhs)) => lhs == rhs,
            (Self::MaybeUninit(lhs), Self::MaybeUninit(rhs)) => lhs == rhs,
            (Self::Named(lhs), Self::Named(rhs)) => lhs == rhs,
            (Self::Option(lhs), Self::Option(rhs)) => lhs == rhs,
            (Self::OwnedPtr(lhs), Self::OwnedPtr(rhs)) => lhs == rhs,
            (Self::Ptr(lhs), Self::Ptr(rhs)) => lhs == rhs,
            (Self::Ref(lhs), Self::Ref(rhs)) => lhs == rhs,
            (Self::Result(lhs), Self::Result(rhs)) => lhs == rhs,
            (Self::Safe(lhs), Self::Safe(rhs)) => lhs == rhs,
            (Self::Scalar(lhs), Self::Scalar(rhs)) => lhs == rhs,
            (Self::Slice(lhs), Self::Slice(rhs)) => lhs == rhs,
            (Self::Str(lhs), Self::Str(rhs)) => lhs == rhs,
            (Self::Unit(lhs), Self::Unit(rhs)) => lhs == rhs,
            (Self::Writer(lhs), Self::Writer(rhs)) => lhs == rhs,
            (Self::Verbatim(_), Self::Verbatim(_)) => {
                // TODO(eric): implement this?
                false
            }
            _ => false,
        }
    }
}

macro_rules! from_impl {
    ($($name:ident => $inner:ident),+ $(,)?) => {
        $(
            impl From<$inner> for Type {
                fn from(v: $inner) -> Self {
                    Self::$name(v)
                }
            }
        )+
    }
}
from_impl! {
    Named => Named,
    Scalar => Scalar,
    Unit => Unit,
}

macro_rules! from_boxed_impl {
    ($($name:ident => $inner:ident),+ $(,)?) => {
        $(
            impl From<$inner> for Type {
                fn from(v: $inner) -> Self {
                    Box::new(v).into()
                }
            }
            impl From<Box<$inner>> for Type {
                fn from(v: Box<$inner>) -> Self {
                    Self::$name(v)
                }
            }
        )+
    }
}
from_boxed_impl! {
    FnPtr => FnPtr,
    MaybeUninit => MaybeUninit,
    Option => Opt,
    OwnedPtr => OwnedPtr,
    Ptr => Ptr,
    Ref => Ref,
    Result => ResultType,
    Safe => Safe,
}

impl From<TokenStream> for Type {
    fn from(v: TokenStream) -> Self {
        Self::Verbatim(v)
    }
}

impl ToTokens for Type {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::CBytes(v) => v.to_tokens(tokens),
            Self::CStr(v) => v.to_tokens(tokens),
            Self::FnPtr(v) => v.to_tokens(tokens),
            Self::MaybeUninit(v) => v.to_tokens(tokens),
            Self::Named(v) => v.to_tokens(tokens),
            Self::Option(v) => v.to_tokens(tokens),
            Self::OwnedPtr(v) => v.to_tokens(tokens),
            Self::Ptr(v) => v.to_tokens(tokens),
            Self::Ref(v) => v.to_tokens(tokens),
            Self::Result(v) => v.to_tokens(tokens),
            Self::Safe(v) => v.to_tokens(tokens),
            Self::Scalar(v) => v.to_tokens(tokens),
            Self::Slice(v) => v.to_tokens(tokens),
            Self::Str(v) => v.to_tokens(tokens),
            Self::Unit(v) => v.to_tokens(tokens),
            Self::Writer(v) => v.to_tokens(tokens),
            Self::Verbatim(v) => v.to_tokens(tokens),
        }
    }
}

/// `CBytes`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CBytes {
    pub ident: kw::CBytes,
}

impl CBytes {
    #[instrument(skip_all)]
    fn parse(_ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `CBytes`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }
        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        if !matches!(arguments, PathArguments::None) {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment must not have arguments",
            ));
        }

        Ok(Self {
            ident: kw::CBytes(ident.span()),
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "CBytes") || type_path_matches(ty, "__capi::safe::CBytes")
    }
}

impl ToTokens for CBytes {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(__capi::safe::CBytes));
    }
}

/// `CStr`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CStr {
    pub ident: kw::CStr,
}

impl CStr {
    #[instrument(skip_all)]
    fn parse(_ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `CStr`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }
        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        if !matches!(arguments, PathArguments::None) {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment must not have arguments",
            ));
        }

        Ok(Self {
            ident: kw::CStr(ident.span()),
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "CStr") || type_path_matches(ty, "__capi::safe::CStr")
    }
}

impl ToTokens for CStr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(__capi::safe::CStr));
    }
}

/// `extern "C" fn(...)`.
///
/// It is only allowed when used as the inner type for [`Opt`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FnPtr {
    pub unsafety: Option<Token![unsafe]>,
    pub abi: Abi,
    pub fn_token: Token![fn],
    pub paren_token: Paren,
    pub inputs: Punctuated<FnPtrArg, Token![,]>,
    pub variadic: Option<BareVariadic>,
    pub output: ReturnType,
}

impl FnPtr {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, f: TypeBareFn) -> Result<Self> {
        trace!("parsing `FnPtr`");

        let Some(abi) = f.abi else {
            return Err(Error::new_spanned(
                f.abi,
                "function pointers must specify an ABI",
            ));
        };
        // TODO(eric): require the C ABI?

        Ok(Self {
            unsafety: f.unsafety,
            abi,
            fn_token: f.fn_token,
            paren_token: f.paren_token,
            inputs: f
                .inputs
                .into_iter()
                .map(|arg| FnPtrArg::parse(ctx, arg))
                .collect::<Result<_>>()?,
            variadic: f.variadic,
            output: ReturnType::parse(ctx, f.output)?,
        })
    }
}

impl ToTokens for FnPtr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.unsafety.to_tokens(tokens);
        self.abi.to_tokens(tokens);
        self.fn_token.to_tokens(tokens);
        self.paren_token.surround(tokens, |tokens| {
            self.inputs.to_tokens(tokens);
            if let Some(variadic) = &self.variadic {
                if !self.inputs.empty_or_trailing() {
                    let span = variadic.dots.spans[0];
                    Token![,](span).to_tokens(tokens);
                }
                variadic.to_tokens(tokens);
            }
        });
        self.output.to_tokens(tokens);
    }
}

/// An argument for a [`FnPtr`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FnPtrArg {
    pub attrs: Vec<Attribute>,
    pub name: Option<(Ident, Token![:])>,
    pub ty: Type,
}

impl FnPtrArg {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, arg: BareFnArg) -> Result<Self> {
        trace!("parsing `FnPtrArg`");

        Ok(Self {
            attrs: arg.attrs,
            name: arg.name,
            ty: Type::parse(ctx, arg.ty)?,
        })
    }
}

impl ToTokens for FnPtrArg {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(self.attrs.outer());
        if let Some((name, colon)) = &self.name {
            name.to_tokens(tokens);
            colon.to_tokens(tokens);
        }
        self.ty.to_tokens(tokens);
    }
}

/// A function's return type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReturnType {
    /// Return type is not specified.
    ///
    /// Defaults to `()`.
    Default,
    /// A particular type is returned.
    Type(Token![->], Type),
}

impl ReturnType {
    #[instrument(skip_all)]
    pub(crate) fn parse(ctx: &Ctx, ty: syn::ReturnType) -> Result<Self> {
        trace!("parsing `ReturnType`");

        match ty {
            syn::ReturnType::Default => Ok(Self::Default),
            syn::ReturnType::Type(token, ty) => {
                let ty = Type::parse_ret_ty(ctx, *ty)?;
                Ok(Self::Type(token, ty))
            }
        }
    }

    /// Is this `Result<T, E>`?
    pub fn is_result(&self) -> bool {
        matches!(self, Self::Type(_, Type::Result(_)))
    }

    /// Is this `Result<T, E>` for `T` != `()`.
    pub fn is_non_unit_result(&self) -> bool {
        if let Self::Type(_, Type::Result(res)) = self {
            return !matches!(&res.ok, Type::Unit(_));
        }
        false
    }

    /// Returns the meaningful concrete result type so long as it
    /// is not `()`.
    ///
    /// For example:
    ///
    /// - `u64` -> `Some(u64)`
    /// - `Result<u64, E>` -> `Some(u64)`
    /// - `Result<(), E>` -> `None`
    /// - `Result<Result<u64, E1>, E2>` -> `Some(u64)`
    pub fn inner_type(&self) -> Option<&Type> {
        fn unwrap(ty: &Type) -> Option<&Type> {
            match ty {
                Type::Result(r) => match &r.ok {
                    Type::Unit(_) => None,
                    ty => Some(ty),
                },
                ty => Some(ty),
            }
        }
        match self {
            Self::Default => None,
            Self::Type(_, ty) => unwrap(ty),
        }
    }
}

impl ToTokens for ReturnType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Default => {}
            Self::Type(arrow, ty) => {
                arrow.to_tokens(tokens);
                ty.to_tokens(tokens);
            }
        }
    }
}

impl fmt::Display for ReturnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "(default)"),
            Self::Type(_, ty) => ty.fmt(f),
        }
    }
}

/// `MaybeUninit<T>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaybeUninit {
    pub ident: kw::MaybeUninit,
    pub lt_token: Token![<],
    /// The `T` in `MaybeUninit<T>`.
    pub elem: Type,
    pub gt_token: Token![>],
}

impl MaybeUninit {
    /// Creates a [`MaybeUninit`].
    pub(crate) fn new(elem: Type) -> Self {
        // TODO(eric): better span?
        let span = Span::call_site();
        Self {
            ident: kw::MaybeUninit(span),
            lt_token: Token![<](span),
            elem,
            gt_token: Token![>](span),
        }
    }

    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `MaybeUninit`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 1 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `MaybeUninit` has one generic argument",
            ));
        }
        let Some(arg) = args.args.pop() else {
            return Err(Error::new_spanned(&args, "BUG: should have one argument"));
        };
        let GenericArgument::Type(ty) = arg.into_value() else {
            return Err(Error::new_spanned(&args, ""));
        };
        Ok(Self {
            ident: kw::MaybeUninit(ident.span()),
            lt_token: args.lt_token,
            elem: Type::parse(ctx, ty)?,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "MaybeUninit<*>")
            || type_path_matches(ty, "::core::mem::MaybeUninit<*>")
            || type_path_matches(ty, "::core::mem::MaybeUninit<*>")
    }
}

impl ToTokens for MaybeUninit {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(::core::mem::MaybeUninit));
        self.lt_token.to_tokens(tokens);
        self.elem.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

/// Some other named type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Named {
    pub qself: Option<QSelf>,
    pub path: Path,
}

impl Named {
    #[instrument(skip_all)]
    pub(crate) fn parse(ctx: &Ctx, path: TypePath) -> Result<Self> {
        trace!("parsing `Named`");

        let qself = if let Some(v) = path.qself {
            Some(QSelf {
                lt_token: v.lt_token,
                ty: Box::new(Type::parse(ctx, *v.ty)?),
                position: v.position,
                as_token: v.as_token,
                gt_token: v.gt_token,
            })
        } else {
            None
        };

        Ok(Self {
            qself,
            path: path.path,
        })
    }

    /// Returns `_`.
    pub(crate) fn unknown() -> Self {
        Self {
            qself: None,
            path: format_ident!("_").into(),
        }
    }
}

impl ToTokens for Named {
    #[allow(clippy::arithmetic_side_effects)]
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Some(qself) = &self.qself else {
            self.path.to_tokens(tokens);
            return;
        };
        qself.lt_token.to_tokens(tokens);
        qself.ty.to_tokens(tokens);

        let pos = cmp::min(qself.position, self.path.segments.len());
        let mut segments = self.path.segments.pairs();
        if pos > 0 {
            TokensOrDefault(&qself.as_token).to_tokens(tokens);
            self.path.leading_colon.to_tokens(tokens);
            for (i, segment) in segments.by_ref().take(pos).enumerate() {
                segment.value().to_tokens(tokens);
                if i + 1 == pos {
                    qself.gt_token.to_tokens(tokens);
                }
                segment.punct().to_tokens(tokens);
            }
        } else {
            qself.gt_token.to_tokens(tokens);
            self.path.leading_colon.to_tokens(tokens);
        }
        for segment in segments {
            segment.to_tokens(tokens);
            segment.punct().to_tokens(tokens);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QSelf {
    pub lt_token: Token![<],
    pub ty: Box<Type>,
    pub position: usize,
    pub as_token: Option<Token![as]>,
    pub gt_token: Token![>],
}

/// `Option<T>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Opt {
    pub ident: kw::Option,
    pub lt_token: Token![<],
    /// The `T` in `Option<T>`.
    pub elem: Type,
    pub gt_token: Token![>],
}

impl Opt {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `Opt`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 1 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `Option` has one generic argument",
            ));
        }
        let Some(arg) = args.args.pop() else {
            return Err(Error::new_spanned(&args, "BUG: should have one argument"));
        };
        let GenericArgument::Type(ty) = arg.into_value() else {
            return Err(Error::new_spanned(
                &args,
                "BUG: expected generic type argument",
            ));
        };
        Ok(Self {
            ident: kw::Option(ident.span()),
            lt_token: args.lt_token,
            elem: Type::parse_opt(ctx, ty)?,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "Option<*>")
            || type_path_matches(ty, "::core::option::Option<*>")
            || type_path_matches(ty, "::core::option::Option<*>")
    }
}

impl ToTokens for Opt {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(::core::option::Option));
        self.lt_token.to_tokens(tokens);
        self.elem.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

/// `OwnedPtr<T>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedPtr {
    pub ident: kw::OwnedPtr,
    pub lt_token: Token![<],
    /// The `T` in `OwnedPtr<T>`.
    pub elem: Type,
    pub gt_token: Token![>],
}

impl OwnedPtr {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `Opt`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 1 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `OwnedPtr` has one generic argument",
            ));
        }
        let Some(arg) = args.args.pop() else {
            return Err(Error::new_spanned(&args, "BUG: should have one argument"));
        };
        let GenericArgument::Type(ty) = arg.into_value() else {
            return Err(Error::new_spanned(&args, ""));
        };
        Ok(Self {
            ident: kw::OwnedPtr(ident.span()),
            lt_token: args.lt_token,
            elem: Type::parse(ctx, ty)?,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "OwnedPtr<*>") || type_path_matches(ty, "__capi::safe::OwnedPtr<*>")
    }
}

impl ToTokens for OwnedPtr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(__capi::safe::OwnedPtr));
        self.lt_token.to_tokens(tokens);
        self.elem.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

/// Either `*const T` or `*mut T`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ptr {
    pub star_token: Token![*],
    pub const_token: Option<Token![const]>,
    pub mutability: Option<Token![mut]>,
    /// The `T` in `*const T`.
    pub elem: Type,
}

impl Ptr {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, ptr: syn::TypePtr) -> Result<Self> {
        Ok(Self {
            star_token: ptr.star_token,
            const_token: ptr.const_token,
            mutability: ptr.mutability,
            elem: Type::parse(ctx, *ptr.elem)?,
        })
    }
}

impl ToTokens for Ptr {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.star_token.to_tokens(tokens);
        self.const_token.to_tokens(tokens);
        self.mutability.to_tokens(tokens);
        self.elem.to_tokens(tokens);
    }
}

/// Either `&T` or `&mut T`, but `T` cannot be `[U]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ref {
    pub and_token: Token![&],
    pub lifetime: Option<Lifetime>,
    pub mutability: Option<Token![mut]>,
    /// The `T` in `&T`.
    pub elem: Type,
}

impl Ref {
    pub(crate) fn new_mut(elem: Type) -> Self {
        let span = Span::call_site();
        Self {
            and_token: Token![&](span),
            lifetime: None,
            mutability: Some(Token![mut](span)),
            elem,
        }
    }

    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, xref: syn::TypeReference) -> Result<Self> {
        Ok(Self {
            and_token: xref.and_token,
            lifetime: xref.lifetime,
            mutability: xref.mutability,
            elem: Type::parse(ctx, *xref.elem)?,
        })
    }
}

impl ToTokens for Ref {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.and_token.to_tokens(tokens);
        self.lifetime.to_tokens(tokens);
        self.mutability.to_tokens(tokens);
        self.elem.to_tokens(tokens);
    }
}

/// `Result<T, E>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResultType {
    pub ident: kw::Result,
    pub lt_token: Token![<],
    pub ok: Type,
    pub comma: Token![,],
    pub err: Type,
    pub gt_token: Token![>],
}

impl ResultType {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `ResultType`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 2 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `Result` has two generic arguments",
            ));
        }

        let err = {
            let Some(arg) = args.args.pop() else {
                return Err(Error::new_spanned(&args, "BUG: should have an argument"));
            };
            let GenericArgument::Type(ty) = arg.into_value() else {
                return Err(Error::new_spanned(
                    &args,
                    "BUG: expected generic type argument",
                ));
            };
            Type::parse(ctx, ty)?
        };

        let ok = {
            let Some(arg) = args.args.pop() else {
                return Err(Error::new_spanned(&args, "BUG: should have an argument"));
            };
            let GenericArgument::Type(ty) = arg.into_value() else {
                return Err(Error::new_spanned(
                    &args,
                    "BUG: expected generic type argument",
                ));
            };
            Type::parse_res_ok(ctx, ty)?
        };

        Ok(Self {
            ident: kw::Result(ident.span()),
            lt_token: args.lt_token,
            ok,
            comma: Token![,](args.span()),
            err,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "Result<*,*>")
            || type_path_matches(ty, "::core::result::Result<*,*>")
            || type_path_matches(ty, "::core::result::Result<*,*>")
    }

    // Basically like [`Result::map`].
    pub fn map<F>(mut self, f: F) -> Self
    where
        F: FnOnce(Type) -> Type,
    {
        self.ok = f(self.ok);
        self
    }
}

impl ToTokens for ResultType {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(::core::result::Result));
        self.lt_token.to_tokens(tokens);
        self.ok.to_tokens(tokens);
        self.comma.to_tokens(tokens);
        self.err.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

/// `Safe<T>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Safe {
    pub ident: kw::Safe,
    pub lt_token: Token![<],
    /// The `T` in `Safe<T>`.
    pub elem: Type,
    pub gt_token: Token![>],
}

impl Safe {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `Safe`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 1 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `Safe` has one generic argument",
            ));
        }
        let Some(arg) = args.args.pop() else {
            return Err(Error::new_spanned(&args, "BUG: should have one argument"));
        };
        let GenericArgument::Type(ty) = arg.into_value() else {
            return Err(Error::new_spanned(
                &args,
                "BUG: expected generic type argument",
            ));
        };
        Ok(Self {
            ident: kw::Safe(ident.span()),
            lt_token: args.lt_token,
            elem: Type::parse(ctx, ty)?,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "Safe<*>") || type_path_matches(ty, "__capi::safe::Safe<*>")
    }
}

impl ToTokens for Safe {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(__capi::safe::Safe));
        self.lt_token.to_tokens(tokens);
        self.elem.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

/// `u8`, `f32`, etc.
#[derive(Clone, Debug)]
pub struct Scalar {
    pub ty: ScalarType,
    pub span: Span,
}

impl Scalar {
    fn parse(_ctx: &Ctx, ident: &Ident) -> Result<Self> {
        ident
            .to_string()
            .parse()
            .map(|ty| Self {
                ty,
                span: ident.span(),
            })
            .map_err(|_| Error::new_spanned(ident, "unknown scalar"))
    }

    /// Creates a scalar with a particular span.
    pub fn with_span(ty: ScalarType, span: Span) -> Self {
        Self { ty, span }
    }
}

impl AsRef<str> for Scalar {
    fn as_ref(&self) -> &str {
        self.ty.into()
    }
}

impl Eq for Scalar {}
impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty
    }
}

impl PartialEq<Scalar> for &Ident {
    fn eq(&self, scalar: &Scalar) -> bool {
        PartialEq::eq(*self, scalar)
    }
}

impl ToTokens for Scalar {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let ident = format_ident!("{}", self.ty.as_ref(), span = self.span);
        let path: Path = match self.ty {
            ScalarType::CChar | ScalarType::CVoid => {
                parse_quote_spanned! {self.span=>
                    ::core::ffi::#ident
                }
            }
            _ => {
                parse_quote_spanned! {self.span=>
                    ::core::primitive::#ident
                }
            }
        };
        path.to_tokens(tokens);
    }
}

/// `u8`, `f32`, etc.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    strum::AsRefStr,
    strum::Display,
    strum::EnumString,
    strum::IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
pub enum ScalarType {
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
    F32,
    F64,
    CChar,
    CVoid,
}

/// `[T]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Slice {
    pub bracket_token: Bracket,
    /// The `T` in `&[T]`.
    pub elem: Type,
}

impl Slice {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, s: TypeSlice) -> Result<Self> {
        trace!("parsing `Slice`");

        Ok(Self {
            bracket_token: s.bracket_token,
            elem: Type::parse(ctx, *s.elem)?,
        })
    }
}

impl ToTokens for Slice {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.bracket_token.surround(tokens, |tokens| {
            self.elem.to_tokens(tokens);
        });
    }
}

/// `str`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Str {
    pub ident: kw::str,
}

impl Str {
    #[instrument(skip_all)]
    fn parse(_ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `Str`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }
        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        if !matches!(arguments, PathArguments::None) {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment must not have arguments",
            ));
        }

        Ok(Self {
            ident: kw::str(ident.span()),
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "str") || type_path_matches(ty, "__capi::internal::primitive::str")
    }
}

impl ToTokens for Str {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(::core::primitive::str));
    }
}

/// `()`
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Unit {
    pub paren_token: Paren,
}

impl Unit {
    #[instrument(skip_all)]
    pub(crate) fn parse(_ctx: &Ctx, tuple: syn::TypeTuple) -> Result<Self> {
        trace!("parsing `Unit`");

        if tuple.elems.is_empty() {
            Ok(Self {
                paren_token: tuple.paren_token,
            })
        } else {
            Err(Error::new_spanned(&tuple, "only `()` is supported"))
        }
    }

    /// Creates a unit with a span.
    pub fn with_span(span: Span) -> Self {
        let span = {
            let mut group = Group::new(Delimiter::None, TokenStream::new());
            group.set_span(span);
            group.delim_span()
        };
        Self {
            paren_token: Paren { span },
        }
    }
}

impl ToTokens for Unit {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        self.paren_token.surround(tokens, |_| {});
    }
}

/// `Writer<T>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Writer {
    pub ident: kw::Writer,
    pub lt_token: Token![<],
    /// The `T` in `Writer<T>`.
    pub elem: Type,
    pub gt_token: Token![>],
}

impl Writer {
    #[instrument(skip_all)]
    fn parse(ctx: &Ctx, mut ty: TypePath) -> Result<Self> {
        trace!("parsing `Writer`");

        if !Self::matches(&ty) {
            return Err(Error::new_spanned(
                &ty,
                format!("BUG: wrong path: {}", Trimmed(&ty)),
            ));
        }

        let PathSegment { ident, arguments } = match ty.path.segments.pop() {
            Some(v) => v.into_value(),
            None => return Err(Error::new_spanned(ty, "BUG: unable to pop last segment")),
        };
        let PathArguments::AngleBracketed(mut args) = arguments else {
            return Err(Error::new_spanned(
                arguments,
                "BUG: last segment not generic",
            ));
        };
        if args.args.len() != 1 {
            return Err(Error::new_spanned(
                &args,
                "BUG: `Writer` has one generic argument",
            ));
        }
        let Some(arg) = args.args.pop() else {
            return Err(Error::new_spanned(&args, "BUG: should have one argument"));
        };
        let GenericArgument::Type(ty) = arg.into_value() else {
            return Err(Error::new_spanned(
                &args,
                "BUG: expected generic type argument",
            ));
        };
        Ok(Self {
            ident: kw::Writer(ident.span()),
            lt_token: args.lt_token,
            elem: Type::parse(ctx, ty)?,
            gt_token: args.gt_token,
        })
    }

    fn matches(ty: &TypePath) -> bool {
        type_path_matches(ty, "Writer<*>") || type_path_matches(ty, "__capi::safe::Writer<*>")
    }
}

impl ToTokens for Writer {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.extend(quote!(__capi::safe::Writer));
        self.lt_token.to_tokens(tokens);
        self.elem.to_tokens(tokens);
        self.gt_token.to_tokens(tokens);
    }
}

#[cfg(test)]
mod tests {
    use syn::parse_quote;

    use super::*;

    macro_rules! scalar {
        ($ty:ident) => {
            Type::Scalar(Scalar {
                ty: ScalarType::$ty,
                span: Span::call_site(),
            })
        };
    }
    macro_rules! maybe_uninit {
        ($ty:expr) => {{
            let span = Span::call_site();
            Type::MaybeUninit(Box::new(MaybeUninit {
                ident: kw::MaybeUninit(span),
                lt_token: Token![<](span),
                elem: $ty.into(),
                gt_token: Token![>](span),
            }))
        }};
    }
    #[allow(unused_macros)] // TODO
    macro_rules! option {
        ($ty:expr) => {{
            let span = Span::call_site();
            Type::Option(Opt {
                ident: kw::Option(span),
                lt_token: Token![<](span),
                elem: $ty.into(),
                gt_token: Token![>](span),
            })
        }};
    }
    macro_rules! result {
        ($ok:expr, $err:expr) => {{
            let span = Span::call_site();
            Type::Result(Box::new(ResultType {
                ident: kw::Result(span),
                lt_token: Token![<](span),
                ok: $ok.into(),
                comma: Token![,](span),
                err: $err.into(),
                gt_token: Token![>](span),
            }))
        }};
    }
    macro_rules! unit {
        () => {{
            Type::Unit(Unit {
                paren_token: Paren::default(),
            })
        }};
    }

    /// Test [`parse_type_path`].
    // TODO(eric): negative tests
    // TODO(eric): `Option` tests.
    #[test]
    fn test_parse_type_path() {
        #[allow(non_snake_case)]
        fn E() -> Named {
            Named {
                qself: None,
                path: parse_quote!(E),
            }
        }
        // TODO(eric): generate these test cases with macros.
        let tests: Vec<(TypePath, Type)> = vec![
            (parse_quote!(u8), scalar!(U8)),
            (parse_quote!(u16), scalar!(U16)),
            (parse_quote!(u32), scalar!(U32)),
            (parse_quote!(u64), scalar!(U64)),
            (parse_quote!(u128), scalar!(U128)),
            (parse_quote!(usize), scalar!(Usize)),
            (parse_quote!(i8), scalar!(I8)),
            (parse_quote!(i16), scalar!(I16)),
            (parse_quote!(i32), scalar!(I32)),
            (parse_quote!(i64), scalar!(I64)),
            (parse_quote!(i128), scalar!(I128)),
            (parse_quote!(isize), scalar!(Isize)),
            (parse_quote!(MaybeUninit<u8>), maybe_uninit!(scalar!(U8))),
            (parse_quote!(MaybeUninit<u8>), maybe_uninit!(scalar!(U8))),
            (parse_quote!(MaybeUninit<u16>), maybe_uninit!(scalar!(U16))),
            (parse_quote!(MaybeUninit<u32>), maybe_uninit!(scalar!(U32))),
            (parse_quote!(MaybeUninit<u64>), maybe_uninit!(scalar!(U64))),
            (
                parse_quote!(MaybeUninit<u128>),
                maybe_uninit!(scalar!(U128)),
            ),
            (
                parse_quote!(MaybeUninit<usize>),
                maybe_uninit!(scalar!(Usize)),
            ),
            (parse_quote!(MaybeUninit<i8>), maybe_uninit!(scalar!(I8))),
            (parse_quote!(MaybeUninit<i16>), maybe_uninit!(scalar!(I16))),
            (parse_quote!(MaybeUninit<i32>), maybe_uninit!(scalar!(I32))),
            (parse_quote!(MaybeUninit<i64>), maybe_uninit!(scalar!(I64))),
            (
                parse_quote!(MaybeUninit<i128>),
                maybe_uninit!(scalar!(I128)),
            ),
            (
                parse_quote!(MaybeUninit<isize>),
                maybe_uninit!(scalar!(Isize)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u8>),
                maybe_uninit!(scalar!(U8)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u8>),
                maybe_uninit!(scalar!(U8)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u16>),
                maybe_uninit!(scalar!(U16)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u32>),
                maybe_uninit!(scalar!(U32)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u64>),
                maybe_uninit!(scalar!(U64)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<u128>),
                maybe_uninit!(scalar!(U128)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<usize>),
                maybe_uninit!(scalar!(Usize)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<i8>),
                maybe_uninit!(scalar!(I8)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<i16>),
                maybe_uninit!(scalar!(I16)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<i32>),
                maybe_uninit!(scalar!(I32)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<i64>),
                maybe_uninit!(scalar!(I64)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<i128>),
                maybe_uninit!(scalar!(I128)),
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<isize>),
                maybe_uninit!(scalar!(Isize)),
            ),
            (parse_quote!(Result<(), E>), result!(unit!(), E())),
            (parse_quote!(Result<u8, E>), result!(scalar!(U8), E())),
            (parse_quote!(Result<u8, E>), result!(scalar!(U8), E())),
            (parse_quote!(Result<u16, E>), result!(scalar!(U16), E())),
            (parse_quote!(Result<u32, E>), result!(scalar!(U32), E())),
            (parse_quote!(Result<u64, E>), result!(scalar!(U64), E())),
            (parse_quote!(Result<u128, E>), result!(scalar!(U128), E())),
            (parse_quote!(Result<usize, E>), result!(scalar!(Usize), E())),
            (parse_quote!(Result<i8, E>), result!(scalar!(I8), E())),
            (parse_quote!(Result<i16, E>), result!(scalar!(I16), E())),
            (parse_quote!(Result<i32, E>), result!(scalar!(I32), E())),
            (parse_quote!(Result<i64, E>), result!(scalar!(I64), E())),
            (parse_quote!(Result<i128, E>), result!(scalar!(I128), E())),
            (parse_quote!(Result<isize, E>), result!(scalar!(Isize), E())),
        ];
        let mut ctx = Ctx {
            capi: parse_quote!(aranya_capi_core),
            conv: parse_quote!(aranya_capi_core::internal::conv),
            util: parse_quote!(aranya_capi_core::internal::util),
            error: parse_quote!(aranya_capi_core::internal::error),
            err_ty: parse_quote!(Error),
            ext_err_ty: parse_quote!(ExtError),
            fn_prefix: format_ident!("fn_prefix"),
            ty_prefix: format_ident!("ty_prefix"),
            errs: Default::default(),
            defs: parse_quote!(self),
            hidden: format_ident!("__hidden"),
            imports: format_ident!("__imports"),
        };
        for (i, (ty, want)) in tests.into_iter().enumerate() {
            #[allow(clippy::assertions_on_constants)]
            match parse_type_path(&ctx, ty) {
                Ok(got) => {
                    assert_eq!(got, want, "#{i}");
                    ctx.propagate().unwrap();
                }
                Err(err) => {
                    assert!(false, "#{i}: {err}");
                    ctx.errs.borrow_mut().clear();
                }
            }
        }
    }

    /// Test [`type_path_matches`].
    #[test]
    fn test_type_path_matches() {
        let tests: &[(TypePath, &str, bool)] = &[
            (parse_quote!(core), "core", true),
            (parse_quote!(::core), "::core", true),
            (parse_quote!(::core::mem), "::core::mem", true),
            (
                parse_quote!(::core::primitive::u8),
                "::core::primitive::u8",
                true,
            ),
            (
                parse_quote!(::core::mem::MaybeUninit<T>),
                "::core::mem::MaybeUninit<*>",
                true,
            ),
            (
                parse_quote!(::a::b::c::Foo<T,G>),
                "::a::b::c::Foo<*,*>",
                true,
            ),
            (parse_quote!(::core::mem), "core::mem", false),
            (parse_quote!(::core::foo), "::core::mem", false),
            (parse_quote!(::core::mem::MaybeUninit), "::core::mem", false),
            (
                parse_quote!(::a::b::c::Foo<T>),
                "::a::b::c::Foo<*,*>",
                false,
            ),
            (
                parse_quote!(::a::b::c::Foo<T,G>),
                "::a::b::c::Foo<*>",
                false,
            ),
        ];
        for (i, (ty, s, want)) in tests.iter().enumerate() {
            let got = type_path_matches(ty, s);
            assert_eq!(got, *want, "#{i}");
        }
    }
}
