use std::{collections::HashMap, iter::Peekable, mem, slice};

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens, TokenStreamExt};
use syn::{
    parse_quote, parse_quote_spanned,
    punctuated::{Pair, Punctuated},
    spanned::Spanned,
    Attribute, Expr, Ident, ItemConst, ItemImpl, ItemStruct, Path, Result, Token,
};
use tracing::{debug, instrument, trace};

use super::{Ast, IdentMap};
use crate::{
    ctx::Ctx,
    syntax::{
        attrs::{NoExtError, Repr},
        trace::Instrument,
        Alias, AttrsExt, Builds, DeriveTrait, Enum, FfiFn, Fields, FnArg, Lifetimes, MaybeUninit,
        Node, Ptr, Ref, ReturnType, RustFn, Scalar, ScalarType, Struct, Type, Union, Unit,
    },
    util::{parse_doc, IdentExt, PathExt},
};

impl Ast {
    /// An AST pass that expands nodes.
    pub(super) fn expand_nodes(&mut self, ctx: &mut Ctx) {
        for node in mem::take(&mut self.nodes) {
            if let Err(err) = self.expand_node(ctx, node) {
                ctx.push(err);
            }
        }
    }

    fn expand_node(&mut self, ctx: &Ctx, node: Node) -> Result<()> {
        match node {
            Node::Alias(a) => self.expand_alias(ctx, a)?,
            Node::Enum(e) => self.expand_enum(ctx, e)?,
            Node::RustFn(f) => self.expand_fn(ctx, f)?,
            Node::FfiFn(f) => {
                // `FfiFn`s are generated during the expansion
                // AST pass.
                ctx.error(f, "bug: unexpected `FfiFn` in AST expansion pass")
            }
            n @ Node::Other(_) => self.add_node(n),
            Node::Struct(s) => self.expand_struct(ctx, s)?,
            Node::Union(u) => self.expand_union(ctx, u),
        }
        Ok(())
    }

    /// Attempts to add a type alias to `ast`.
    #[instrument(skip_all, fields(ident = %alias.ident))]
    fn expand_alias(&mut self, ctx: &Ctx, alias: Alias) -> Result<()> {
        if alias.repr().is_some() {
            ctx.error(&alias, "type alias cannot have `#[repr(...)]`");
        }

        let underlying = ctx.defs.join(alias.ident.clone());
        let Alias {
            doc,
            derives,
            ext_error,
            opaque,
            builds,
            attrs,
            vis,
            type_token,
            ident,
            semi_token,
            ..
        } = alias;
        let strukt = Struct {
            doc,
            derives,
            repr: Repr::Transparent,
            ext_error,
            opaque,
            builds,
            attrs,
            vis,
            struct_token: Token![struct](type_token.span()),
            ident,
            fields: Fields::parse(
                ctx,
                syn::Fields::Unnamed(parse_quote! {
                    (#underlying)
                }),
            )?,
            semi_token: Some(semi_token),
        };
        self.expand_struct(ctx, strukt)?;

        Ok(())
    }

    /// Attempts to add an `enum` to `ast`.
    #[instrument(skip_all, fields(ident = %enum_.ident))]
    fn expand_enum(&mut self, ctx: &Ctx, mut enum_: Enum) -> Result<()> {
        let span = enum_.enum_token.span();
        enum_.attrs.push(parse_quote_spanned! {span=>
            #[must_use]
        });

        let underlying = ctx.defs.join(enum_.ident.clone());
        enum_.ident = enum_.ident.with_prefix(&ctx.ty_prefix);
        let name = &enum_.ident;
        let repr = &enum_.to_repr();

        let is_error = enum_.derives.contains(DeriveTrait::ErrorCode);

        // Extra impls, etc.
        let extra = {
            let mut items = Vec::<ItemImpl>::new();
            let capi = &ctx.capi;

            fn cfg_attrs(attrs: &[Attribute]) -> impl Iterator<Item = &Attribute> {
                attrs
                    .iter()
                    .filter(|a| a.path().is_ident("cfg") || a.path().is_ident("cfg_attr"))
            }
            fn mangle(ident: &Ident) -> Ident {
                format_ident!(
                    "__ENUM_{}",
                    ident.to_screaming_snake_case(),
                    span = ident.span()
                )
            }

            if !is_error {
                items.push({
                    let consts = enum_.variants.iter().map(|v| {
                        let cfg = cfg_attrs(&v.attrs);
                        let ident = &v.ident;
                        quote! {
                            #[cfg(not(cbindgen))]
                            #(#cfg)*
                            const #ident: Self = Self(#underlying::#ident as _);
                        }
                    });
                    parse_quote! {
                        impl #name {
                            #(#consts)*
                        }
                    }
                });
            }

            // Consts for `capi::types::Enum`.
            //
            // These are associated consts (instead of being
            // local to the `Enum` impl) so we can use `Self`.
            // (Our rewrite rules aren't smart enough to handle,
            // e.g., `MyEnum::Foo`.)
            items.push({
                let consts = enum_.variants.iter().map(|v| {
                    let cfg = cfg_attrs(&v.attrs);
                    let ident = &v.ident;
                    let mangled = mangle(ident);
                    quote! {
                        #(#cfg)*
                        const #mangled: <Self as #capi::types::Enum>::Repr =
                            #underlying::#ident as <Self as #capi::types::Enum>::Repr;
                    }
                });
                parse_quote! {
                    impl #name {
                        #(#consts)*
                    }
                }
            });

            // Implement `capi::types::Enum`.
            items.push({
                let cases = enum_.variants.iter().map(|v| {
                    let cfg = cfg_attrs(&v.attrs);
                    let ident = &v.ident;
                    let mangled = mangle(ident);
                    quote! {
                        #(#cfg)*
                        Self::#mangled => Self::#ident
                    }
                });
                parse_quote! {
                    #[automatically_derived]
                    impl #capi::types::Enum for #name {
                        type Repr = #repr;

                        fn try_from_repr(repr: Self::Repr) -> ::core::option::Option<Self> {
                            let v = match repr {
                                #(#cases),*,
                                _ => return ::core::option::Option::None
                            };
                            ::core::option::Option::Some(v)
                        }
                    }
                }
            });

            // To/from underlying impls.
            items.push({
                let from_cases = enum_.variants.iter().map(|v| {
                    let cfg = cfg_attrs(&v.attrs);
                    let ident = &v.ident;
                    quote! {
                        #(#cfg)*
                        #underlying::#ident => Self::#ident
                    }
                });

                parse_quote! {
                    impl #name {
                        /// Converts the underlying type to
                        /// `Self`.
                        const fn from_underlying(other: #underlying) -> Self {
                            // NB: Since we only support
                            // unit-only enums, this should
                            // compile down into nothing.
                            match other {
                                #(#from_cases),*,
                            }
                        }
                    }
                }
            });

            items.push(parse_quote! {
                /// SAFETY: The type is a unit-only enumeration
                /// with a `#[repr(...)]`, and we check for
                /// invalid representations, so it is FFI safe.
                #[automatically_derived]
                unsafe impl #capi::types::Input for #name {}
            });

            items.push(parse_quote! {
                /// SAFETY: The type is a unit-only enumeration
                /// with a `#[repr(...)]`, and we check for
                /// invalid representations, so it is FFI safe.
                #[automatically_derived]
                unsafe impl #capi::types::ByValue for #name {}
            });

            items.push(parse_quote! {
                /// SAFETY: The type is a unit-only enumeration
                /// with a `#[repr(...)]`, and we check for
                /// invalid representations, so it is FFI safe.
                #[automatically_derived]
                unsafe impl #capi::types::ByMutPtr for #name {}
            });

            // Forward `From` impls needed to implement
            // `ErrorCode`.
            items.push(parse_quote! {
                #[automatically_derived]
                impl<T> ::core::convert::From<T> for #name
                where
                    #underlying: ::core::convert::From<T>,
                {
                    fn from(v: T) -> Self {
                        let other: #underlying = <#underlying as ::core::convert::From<T>>::from(v);
                        Self::from_underlying(other)
                    }
                }
            });

            if !is_error {
                items.push({
                    let cases = enum_.variants.iter().map(|v| {
                        let cfg = cfg_attrs(&v.attrs);
                        let ident = &v.ident;
                        quote! {
                            #(#cfg)*
                            #name::#ident => ::core::option::Option::Some(Self::#ident),
                        }
                    });
                    parse_quote! {
                        #[automatically_derived]
                        impl #capi::types::Enum for #underlying {
                            type Repr = #name;
                            fn try_from_repr(repr: #name) -> Option<Self> {
                                match repr {
                                    #(#cases)*
                                    _ => ::core::option::Option::None,
                                }
                            }
                        }
                    }
                });
            }

            items
        };
        self.add_hidden_node::<ItemConst>(parse_quote! {
            #[doc = ::core::concat!("Hidden impls, etc. for [`", ::core::stringify!(#name), "`].")]
            const _: () = { #(#extra)* };
        });

        // TODO: Migrate error type handling to new format.
        if is_error {
            self.add_node(enum_);
        } else {
            // TODO: Derives proper?
            let wrapper: ItemStruct = parse_quote! {
                #[cfg(not(cbindgen))]
                #[repr(transparent)]
                #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
                pub struct #name(#repr);
            };
            self.add_node::<ItemStruct>(wrapper);

            enum_.attrs.insert(0, parse_quote! { #[cfg(cbindgen)] });
            self.add_node(enum_);
        }

        Ok(())
    }

    #[instrument(skip_all, fields(ident = %strukt.ident))]
    fn expand_struct(&mut self, ctx: &Ctx, mut strukt: Struct) -> Result<()> {
        let span = strukt.struct_token.span();

        let old = strukt.ident.clone();
        let underlying = ctx.defs.join(old.clone());
        strukt.ident = strukt.ident.with_prefix(&ctx.ty_prefix);
        let name = &strukt.ident;

        // Generate a constructor.
        if strukt.derives.contains(DeriveTrait::Init) {
            self.add_init_constructor(
                ctx,
                &strukt.ident,
                &old,
                &Lifetimes::default(),
                if strukt.ext_error.is_some() {
                    Some(NoExtError::with_span(span))
                } else {
                    None
                },
            )?;
        }

        if let Some(Builds { ty }) = &mut strukt.builds {
            *ty = ty.with_prefix(&ctx.ty_prefix);
            self.add_build_constructor(
                ctx,
                &strukt.ident,
                &old,
                ty,
                &Lifetimes::default(),
                if strukt.ext_error.is_some() {
                    Some(NoExtError::with_span(span))
                } else {
                    None
                },
            )?;
        }

        // Generate a destructor.
        if strukt.derives.contains(DeriveTrait::Cleanup) {
            self.add_destructor(
                ctx,
                &strukt.ident,
                &old,
                &Lifetimes::default(),
                if strukt.ext_error.is_some() {
                    Some(NoExtError::with_span(span))
                } else {
                    None
                },
            )?;
        }

        // TODO
        // fn add_assert(capi: &Path, tokens: &mut TokenStream, ty: &Type) {
        //     match ty {
        //         Type::FnPtr(f) => {
        //             for arg in &f.inputs {
        //                 add_assert(capi, tokens, &arg.ty)
        //             }
        //         }
        //         // Check `Option` specifically because
        //         // it's used to wrap function pointers.
        //         Type::Option(opt) => add_assert(capi, tokens, &opt.elem),
        //         ty => tokens.extend(quote! {
        //             const _: () = #capi::types::const_assert_valid_input_ty::<#ty>();
        //         }),
        //     }
        // }
        // if !strukt.opaque.is_some() {
        //     for field in &strukt.fields {
        //         // TODO
        //         if false {
        //             add_assert(capi, &mut tokens, &field.ty);
        //         }
        //     }
        // }

        if strukt.opaque.is_none() {
            // Include the full struct definition so that
            // `cbindgen` displays the struct fields.
            self.add_node({
                let mut s = strukt.clone();
                s.attrs.push(parse_quote_spanned! {span=>
                    #[cfg(cbindgen)]
                });
                s
            });
            strukt.attrs.push(parse_quote_spanned! {span=>
                #[cfg(not(cbindgen))]
            });
        }

        self.add_hidden_node(ffi_wrapper(ctx, &strukt, &underlying));
        let ty = Box::new(Type::named(parse_quote! {
            self::__hidden::#name
        }));

        self.add_node({
            let Struct {
                doc,
                derives,
                ext_error,
                opaque,
                builds,
                attrs,
                vis,
                struct_token,
                ident,
                semi_token,
                ..
            } = strukt;
            Alias {
                doc,
                derives,
                ext_error,
                opaque,
                builds,
                attrs,
                vis,
                type_token: Token![type](struct_token.span()),
                ident,
                lifetimes: Lifetimes::none(),
                eq_token: Token![=](span),
                ty,
                semi_token: semi_token.unwrap_or_else(|| Token![;](span)),
            }
        });

        Ok(())
    }

    #[instrument(skip_all, fields(ident = %union_.ident))]
    fn expand_union(&mut self, ctx: &Ctx, mut union_: Union) {
        let span = union_.span();
        union_.attrs.push(parse_quote_spanned! {span=>
            #[repr(C)]
        });
        union_.attrs.push(parse_quote_spanned! {span=>
            #[must_use]
        });
        union_.ident = union_.ident.with_prefix(&ctx.ty_prefix);
        self.add_node(union_);
    }
}

// `expand_fn` and all its associated functions.
impl Ast {
    /// Attempts to add a freestanding `fn` to `ast`.
    #[instrument(skip_all, fields(ident = %f.sig.ident, generated = f.generated.is_some()))]
    fn expand_fn(&mut self, ctx: &Ctx, mut f: RustFn) -> Result<()> {
        // TODO(eric): Add better documentation.

        let capi = &ctx.capi;
        let error = &ctx.error;
        let err_ty = &ctx.err_ty;

        let doc = &f.doc;
        let ctype_attr = parse_quote!(#[deny(improper_ctypes_definitions)]);
        let attrs = &f
            .attrs
            .iter()
            .filter(|attr| {
                // TODO(eric): other attrs?
                attr.path().is_ident("cfg")
            })
            .chain(std::iter::once(&ctype_attr))
            .collect::<Vec<_>>();

        // Rewrite the inputs for the `extern "C"` functions and
        // the trampoline.
        let mut inputs = self.rewrite_inputs(ctx, f.sig.inputs.clone());

        // `f` is infallible if:
        //
        // 1. It does not accept ref arguments.
        // 2. It does not return `Result`.
        let f_is_infallible = inputs.are_infallible() && !f.sig.output.is_result();

        // Do we need to use an output parameter?
        let out_param = match (f_is_infallible, f.sig.output.inner_type()) {
            (false, Some(ty)) => Some(FnArg {
                attrs: Vec::new(),
                name: format_ident!("__output"),
                colon_token: Token![:](Span::call_site()),
                ty: {
                    let elem = Type::MaybeUninit(Box::new(MaybeUninit::new(ty.clone())));
                    Type::Ref(Box::new(Ref::new_mut(elem)))
                },
            }),
            _ => None,
        };
        if let Some(out) = &out_param {
            inputs.append(self.rewrite_inputs(ctx, [out.clone()]));
        }

        // Make sure the result type is FFI safe.
        match &mut f.sig.output {
            ReturnType::Default => {}
            ReturnType::Type(_, ty) => *ty = ffi_safe_ty(ty),
        }

        // Use the existing return type if the function is
        // infallible. Otherwise, return the API's error type.
        let ret = if f_is_infallible {
            f.sig.output.clone()
        } else {
            ReturnType::parse(ctx, parse_quote!(-> #err_ty))?
        };

        let unsafety = &f.sig.unsafety;

        // Generate the trampoline.
        let tramp = {
            // The underlying Rust function that we're invoking.
            let orig = if f.generated.is_some() {
                // We generated this function.
                syn::parse_str::<Path>("self")?.join(f.sig.ident.clone())
            } else {
                // We parsed this function.
                ctx.defs.join(f.sig.ident.clone())
            };
            debug!(orig = %quote!(#orig), "original function");

            let args = f.sig.inputs.iter().map(|arg| &arg.name);

            // The trampoline's return type.
            let ret = {
                // If we're using an output parameter then we
                // need to rewrite `Result<Result<T, E1>, E2>` to
                // `Result<Result<(), E1>, E2>`, etc.
                let ok = match &f.sig.output {
                    ReturnType::Default => quote!(()),
                    ReturnType::Type(_, Type::Result(res)) if out_param.is_some() => {
                        let res = res
                            .clone()
                            .map(|_| Type::Unit(Unit::with_span(f.sig.output.span())));
                        quote!(#res)
                    }
                    ReturnType::Type(_, ty) => {
                        if out_param.is_some() {
                            quote!(())
                        } else {
                            quote!(#ty)
                        }
                    }
                };
                if inputs.are_infallible() {
                    quote!(-> #ok)
                } else {
                    quote!(-> Result<#ok, #capi::InvalidArg<'static>>)
                }
            };

            let pattern = format_ident!("__pattern");
            let result = f
                .sig
                .output
                .inner_type()
                .and_then(|ty| {
                    if out_param.is_some() {
                        // Out params are just regular function
                        // parameters which are already cast.
                        None
                    } else {
                        cast_output_ty(ctx, ty, &pattern, &self.types, &self.idents)
                    }
                })
                .unwrap_or_else(|| quote!(#pattern.into()));

            let block = if f_is_infallible {
                // Output params are `*mut T`, which should make
                // `f` fallible.
                assert!(out_param.is_none());

                // Either `f` is infallible or the trampoline
                // doesn't need to perform any conversions, so
                // just return the result directly.
                quote!(#result)
            } else if let Some(out) = &out_param {
                // There is an output parameter.
                let name = &out.name;
                if f.sig.output.is_non_unit_result() {
                    // `f` returns `Result<T, E>`, so pull the
                    // value out of `Ok`.
                    quote! {
                        match #pattern {
                            // The underlying Rust function
                            // succeeded.
                            ::core::result::Result::Ok(#pattern) => {
                                ::core::mem::MaybeUninit::write(#name, #result);
                                ::core::result::Result::Ok(
                                    ::core::result::Result::Ok(())
                                )
                            }
                            // The underlying Rust function
                            // failed.
                            ::core::result::Result::Err(err) => {
                                ::core::result::Result::Ok(
                                    ::core::result::Result::Err(err)
                                )
                            }
                        }
                    }
                } else {
                    // `f` returns something else.
                    quote! {
                        ::core::mem::MaybeUninit::write(#name, #result);
                        ::core::result::Result::Ok(())
                    }
                }
            } else if !inputs.are_infallible() {
                // No output parameter, but the trampoline is
                // still fallible.
                quote! {
                    ::core::result::Result::Ok(#result)
                }
            } else {
                // No output parameter, but the trampoline is
                // infallible.
                quote!(#result)
            };

            let cfg = f.attrs.iter().filter(|a| a.path().is_ident("cfg"));

            let stmts = inputs.iter().filter_map(|input| {
                let name = &input.arg.name;
                if f.generated.is_some() {
                    // `f` is generated (e.g., a constructor), so
                    // we don't need to transmute any newtype
                    // args.
                    //
                    // Otherwise, we try to transmute (for
                    // example), `OsFoo` to `Foo`, but our
                    // generated fn actually expects `OsFoo`.
                    //
                    // Our generated fn can't accept `Foo`
                    // because that's in a separate module. We
                    // could refer to it using its full path
                    // (e.g., `other::module::Foo`), but then
                    // `expand_fn` we won't correctly rewrite
                    // `other::module::Foo` to `OsFoo`.
                    //
                    // Only a conversion, so we know the
                    // concrete type.
                    // TODO(eric): what if `conv` is `None`?
                    let ty = &input.ty;
                    let conv = &input.conv;
                    return Some(quote! {
                        let #name: #ty = #conv;
                    });
                }
                match (&input.conv, &input.newtype) {
                    (None, None) => None,
                    (Some(conv), None) => {
                        // Only a conversion, so we know the
                        // concrete type.
                        let ty = &input.ty;
                        Some(quote! {
                            let #name: #ty = #conv;
                        })
                    }
                    (None, Some(newtype)) => {
                        let ty = input.ty.generify();
                        Some(quote! {
                            #[allow(clippy::let_with_type_underscore)]
                            let #name: #ty = #newtype;
                        })
                    }
                    (Some(conv), Some(newtype)) => {
                        let ty = input.ty.generify();
                        // Rebind `#name` because the "try_*"
                        // macros stringify the identifier and
                        // pass it to `InvalidArg` so that
                        // callers know the name of the invalid
                        // argument.
                        Some(quote! {
                            #[allow(clippy::let_with_type_underscore)]
                            let #name: #ty = {
                                // TODO(eric): ordering?
                                let #name = #conv;
                                #newtype
                            };
                        })
                    }
                }
            });

            let name = f
                .sig
                .ident
                .with_prefix(&ctx.fn_prefix)
                .with_prefix("__tramp_");
            let f = parse_quote_spanned! {f.sig.span()=>
                #(#cfg)*
                #[#capi::generated]
                #[allow(clippy::unused_unit)]
                fn #name(#inputs) #ret {
                    #(#stmts)*

                    #[allow(clippy::blocks_in_conditions)]
                    #[allow(clippy::match_single_binding)]
                    #[allow(unused_braces)]
                    match #unsafety { #orig(#(#args),*) } {
                        #[allow(clippy::useless_conversion)]
                        #[allow(clippy::unit_arg)]
                        #pattern => { #block }
                    }
                }
            };
            RustFn::parse(ctx, f)?
        };

        // A C API function without an extended error parameter.
        let basic = {
            let name = &f.sig.ident.with_prefix(&ctx.fn_prefix);
            let args = inputs.args().map(|arg| {
                // Assert that each input type is allowed.
                check_valid_input_ty(ctx, arg)
            });
            let tracing = Instrument::from_inputs(capi, inputs.args());
            let tramp_fn = &tramp.sig.ident;

            let pattern = format_ident!("__pattern");
            let block = if f_is_infallible {
                // It's infallible, so just return the result
                // directly.
                let util = &ctx.util;
                quote!(#util::check_valid_output_ty(#pattern))
            } else {
                let success = if f.sig.output.is_result() {
                    quote! {
                        match #pattern {
                            ::core::result::Result::Ok(()) => {
                                <#err_ty as #capi::ErrorCode>::SUCCESS
                            }
                            ::core::result::Result::Err(ref err) => {
                                #error::convert_err(err)
                            }
                        }
                    }
                } else {
                    quote!(<#err_ty as #capi::ErrorCode>::SUCCESS)
                };

                if inputs.are_infallible() {
                    success
                } else {
                    quote! {
                        match #pattern {
                            // The arguments are all valid.
                            ::core::result::Result::Ok(#pattern) => {
                                #success
                            }
                            // An argument is invalid.
                            ::core::result::Result::Err(ref err) => {
                                #error::convert_err(err)
                            }
                        }
                    }
                }
            };

            let f = parse_quote_spanned! {f.sig.span()=>
                #doc
                #(#attrs)*
                #tracing
                #[no_mangle]
                pub extern "C" fn #name(#inputs) #ret {
                    #[allow(clippy::blocks_in_conditions)]
                    #[allow(clippy::match_single_binding)]
                    #[allow(unused_braces)]
                    match #unsafety { #tramp_fn(#(#args),*) } {
                        #pattern => { #block }
                    }
                }
            };
            FfiFn::parse(ctx, f)?
        };

        // A C API function with an extended error parameter.
        let extended = if !f_is_infallible && f.no_ext_error.is_none() {
            Some({
                let ext_err_ty = &ctx.ext_err_ty;
                // TODO
                let _underlying_ext_err_ty = {
                    if let Some(ident) = ext_err_ty.get_ident() {
                        quote!(self::#ident)
                    } else {
                        quote!(#ext_err_ty)
                    }
                };
                let ext_err = format_ident!("__ext_err");
                let name = f.sig.ident.with_prefix(&ctx.fn_prefix).with_suffix("_ext");

                let inputs = {
                    let arg = FnArg::parse_ffi(ctx, parse_quote!(#ext_err: *mut #ext_err_ty))?;
                    let mut inputs = inputs.clone();
                    inputs.append(self.rewrite_inputs(ctx, [arg]));
                    inputs
                };

                // Exclude `__ext_err`.
                let args = inputs
                    .args()
                    .map(|arg| {
                        // Assert that each input type is allowed.
                        check_valid_input_ty(ctx, arg)
                    })
                    .take(inputs.len().saturating_sub(1));
                let tramp_fn = &tramp.sig.ident;
                let tracing = Instrument::from_inputs(capi, inputs.args());

                let pattern = format_ident!("__pattern");
                let block = if f_is_infallible {
                    // It's infallible, so just return the result
                    // directly.
                    let util = &ctx.util;
                    quote!(#util::check_valid_output_ty(#pattern))
                } else {
                    // We have an output parameter, so we either
                    // return nothing or an error.
                    let success = if f.sig.output.is_result() {
                        quote! {
                            match #pattern {
                                ::core::result::Result::Ok(()) => {
                                    <#err_ty as #capi::ErrorCode>::SUCCESS
                                }
                                ::core::result::Result::Err(err) => {
                                    type __ExtErrTy = #ext_err_ty;
                                    #error::handle_ext_error(
                                        err,
                                        #capi::from_inner_mut_ptr!(#ext_err => __ExtErrTy),
                                    )
                                }
                            }
                        }
                    } else {
                        quote!(<#err_ty as #capi::ErrorCode>::SUCCESS)
                    };

                    if inputs.are_infallible() {
                        success
                    } else {
                        quote! {
                            match #pattern {
                                // The arguments are all valid.
                                ::core::result::Result::Ok(#pattern) => {
                                    #success
                                }
                                // An argument is invalid.
                                ::core::result::Result::Err(err) => {
                                    type __ExtErrTy = #ext_err_ty;
                                    #error::handle_ext_error(
                                        err,
                                        #capi::from_inner_mut_ptr!(#ext_err => __ExtErrTy),
                                    )
                                }
                            }
                        }
                    }
                };

                let f = parse_quote_spanned! {f.sig.span()=>
                    #doc
                    #(#attrs)*
                    #tracing
                    #[no_mangle]
                    pub extern "C" fn #name(#inputs) #ret {
                        #[allow(clippy::blocks_in_conditions)]
                        #[allow(clippy::match_single_binding)]
                        #[allow(unused_braces)]
                        match #unsafety { #tramp_fn(#(#args),*) } {
                            #pattern => { #block }
                        }
                    }
                };
                FfiFn::parse(ctx, f)?
            })
        } else {
            None
        };

        self.add_node(basic);
        if let Some(ext) = extended {
            self.add_node(ext);
        }
        self.add_node(tramp);

        if f.generated.is_some() {
            self.add_node(f);
        }

        Ok(())
    }

    /// Generates an `init` constructor for `ty`.
    #[instrument(skip_all, fields(%ty, ?no_ext_error))]
    fn add_init_constructor(
        &mut self,
        ctx: &Ctx,
        ty: &Ident,
        old: &Ident,
        lifetimes: &Lifetimes,
        no_ext_error: Option<NoExtError>,
    ) -> Result<()> {
        trace!("generating `init` constructor");

        // TODO(eric): fix this span
        let span = Span::call_site();
        let capi = &ctx.capi;
        let util = &ctx.util;
        let name = old.to_snake_case().with_suffix("_init");

        let doc = parse_doc! {r#"
/// Initializes `{ty}`.
///
/// When no longer needed, `out`'s resources must be released
/// with its cleanup routine.
///
/// @relates {ty}
"#};
        let f = RustFn::parse(
            ctx,
            parse_quote_spanned! {span=>
                #doc
                #no_ext_error
                #[#capi::generated]
                #[::tracing::instrument(
                    fields(out = %#util::Addr::from_mut(out)),
                )]
                fn #name #lifetimes(
                    out: &mut MaybeUninit<#ty #lifetimes>,
                ) -> Result<(), #capi::InvalidArg<'static>> {
                    <#ty as #capi::InitDefault>::init_default(out);
                    ::core::result::Result::Ok(())
                }
            },
        )?;
        self.expand_fn(ctx, f)
    }

    /// Generates a `build` constructor.
    #[instrument(skip_all, fields(%builder, %output, ?no_ext_error))]
    fn add_build_constructor(
        &mut self,
        ctx: &Ctx,
        builder: &Ident,
        old: &Ident,
        output: &Ident,
        lifetimes: &Lifetimes,
        no_ext_error: Option<NoExtError>,
    ) -> Result<()> {
        trace!("generating `build` constructor");

        // TODO(eric): fix this span
        let span = Span::call_site();
        let capi = &ctx.capi;
        let util = &ctx.util;
        let name = old.to_snake_case().with_suffix("_build");

        let doc = parse_doc! {r#"
/// Builds `{output}`.
///
/// When no longer needed, `out`'s resources must be released
/// with its cleanup function.
"#};
        let f = RustFn::parse(
            ctx,
            parse_quote_spanned! {span=>
                #doc
                #no_ext_error
                #[#capi::generated]
                #[::tracing::instrument(
                    fields(
                        builder = %#util::Addr::from_owned_ptr(&builder),
                        out = %#util::Addr::from_mut(out),
                    ),
                )]
                fn #name #lifetimes(
                    builder: OwnedPtr<#builder #lifetimes>,
                    out: &mut MaybeUninit<#output #lifetimes>,
                ) -> Result<(), <OwnedPtr<#builder #lifetimes> as #capi::Builder>::Error> {
                    builder.build(#capi::to_inner_mut!(out))?;
                    ::core::result::Result::Ok(())
                }
            },
        )?;
        self.expand_fn(ctx, f)
    }

    /// Generates a destructor for `ty`.
    #[instrument(skip_all, fields(%ty, ?no_ext_error))]
    fn add_destructor(
        &mut self,
        ctx: &Ctx,
        ty: &Ident,
        old: &Ident,
        lifetimes: &Lifetimes,
        no_ext_error: Option<NoExtError>,
    ) -> Result<()> {
        trace!("generating destructor");

        // TODO(eric): fix this span
        let span = Span::call_site();
        let capi = &ctx.capi;
        let util = &ctx.util;
        let name = old.to_snake_case().with_suffix("_cleanup");
        let init = old
            .to_snake_case()
            .with_suffix("_init")
            .with_prefix(&ctx.fn_prefix);

        let doc = parse_doc! {r#"
/// Releases any resources associated with `ptr`.
///
/// `ptr` must either be null or initialized by `::{init}`.
///
/// @relates {ty}
"#};
        let f = RustFn::parse(
            ctx,
            parse_quote_spanned! {span=>
                #doc
                #no_ext_error
                #[#capi::generated]
                #[#capi::internal::tracing::instrument(
                    fields(
                        ptr = %#util::Addr::from_opt_owned_ptr(&ptr),
                    ),
                )]
                fn #name #lifetimes(
                    ptr: Option<OwnedPtr<#ty #lifetimes>>,
                ) -> Result<(), #capi::InvalidArg<'static>> {
                    if let ::core::option::Option::Some(ptr) = ptr {
                        unsafe {
                            ptr.drop_in_place();
                        }
                    }
                    ::core::result::Result::Ok(())
                }
            },
        )?;
        self.expand_fn(ctx, f)
    }

    /// Retwrite a function's inputs.
    ///
    /// Returns the glue code that converts FFI types to regular
    /// Rust types.
    fn rewrite_inputs<I>(&self, ctx: &Ctx, inputs: I) -> FnInputs
    where
        I: IntoIterator<Item = FnArg>,
    {
        let mut new = FnInputs::new();
        for arg in inputs {
            let arg = self.expand_fn_arg(arg);

            let conv = self.ffi_conv_glue(ctx, &arg);
            let newtype = unpack_newtype_glue(ctx, &arg);

            new.push(FnInput {
                ty: arg.ty,
                arg: arg.arg,
                conv,
                newtype,
            });
            if let Some(arg) = arg.extra {
                new.push(FnInput {
                    ty: arg.ty.clone(),
                    arg,
                    conv: None,
                    newtype: None,
                })
            }
        }
        new
    }

    /// Expand `arg` as necessary.
    ///
    /// For example
    ///
    /// ```text
    /// foo: &[T]
    /// ```
    ///
    /// is expanded to
    ///
    /// ```text
    /// foo: *const T, foo_len: usize
    /// ```
    fn expand_fn_arg(&self, mut arg: FnArg) -> ExpandedArg {
        let ffi = ffi_safe_ty(&arg.ty);
        let ty = mem::replace(&mut arg.ty, ffi);

        let name = &arg.name;
        let extra = match &ty {
            Type::CBytes(_) => {
                // `CBytes` -> `(*const u8, usize)`
                Some(FnArg::usize(name.with_suffix("_len")))
            }

            Type::Ref(xref) if xref.mutability.is_none() => {
                // `&[T]` -> `(*const T, usize)`
                // `&str` -> `(*const u8, usize)`
                if let Type::Slice(_) | Type::Str(_) = &xref.elem {
                    Some(FnArg::usize(name.with_suffix("_len")))
                } else {
                    None
                }
            }

            Type::Ref(xref) if xref.mutability.is_some() => {
                // `&mut [T]` -> `(*mut T, usize)`
                if let Type::Slice(_) = &xref.elem {
                    Some(FnArg::usize(name.with_suffix("_len")))
                } else {
                    None
                }
            }

            Type::Writer(_) => {
                // `Writer` -> `(*mut u8, *mut usize)`
                let span = Span::call_site();
                Some(FnArg {
                    attrs: Vec::new(),
                    name: name.with_suffix("_len"),
                    colon_token: Token![:](span),
                    ty: Type::usize(span).into_mut_ptr(),
                })
            }

            _ => None,
        };
        ExpandedArg { ty, arg, extra }
    }

    /// Generates an [`Expr`] that performs the Rust to FFI type
    /// conversion.
    ///
    /// Returns `None` if glue isn't needed.
    fn ffi_conv_glue(&self, ctx: &Ctx, arg: &ExpandedArg) -> Option<Expr> {
        let capi = &ctx.capi;
        let name = &arg.arg.name;

        let expr = match &arg.ty {
            // `CBytes` -> `(*const u8, usize)`
            Type::CBytes(_) => {
                let size = name.with_suffix("_len");
                parse_quote! {
                    #capi::safe::CBytes::from_slice(
                        #capi::try_as_slice!(#name, #size),
                    )
                }
            }

            // `CStr` -> `*const c_char`
            Type::CStr(_) => parse_quote! {
                #capi::try_as_ref!(#name)
            },

            // `OwnedPtr<T>` -> `*mut T`
            Type::OwnedPtr(_) => parse_quote! {
                #capi::try_consume!(#name)
            },

            // `&T` -> `*const T`
            Type::Ref(xref) if xref.mutability.is_none() => match &xref.elem {
                // `&[T]` -> `(*const T, usize)`
                Type::Slice(_) => {
                    let size = name.with_suffix("_len");
                    parse_quote! {
                        #capi::try_as_slice!(#name, #size)
                    }
                }
                // `&str` -> `(*const u8, usize)`
                Type::Str(_) => {
                    let size = name.with_suffix("_len");
                    parse_quote! {
                        #capi::try_as_str!(#name, #size)
                    }
                }
                _ => parse_quote! {
                    #capi::try_as_ref!(#name)
                },
            },

            // `&mut T` -> `*mut T`
            Type::Ref(xref) if xref.mutability.is_some() => match &xref.elem {
                // `&mut MaybeUninit<T>` -> `*mut MaybeUninit<T>`.
                Type::MaybeUninit(_) => parse_quote! {
                    #capi::try_as_uninit_mut!(#name)
                },
                // `&mut [T]` -> `(*mut T, usize)`
                Type::Slice(_) => {
                    let size = name.with_suffix("_len");
                    parse_quote! {
                        #capi::try_as_mut_slice!(#name, #size)
                    }
                }
                _ => parse_quote! {
                    #capi::try_as_mut!(#name)
                },
            },

            // `Option<&T>` -> `*const T`
            // `Option<&mut T>` -> `*mut T`
            // `Option<OwnedPtr<T>>` -> `*mut T`
            Type::Option(ty) => match &ty.elem {
                Type::Ref(xref) if xref.mutability.is_none() => parse_quote! {
                    #capi::try_as_opt!(#name)
                },
                Type::Ref(xref) if xref.mutability.is_some() => parse_quote! {
                    #capi::try_as_opt_mut!(#name)
                },
                Type::OwnedPtr(_) => parse_quote! {
                    #capi::try_consume_opt!(#name)
                },
                _ => return None,
            },

            Type::Named(named) => {
                let new_name = named.path.ty_name();
                let old_name = self.idents.get_old(new_name).expect("unknown type");
                let defs = &ctx.defs;
                if let Some(Node::Enum(_)) = self.types.get(old_name) {
                    parse_quote! {
                        #capi::try_as_enum!(#defs::#old_name, #name)
                    }
                } else {
                    return None;
                }
            }

            Type::Writer(_) => {
                let size = name.with_suffix("_len");
                parse_quote! {
                    #capi::try_as_writer!(#name, #size)
                }
            }

            _ => return None,
        };
        Some(expr)
    }
}

/// Converts the type to an FFI-safe argument.
///
/// For example, it converts `OwnedPtr<T>` to `*mut T`.
fn ffi_safe_ty(ty: &Type) -> Type {
    match ty {
        Type::CBytes(cbytes) => {
            let span = cbytes.span();
            Type::Ptr(Box::new(Ptr {
                star_token: Token![*](span),
                const_token: Some(Token![const](span)),
                mutability: None,
                elem: Scalar::with_span(ScalarType::U8, span).into(),
            }))
        }
        Type::CStr(cstr) => {
            let span = cstr.span();
            Type::Ptr(Box::new(Ptr {
                star_token: Token![*](span),
                const_token: Some(Token![const](span)),
                mutability: None,
                elem: Scalar::with_span(ScalarType::CChar, span).into(),
            }))
        }
        Type::Option(opt) => ffi_safe_ty(&opt.elem),
        Type::OwnedPtr(ptr) => {
            let span = ptr.span();
            Type::Ptr(Box::new(Ptr {
                star_token: Token![*](span),
                const_token: None,
                mutability: Some(Token![mut](span)),
                elem: ffi_safe_ty(&ptr.elem),
            }))
        }
        Type::Ref(xref) => match &xref.elem {
            Type::Str(str) => {
                let span = str.span();
                Type::Ptr(Box::new(Ptr {
                    star_token: Token![*](span),
                    const_token: Some(Token![const](span)),
                    mutability: None,
                    elem: Scalar::with_span(ScalarType::U8, span).into(),
                }))
            }
            elem => {
                let span = xref.span();
                let (const_token, mutability) = if xref.mutability.is_some() {
                    (None, Some(Token![mut](span)))
                } else {
                    (Some(Token![const](span)), None)
                };
                let elem = if let Type::Slice(slice) = &elem {
                    &slice.elem
                } else {
                    elem
                };
                Type::Ptr(Box::new(Ptr {
                    star_token: Token![*](span),
                    const_token,
                    mutability,
                    elem: ffi_safe_ty(elem),
                }))
            }
        },
        v @ Type::Result(_) => {
            // TODO(eric): return an error instead.
            v.clone()
        }
        Type::Writer(writer) => {
            let span = writer.span();
            Type::Ptr(Box::new(Ptr {
                star_token: Token![*](span),
                const_token: None,
                mutability: Some(Token![mut](span)),
                elem: ffi_safe_ty(&writer.elem),
            }))
        }
        v => v.clone(),
    }
}

struct ExpandedArg {
    /// The original, possibly non-FFI safe type.
    ty: Type,
    /// The function argument with its type mapped to its FFI
    /// representation.
    arg: FnArg,
    /// Any extra args. For example, the length of a slice.
    extra: Option<FnArg>,
}

#[derive(Clone, Debug)]
struct FnInputs {
    inputs: Vec<FnInput>,
}

impl FnInputs {
    const fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Appends `input` to `self`.
    fn push(&mut self, input: FnInput) {
        self.inputs.push(input)
    }

    /// Appends `other` to `self`.
    fn append(&mut self, mut other: Self) {
        self.inputs.append(&mut other.inputs)
    }

    /// Reports whether all arguments do not contain conv glue.
    fn are_infallible(&self) -> bool {
        self.inputs.iter().all(|arg| arg.conv.is_none())
    }

    /// Returns an iterator over the [`FnInput`]s.
    fn iter(&self) -> slice::Iter<'_, FnInput> {
        self.inputs.iter()
    }

    /// Returns an iterator over the [`FnArg`]s.
    fn args(&self) -> impl Iterator<Item = &FnArg> {
        self.iter().map(|input| &input.arg)
    }

    /// Returns an iterator over the [`FnArg`]s interspersed with
    /// commas.
    fn punctuated_args(&self) -> PunctuatedArgs<'_> {
        PunctuatedArgs {
            inputs: self.inputs.iter().peekable(),
        }
    }
}

impl Extend<FnInput> for FnInputs {
    fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = FnInput>,
    {
        self.inputs.extend(iter)
    }
}

impl IntoIterator for FnInputs {
    type Item = FnInput;
    type IntoIter = <Vec<FnInput> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.inputs.into_iter()
    }
}

impl ToTokens for FnInputs {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        tokens.append_all(self.punctuated_args())
    }
}

/// An iterator over [`FnArg`] interspersed with commas.
struct PunctuatedArgs<'a> {
    inputs: Peekable<slice::Iter<'a, FnInput>>,
}

impl<'a> Iterator for PunctuatedArgs<'a> {
    type Item = Pair<&'a FnArg, Token![,]>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.inputs.next()?;
        if self.inputs.peek().is_some() {
            let span = Span::call_site();
            Some(Pair::Punctuated(&next.arg, Token![,](span)))
        } else {
            Some(Pair::End(&next.arg))
        }
    }
}

#[derive(Clone, Debug)]
struct FnInput {
    /// The original type.
    ty: Type,
    /// The argument.
    arg: FnArg,
    /// Converts an FFI type to a Rust type.
    conv: Option<Expr>,
    /// Unpacks a `NewType`.
    newtype: Option<Expr>,
}

/// Generates an [`Expr`] that unpacks a `NewType` to its inner
/// type.
fn unpack_newtype_glue(ctx: &Ctx, arg: &ExpandedArg) -> Option<Expr> {
    let capi = &ctx.capi;
    let ident = &arg.arg.name;
    match &arg.ty {
        Type::Named(_) => Some(parse_quote!(#capi::to_inner!(#ident))),
        Type::OwnedPtr(_) => Some(parse_quote! {
            #capi::to_inner!(#ident)
        }),
        // `*const T`
        Type::Ptr(ptr) if ptr.mutability.is_none() => {
            if let Type::Named(_) = &ptr.elem {
                Some(parse_quote!(#capi::to_inner_ptr!(#ident)))
            } else {
                None
            }
        }
        // `*mut T`
        Type::Ptr(ptr) if ptr.mutability.is_some() => {
            if let Type::MaybeUninit(_) | Type::Named(_) = &ptr.elem {
                Some(parse_quote!(#capi::to_inner_mut_ptr!(#ident)))
            } else {
                None
            }
        }
        // `&T`, `&[T]`, etc.
        Type::Ref(xref) if xref.mutability.is_none() => match &xref.elem {
            Type::Named(_) => Some(parse_quote!(#capi::to_inner_ref!(#ident))),
            Type::Slice(_) => Some(parse_quote!(#capi::to_inner_slice!(#ident))),
            _ => None,
        },
        // `&mut T`, `&mut [T]`, etc.
        Type::Ref(xref) if xref.mutability.is_some() => match &xref.elem {
            Type::MaybeUninit(_) | Type::Named(_) => {
                Some(parse_quote!(#capi::to_inner_mut!(#ident)))
            }
            Type::Slice(_) => Some(parse_quote!(#capi::to_inner_slice_mut!(#ident))),
            _ => None,
        },
        Type::Option(_) => Some(parse_quote!(#capi::to_inner!(#ident))),
        _ => None,
    }
}

/// Cast a trampoline's result.
fn cast_output_ty(
    ctx: &Ctx,
    ty: &Type,
    ident: &Ident,
    types: &HashMap<Ident, Node>,
    idents: &IdentMap,
) -> Option<TokenStream> {
    let (mac, named) = match ty {
        Type::Named(named) => {
            let new_name: &Ident = named.path.ty_name();
            let old_name = idents.get_old(new_name).expect("unknown type");
            if let Some(Node::Enum(_)) = types.get(old_name) {
                return Some(quote! {
                    #new_name::from(#ident)
                });
            } else {
                (quote!(from_inner), named)
            }
        }
        // `OwnedPtr<T>`
        Type::OwnedPtr(ptr) => {
            if let Type::Named(named) = &ptr.elem {
                (quote!(from_inner), named)
            } else {
                return None;
            }
        }
        // `*const T`
        Type::Ptr(ptr) if ptr.mutability.is_none() => {
            if let Type::Named(named) = &ptr.elem {
                (quote!(from_inner_ptr), named)
            } else {
                return None;
            }
        }
        // `*mut T`
        Type::Ptr(ptr) if ptr.mutability.is_some() => {
            if let Type::Named(named) = &ptr.elem {
                (quote!(from_inner_mut_ptr), named)
            } else {
                return None;
            }
        }
        // `&T`, `&[T]`, etc.
        Type::Ref(xref) if xref.mutability.is_none() => match &xref.elem {
            Type::Named(named) => (quote!(from_inner_ref), named),
            Type::Slice(slice) => {
                if let Type::Named(named) = &slice.elem {
                    (quote!(from_inner_slice), named)
                } else {
                    return None;
                }
            }
            _ => return None,
        },
        // `&mut T`, `&mut [T]`, etc.
        Type::Ref(xref) if xref.mutability.is_some() => match &xref.elem {
            // TODO
            // Type::MaybeUninit(v) => {
            //     let elem = &v.elem;
            //     (quote!(from_inner_mut), &v.elem)
            // }
            Type::Named(named) => (quote!(from_inner_mut), named),
            Type::Slice(slice) => {
                if let Type::Named(named) = &slice.elem {
                    (quote!(from_inner_slice_mut), named)
                } else {
                    return None;
                }
            }
            _ => return None,
        },
        _ => return None,
    };

    // The 'rewrite' AST pass does not inspect macros (and
    // effectively cannot because macros are unstructured), so
    // simply generating
    //
    //    #conv::#mac!(#ident => #named)
    //
    // causes compilation errors. Snag the result type so that we
    // rewrite the type correctly.
    let capi = &ctx.capi;
    Some(quote! {{
        type __Result = #named;
        #capi::#mac!(#ident => __Result)
    }})
}

fn check_valid_input_ty(ctx: &Ctx, arg: &FnArg) -> TokenStream {
    let util = &ctx.util;
    let name = &arg.name;
    match &arg.ty {
        Type::CStr(_) => {
            quote! {
                #util::check_valid_input_ty_const_ptr(#name)
            }
        }
        Type::Ptr(ptr) if ptr.mutability.is_none() => {
            quote! {
                #util::check_valid_input_ty_const_ptr(#name)
            }
        }
        Type::OwnedPtr(_) | Type::Writer(_) => {
            quote! {
                #util::check_valid_input_ty_mut_ptr(#name)
            }
        }
        Type::Ptr(ptr) if ptr.mutability.is_some() => {
            quote! {
                #util::check_valid_input_ty_mut_ptr(#name)
            }
        }
        _ => {
            quote! {
                #util::check_valid_input_ty_val(#name)
            }
        }
    }
}

/// Generates an "FFI wrapper" type for the type `name`.
///
/// The wrapper has one generic parameter per field. This lets us
/// implement certain traits iff all fields also implement that
/// trait.
///
/// The wrapper has the same memory layout as its underlying
/// type.
fn ffi_wrapper(ctx: &Ctx, strukt: &Struct, underlying: &Path) -> TokenStream {
    let capi = &ctx.capi;
    let conv = &ctx.conv;

    let name = &strukt.ident;

    let inner = format_ident!("Inner");

    // TODO(eric): I actually don't exactly remember why we do
    // this...
    let fields = if matches!(strukt.repr, Repr::Transparent) {
        &Fields::Unit
    } else {
        &strukt.fields
    };
    let types = fields.iter().map(|f| &f.ty);
    let fields = (0..fields.len())
        .map(|i| format_ident!("_{i}"))
        .collect::<Vec<_>>();
    let attrs = strukt
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"))
        .collect::<Vec<_>>();

    // All generic arguments.
    let generics = {
        let mut generics = Punctuated::<Ident, Token![,]>::new();
        generics.push(inner.clone());
        generics.extend(fields.clone());
        generics
    };

    let wrapper = format_ident!("__{}FfiWrapper", name);

    let mut tokens = TokenStream::new();
    tokens.extend(quote! {
        #(#attrs)*
        pub type #name = #wrapper<#underlying, #(#types),*>;

        #[repr(transparent)]
        #[derive(Debug)]
        #(#attrs)*
        pub struct #wrapper<#generics> {
            pub inner: #inner,
            #(#fields : ::core::marker::PhantomData<#fields>),*
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> #capi::InitDefault for #wrapper<#generics>
        where
            #inner: #capi::InitDefault,
        {
            fn init_default(out: &mut ::core::mem::MaybeUninit<Self>) {
                <#inner as #capi::InitDefault>::init_default(
                    // SAFETY: TODO
                    unsafe {
                        ::core::mem::transmute::<
                            &mut ::core::mem::MaybeUninit<Self>,
                            &mut ::core::mem::MaybeUninit<#inner>,
                        >(out)
                    }
                )
            }
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> ::core::marker::Copy for #wrapper<#generics>
        where
            #inner: ::core::marker::Copy
        {}

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> ::core::clone::Clone for #wrapper<#generics>
        where
            #inner: ::core::clone::Clone
        {
            fn clone(&self) -> Self {
                Self {
                    inner: ::core::clone::Clone::clone(&self.inner),
                    #(#fields : ::core::marker::PhantomData),*
                }
            }
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> ::core::ops::Deref for #wrapper<#generics> {
            type Target = #inner;

            fn deref(&self) -> &Self::Target {
                &self.inner
            }
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> ::core::ops::DerefMut for #wrapper<#generics> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.inner
            }
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> #capi::Builder for #wrapper<#generics>
        where
            #inner: #capi::Builder,
        {
            type Output = <#inner as #capi::Builder>::Output;
            type Error = <#inner as #capi::Builder>::Error;

            unsafe fn build(
                self,
                out: &mut ::core::mem::MaybeUninit<Self::Output>,
            ) -> ::core::result::Result<(), Self::Error> {
                unsafe { #capi::Builder::build(self.inner, out) }
            }
        }

        #[automatically_derived]
        #(#attrs)*
        unsafe impl<#(#fields),*> #conv::newtype::NewType for #wrapper<#underlying, #(#fields),*> {
            type Inner = #underlying;
        }

        #[automatically_derived]
        #(#attrs)*
        impl<#generics> #capi::types::Opaque for #wrapper<#generics>
        where
            #inner: #capi::types::Opaque,
        {}

        #[automatically_derived]
        #(#attrs)*
        unsafe impl<#generics> #capi::types::Input for #wrapper<#generics>
        where
            #(#fields : #capi::types::Input),*
        {}

        #[automatically_derived]
        #(#attrs)*
        unsafe impl<#generics> #capi::types::ByValue for #wrapper<#generics>
        where
            #inner: ::core::marker::Copy,
            #(#fields : #capi::types::ByValue),*
        {}

        #[automatically_derived]
        #(#attrs)*
        unsafe impl<#generics> #capi::types::ByConstPtr for #wrapper<#generics>
        where
            #(#fields : #capi::types::ByConstPtr),*
        {}

        #[automatically_derived]
        #(#attrs)*
        unsafe impl<#generics> #capi::types::ByMutPtr for #wrapper<#generics>
        where
            #(#fields : #capi::types::ByMutPtr),*
        {}

        #(#attrs)*
        const _: () = {
            const GOT: usize = ::core::mem::size_of::<#name>();
            const WANT: usize = ::core::mem::size_of::<#underlying>();
            const MSG: &str = #capi::internal::const_format::formatcp!("BUG: invalid size: {GOT} != {WANT}");
            // NB: We use `core::assert!` instead of
            // `const_format::assertcp_eq!` because the
            // latter clobbers our spans.
            ::core::assert!(GOT == WANT, "{}", MSG);
        };
        #(#attrs)*
        const _: () = {
            const GOT: usize = ::core::mem::align_of::<#name>();
            const WANT: usize = ::core::mem::align_of::<#underlying>();
            const MSG: &str = #capi::internal::const_format::formatcp!("BUG: invalid alignment: {GOT} != {WANT}");
            // NB: We use `core::assert!` instead of
            // `const_format::assertcp_eq!` because the
            // latter clobbers our spans.
            ::core::assert!(GOT == WANT, "{}", MSG);
        };
        #(#attrs)*
        const _: () = {
            const GOT: bool = ::core::mem::needs_drop::<#name>();
            const WANT: bool = ::core::mem::needs_drop::<#underlying>();
            const MSG: &str = #capi::internal::const_format::formatcp!("BUG: invalid `Drop` impl: {GOT} != {WANT}");
            // NB: We use `core::assert!` instead of
            // `const_format::assertcp_eq!` because the
            // latter clobbers our spans.
            ::core::assert!(GOT == WANT, "{}", MSG);
        };
    });

    tokens
}
