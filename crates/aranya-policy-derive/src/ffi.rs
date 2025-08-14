use std::{collections::HashSet, fs::File, io::Write};

use aranya_policy_lang::{
    ast::{EnumDefinition, FieldDefinition, FunctionDecl, StructDefinition, StructItem, VType},
    lang,
};
use proc_macro2::{Span, TokenStream};
use quote::{ToTokens, format_ident, quote, quote_spanned};
use syn::{
    Attribute, Error, FnArg, Ident, ImplItem, ImplItemFn, ItemImpl, LitStr, Meta, Pat, PatIdent,
    PatType, Path, ReturnType, Token,
    parse::{Parse, ParseStream},
    parse_quote,
    spanned::Spanned,
};

use crate::attr::{Attr, Symbol, get_lit_str};

// TODO(eric): allow `#[ffi_export("foo")]` as an alternative to
// `#[ffi_export(name = "foo")]`?

pub(crate) fn parse(attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let FfiAttr {
        module,
        structs,
        enums,
    } = syn::parse2(attr)?;
    let mut item: ItemImpl = syn::parse2(item)?;
    // The type that the `#[ffi]` attribute is applied to.
    let self_ty = &item.self_ty;
    let (impl_generics, _ty_generics, where_clause) = item.generics.split_for_impl();

    // Checks for duplicate FFI names.
    let mut ext_names = HashSet::new();

    let mut funcs = Vec::<Func>::new();
    for item in &mut item.items {
        let ImplItem::Fn(f) = item else {
            continue;
        };
        if let Some(f) = Func::from_ast(f)? {
            let name = f.ext_name.to_string();
            if !ext_names.insert(name) {
                return Err(Error::new_spanned(
                    item,
                    format!("duplicate FFI function name: {}", f.ext_name),
                ));
            }
            funcs.push(f);
        }
    }

    // Our `extern crate`s.
    let alloc: Path = parse_quote!(_alloc);
    let crypto: Path = parse_quote!(_crypto);
    let vm: Path = parse_quote!(_policy_vm);

    let structdefs = structs.iter().map(|d| {
        let name = &d.identifier.as_str();
        let fields = d.items.iter().map(|arg| match arg {
            StructItem::Field(arg) => {
                let name = &arg.identifier.as_str();
                let vtype = VTypeTokens::new(&arg.field_type, &vm);
                quote!(#vm::arg!(#name, #vtype))
            }
            StructItem::StructRef(_) => {
                todo!("struct field insertion");
            }
        });
        quote! {
            #vm::ffi::Struct {
                name: #vm::ident!(#name),
                fields: &[#(#fields),*],
            }
        }
    });

    // `struct Foo { ... }` definitions as parsed from
    // `#[ffi(def = "...")]`.
    let structs = structs.iter().map(|d| {
        let name = format_ident!("{}", d.identifier.as_str());
        let name_str = d.identifier.to_string();
        let (names, fields): (Vec<_>, Vec<_>) = d
            .items
            .iter()
            .map(|d| match d {
                StructItem::Field(d) => (
                    format_ident!("{}", d.identifier.as_str()),
                    format_ident!("__field_{}", d.identifier.as_str()),
                ),
                StructItem::StructRef(s) => {
                    todo!("`+{s}`: Struct field insertion is not implemented for FFI structs.")
                }
            })
            .unzip();
        let types = d.items.iter().map(|d| {
            let vtype = match d {
                StructItem::Field(f) => TypeTokens::new(&f.field_type, &alloc, &crypto, &vm),
                StructItem::StructRef(_) => todo!(),
            };
            quote!(#vtype)
        });
        quote! {
            #[must_use]
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub struct #name {
                #(pub #names: #types),*
            }
            #[automatically_derived]
            impl ::core::convert::From<#name> for #vm::Value {
                fn from(__value: #name) -> Self {
                    let __struct = #vm::Struct::new(
                        #vm::ident!(stringify!(#name)),
                        &[
                            #(#vm::KVPair::new(
                                #vm::ident!(stringify!(#names)),
                                __value.#names.into(),
                            )),*,
                        ],
                    );
                    __struct.into()
                }
            }
            #[automatically_derived]
            impl ::core::convert::TryFrom<#vm::Value> for #name {
                type Error = #vm::ValueConversionError;

                fn try_from(mut __value: #vm::Value) -> ::core::result::Result<Self, Self::Error> {
                    let #vm::Value::Struct(__struct) = &mut __value else {
                        return ::core::result::Result::Err(
                            #vm::ValueConversionError::invalid_type(
                                ::core::concat!("Struct ", #name_str),
                                __value.type_name(),
                                "TryFrom"
                            ));
                    };
                    if __struct.name != ::core::stringify!(#name) {
                        return ::core::result::Result::Err(
                            #vm::ValueConversionError::invalid_type(
                                ::core::concat!("Struct ", #name_str),
                                __value.type_name(),
                                "name doesn't match"
                            ));
                    }
                    #(
                        let #fields = __struct.fields.remove(::core::stringify!(#names))
                            .ok_or(#vm::ValueConversionError::InvalidStructMember(
                                    #vm::ident!(stringify!(#names)),
                            ))?;
                    )*
                    if !__struct.fields.is_empty() {
                        return ::core::result::Result::Err(#vm::ValueConversionError::BadState);
                    }
                    ::core::result::Result::Ok(#name {
                        #(
                            #names: #vm::TryFromValue::try_from_value(#fields)?
                        ),*
                    })
                }
            }
            #[automatically_derived]
            impl #vm::Typed for #name {
                const TYPE: #vm::ffi::Type<'static> = #vm::ffi::Type::Struct(#vm::ident!(#name_str));
            }
        }
    });

    let enum_defs = enums.iter().map(|d| {
        let name = d.identifier.as_str();
        let variants = d.variants.iter().map(|v| v.as_str());
        quote! {
            #vm::ffi::Enum {
                name: #vm::ident!(#name),
                variants: &[#(#vm::ident!(#variants)),*],
            }
        }
    });

    let enums = enums.iter().map(|d| {
        let name = format_ident!("{}", d.identifier.as_str());
        let name_str = d.identifier.to_string();
        let variants = d
            .variants
            .iter()
            .map(|v| format_ident!("{}", v.as_str()))
            .collect::<Vec<_>>();
        let var_const_names: Vec<_> = variants
            .iter()
            .map(|id| format_ident!("__{name}__{id}"))
            .collect();

        quote! {
            #[must_use]
            #[derive(Clone, Debug, Eq, PartialEq)]
            pub enum #name {
                #(#variants),*
            }
            #[automatically_derived]
            impl ::core::convert::From<#name> for #vm::Value {
                fn from(__value: #name) -> Self {
                    #vm::Value::Enum(
                        #vm::ident!(#name_str),
                        __value as i64,
                    )
                }
            }
            #[automatically_derived]
            impl ::core::convert::TryFrom<#vm::Value> for #name {
                type Error = #vm::ValueConversionError;
                fn try_from(value: #vm::Value) -> ::core::result::Result<Self, Self::Error> {
                    let #vm::Value::Enum(name, val) = &value else {
                        return ::core::result::Result::Err(#vm::ValueConversionError::invalid_type(
                            ::core::concat!("Enum ", #name_str), value.type_name(), "try_from"
                        ));
                    };

                    if name != #name_str {
                        return ::core::result::Result::Err(#vm::ValueConversionError::invalid_type(
                            ::core::concat!("Enum ", #name_str),
                            value.type_name(),
                            "enum names don't match",
                        ));
                    }

                    #( const #var_const_names: i64 = #name::#variants as i64; )*

                    match *val {
                        #(
                            #var_const_names => ::core::result::Result::Ok(Self::#variants),
                        )*
                        _ => ::core::result::Result::Err(#vm::ValueConversionError::OutOfRange),
                    }
                }
            }
            #[automatically_derived]
            impl #vm::Typed for #name {
                const TYPE: #vm::ffi::Type<'static> = #vm::ffi::Type::Enum(#vm::ident!(#name_str));
            }
        }
    });

    // The implementation of `FfiModule`.
    let mod_impl = {
        // The `Func` variant identifiers:
        //    __some_func,
        //    __another_func,
        //    ...
        let variants = funcs.iter().map(|f| f.variant()).collect::<Vec<_>>();

        // The `__Func` variants mapped from `usize`:
        //    const __some_func = Self::some_func as usize;
        //    const __another_func = Self::another_func as usize;
        //    ...
        let consts = variants.iter().map(|variant| {
            quote! {
                const #variant: usize = __Func::#variant as usize;
            }
        });

        // The `Func` variant identifiers mapped from
        // `usize`:
        //    Func_some_func => Some(Func_some_func),
        //    Func_another_func => Some(Func_another_func),
        //    ...
        //    _ => None,
        let mappings = variants.iter().map(|variant| {
            quote! {
                #variant => __Func::#variant
            }
        });

        // The `Func::call` match cases.
        //
        //    Func::__Func0 => { foo() },
        //    Func::__Func1 => { let v = stack.pop()?; bar(v) }
        //    ...
        let cases = funcs.iter().map(|f| {
            let variant = &f.variant();

            let names = f
                .args
                .iter()
                .map(|arg| format_ident!("__arg_{}", arg.ident));
            let args = f
                .args
                .iter()
                .map(|arg| {
                    let name = format_ident!("__arg_{}", arg.ident);
                    let rtype = &arg.ty.ty;
                    let vtype = VTypeTokens::new(&arg.def.field_type, &vm);
                    let msg = format!(
                        "mismatched types: expected `{want}`, found `{got}`",
                        want = quote!(#vtype),
                        got = quote!(#rtype),
                    );
                    let const_assert = quote_spanned! {rtype.span()=>
                        const {
                            let want = #vm::__type!(#vtype);
                            let got = <#rtype as #vm::Typed>::TYPE;
                            if !got.const_eq(&want) {
                                panic!(#msg);
                            }
                            // This is a silly workaround to "destructor cannot be evaluated at compile time".
                            // We can't const construct a heap variant for `Identifier`, so this doesn't leak.
                            ::core::mem::forget(got);
                            ::core::mem::forget(want);
                        }
                    };
                    quote! {
                        #const_assert
                        let #name = #vm::Stack::pop::<#rtype>(__stack)?
                    }
                })
                // Arguments are pushed to the stack in argument
                // order, so pop them in reverse order.
                .rev();

            let name = &f.name;
            let name = if f.is_method {
                quote!(self.#name)
            } else {
                quote!(Self::#name)
            };

            let inner = quote! {
                #(#args);*;
                let __result = #name(__ctx, __eng, #(#names),*)?;
                #vm::Stack::push(__stack, __result)?;
                ::core::result::Result::Ok(())
            };
            quote! {
                __Func::#variant => { #inner }
            }
        });

        // The function table.
        let funcs = funcs.iter().map(|f| {
            let name = f.ext_name.to_string();
            let args = f.args.iter().map(|arg| {
                let name = arg.def.identifier.as_str();
                let vtype = VTypeTokens::new(&arg.def.field_type, &vm);
                quote!(#vm::arg!(#name, #vtype))
            });
            let return_type = {
                let vtype = VTypeTokens::new(&f.result, &vm);
                quote!(#vm::__type!(#vtype))
            };
            quote! {
                #vm::ffi::Func {
                    name: #vm::ident!(#name),
                    args: &[#(#args),*],
                    return_type: #return_type,
                }
            }
        });

        quote! {
            #[automatically_derived]
            impl #impl_generics #vm::ffi::FfiModule for #self_ty #where_clause {
                type Error = #vm::MachineError;

                const SCHEMA: #vm::ffi::ModuleSchema<'static> = #vm::ffi::ModuleSchema {
                    name: #vm::ident!(#module),
                    functions: &[
                        #(#funcs),*
                    ],
                    structs: &[
                        #(#structdefs),*
                    ],
                    enums: &[
                        #(#enum_defs),*
                    ],
                };

                #[doc(hidden)]
                #[allow(non_snake_case)]
                fn call<__E: #crypto::engine::Engine>(
                    &self,
                    __proc: usize,
                    __stack: &mut impl #vm::Stack,
                    __ctx: &#vm::CommandContext,
                    __eng: &mut __E,
                ) -> ::core::result::Result<(), Self::Error> {
                    #[allow(non_camel_case_types, clippy::enum_variant_names)]
                    enum __Func {
                        #(#variants),*
                    }
                    #[allow(non_upper_case_globals)]
                    let __f = {
                        #(#consts);*
                        match __proc {
                            #(#mappings),*,
                            _ => {
                                return ::core::result::Result::Err(
                                    #vm::MachineError::new(#vm::MachineErrorType::FfiProcedureNotDefined(
                                        Self::SCHEMA.name.clone(),
                                        __proc,
                                )));
                            }
                        }
                    };
                    // TODO(eric): instead of making this
                    // gigantic function, create a smaller
                    // function for each case and let the
                    // compiler decide whether they should be
                    // inlined.
                    match __f {
                        #(#cases),*
                    }
                }
            }
        }
    };

    let module = format_ident!("__{module}_ffi");
    let block = quote! {
        #[doc(hidden)]
        #[allow(missing_docs, unused_extern_crates)]
        mod #module {
            #[allow(clippy::clippy::wildcard_imports)]
            use super::*;

            // TODO(eric): make `alloc` optional.
            extern crate alloc as #alloc;
            extern crate aranya_crypto as #crypto;
            extern crate aranya_policy_vm as #vm;

            #(#structs)*
            #(#enums)*
        }
        pub use #module::*;

        #[doc(hidden)]
        #[allow(missing_docs, unused_extern_crates)]
        const _: () = {
            #[allow(clippy::clippy::wildcard_imports)]
            use #module::*;

            // TODO(eric): somehow move this out of the const
            // wrapper. The trick is rewriting function
            // arguments/results that use generated structs.
            #item

            // TODO(eric): make `alloc` optional.
            extern crate alloc as #alloc;
            extern crate aranya_crypto as #crypto;
            extern crate aranya_policy_vm as #vm;

            #mod_impl
        };
    };

    // Undocumented.
    if cfg!(policy_derive_debug) {
        let mut data = block.to_string();
        if let Ok(file) = syn::parse_file(&data) {
            data = prettyplease::unparse(&file);
        }
        File::create("/tmp/expand.rs")
            .expect("unable to create `/tmp/expand.rs`")
            .write_all(data.as_bytes())
            .expect("unable to write all data to `/tmp/expand.rs`");
    }
    Ok(block)
}

mod kw {
    syn::custom_keyword!(module);
    syn::custom_keyword!(def);
}

const MODULE: Symbol = Symbol("name");
const DEF: Symbol = Symbol("def");

/// The `#[ffi]` attribute.
struct FfiAttr {
    module: String,
    structs: Vec<StructDefinition>,
    enums: Vec<EnumDefinition>,
}

impl Parse for FfiAttr {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let mut module = Attr::none(MODULE);
        let mut struct_defs = Attr::none(DEF);
        let mut enum_defs = Attr::none(DEF);

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            // `module = "..."`
            if lookahead.peek(kw::module) {
                input.parse::<kw::module>()?;
                let _: Token![=] = input.parse()?;
                let name: LitStr = input.parse()?;
                skip_comma(input)?;
                module.set(&name, name.value())?;
            // `def = "..."`
            } else if lookahead.peek(kw::def) {
                input.parse::<kw::def>()?;
                let _: Token![=] = input.parse()?;
                let decl: LitStr = input.parse()?;
                skip_comma(input)?;
                let lang::FfiTypes { structs, enums } =
                    lang::parse_ffi_structs_enums(&decl.value()).map_err(|err| {
                        Error::new(decl.span(), format!("invalid policy definition: {err}"))
                    })?;
                struct_defs.set(&decl, structs)?;
                enum_defs.set(&decl, enums)?;
            } else {
                return Err(lookahead.error());
            }
        }

        let module = module
            .get()
            .ok_or(Error::new(input.span(), "missing `{MODULE}` argument"))?;
        Ok(Self {
            module,
            structs: struct_defs.get().unwrap_or_default(),
            enums: enum_defs.get().unwrap_or_default(),
        })
    }
}

/// Skips the next token if it's a comma.
fn skip_comma(input: ParseStream<'_>) -> syn::Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}

const FFI_EXPORT: Symbol = Symbol("ffi_export");

/// The `#[ffi_export]` attribute.
struct FfiExportAttr {
    def: FunctionDecl,
}

impl FfiExportAttr {
    fn new(span: Span, attrs: &mut Vec<Attribute>) -> syn::Result<Option<Self>> {
        let mut def = Attr::none(DEF);

        let mut found = attrs
            .iter()
            .enumerate()
            .filter(|(_, attr)| attr.path() == FFI_EXPORT);
        let Some((idx, attr)) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(Error::new(
                span,
                format!("`{FFI_EXPORT}` attribute can only be used once"),
            ));
        }
        match &attr.meta {
            // An empty attribute: `#[ffi_export]`.
            Meta::Path(_) => {}
            _ => attr.parse_nested_meta(|meta| {
                if meta.path == DEF {
                    let decl = get_lit_str(DEF, &meta)?.value();
                    let fd = lang::parse_ffi_decl(&decl)
                        .map_err(|err| meta.error(format!("invalid policy definition: {err}")))?;
                    def.set(&meta.path, fd)
                } else {
                    let path = meta.path.to_token_stream().to_string().replace(' ', "");
                    Err(meta.error(format!("unknown attr: {path}")))
                }
            })?,
        };
        attrs.remove(idx);

        let def = def
            .get()
            .ok_or(Error::new(span, "missing `def` argument in attribute"))?;

        Ok(Some(Self { def }))
    }
}

/// A foreign function.
#[derive(Clone, Debug)]
struct Func {
    /// The function's name (in Rust).
    name: Ident,
    /// The function's name (in Policy code).
    ext_name: Ident,
    /// Is this a method or associated function?
    is_method: bool,
    /// The function's arguments.
    args: Vec<Arg>,
    /// The function's result type.
    result: VType,
}

impl Func {
    fn from_ast(item: &mut ImplItemFn) -> syn::Result<Option<Self>> {
        let attr = match FfiExportAttr::new(item.span(), &mut item.attrs)? {
            Some(v) => v,
            None => return Ok(None),
        };
        let name = item.sig.ident.clone();

        // TODO(eric): reject ext names with invalid characters,
        // including "::".
        let ext_name = format_ident!("{}", attr.def.identifier.as_str());

        let is_method = item
            .sig
            .inputs
            .iter()
            .any(|arg| matches!(arg, FnArg::Receiver(_)));

        // The second and third arguments are `&CommandContext`
        // and `&mut E`, which are passed in by `call`, so skip
        // them.
        //
        // TODO(eric): we should issue a diagnostic when the
        // first non-self argument isn't `&CommandContext` and
        // second argument isn't `&mut E`.
        let num_skip = if is_method { 3 } else { 2 };
        let num_args = match item.sig.inputs.len().checked_sub(num_skip) {
            Some(n) => n,
            None => {
                return Err(Error::new_spanned(
                    &item.sig,
                    format!(
                        "too few function arguments: {} < {num_skip}",
                        item.sig.inputs.len()
                    ),
                ));
            }
        };
        let num_def_args = attr.def.arguments.len();
        if num_args != num_def_args {
            return Err(Error::new_spanned(
                &item.sig,
                format!(
                    "incorrect number of arguments per `def`: found {num_args}, want {num_def_args}"
                ),
            ));
        }

        let args = item
            .sig
            .inputs
            .iter()
            .skip(num_skip)
            .zip(attr.def.arguments.iter())
            .map(|(arg, def)| match arg {
                FnArg::Receiver(_) => unreachable!("should have skipped the receiver"),
                FnArg::Typed(t) => {
                    let Pat::Ident(PatIdent { ident, .. }) = &*t.pat else {
                        return Err(Error::new_spanned(
                            arg,
                            format!("invalid argument name: {}", t.pat.to_token_stream()),
                        ));
                    };

                    // arg name should match definition
                    if !ident.to_string().starts_with("_")
                        && def.identifier.name != ident.to_string().as_str()
                    {
                        return Err(Error::new_spanned(
                            ident,
                            format!(
                                "arg identifier `{ident}` should match definition (`{}`)",
                                def.identifier.name
                            ),
                        ));
                    }

                    Ok(Arg {
                        ident: ident.clone(),
                        ty: t.clone(),
                        def: def.clone(),
                    })
                }
            })
            .collect::<syn::Result<Vec<_>>>()?;

        let Some(vtype) = attr.def.return_type else {
            return Err(Error::new(item.span(), "FFI function must be pure"));
        };
        let result = match &item.sig.output {
            ReturnType::Default => {
                return Err(Error::new(item.span(), "Rust function cannot return `()`"));
            }
            _ => vtype.clone(),
        };

        Ok(Some(Self {
            name,
            ext_name,
            is_method,
            args,
            result,
        }))
    }

    fn variant(&self) -> Ident {
        format_ident!("__{}", self.name)
    }
}

/// A function argument.
#[derive(Clone, Debug)]
struct Arg {
    ident: Ident,
    ty: PatType,
    def: FieldDefinition,
}

/// Implements [`ToTokens`] for `VType.`
struct VTypeTokens<'a> {
    vtype: &'a VType,
    vm: &'a Path,
}

impl<'a> VTypeTokens<'a> {
    fn new(vtype: &'a VType, vm: &'a Path) -> Self {
        Self { vtype, vm }
    }
}

impl ToTokens for VTypeTokens<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let vm = self.vm;
        let item = match &self.vtype.kind {
            aranya_policy_lang::ast::TypeKind::String => quote!(String),
            aranya_policy_lang::ast::TypeKind::Bytes => quote!(Bytes),
            aranya_policy_lang::ast::TypeKind::Int => quote!(Int),
            aranya_policy_lang::ast::TypeKind::Bool => quote!(Bool),
            aranya_policy_lang::ast::TypeKind::Id => quote!(Id),
            aranya_policy_lang::ast::TypeKind::Struct(name) => {
                let name = name.as_str();
                quote!(Struct(#name))
            }
            aranya_policy_lang::ast::TypeKind::Enum(name) => {
                let name = name.as_str();
                quote!(Enum(#name))
            }
            aranya_policy_lang::ast::TypeKind::Optional(vtype) => {
                let vtype = VTypeTokens::new(vtype, vm);
                quote!(Optional(&#vm::ffi::Type::#vtype))
            }
        };
        tokens.extend(item)
    }
}

/// An implementation of [`ToTokens`] that maps [`VType`] to its
/// corresponding Rust types.
struct TypeTokens<'a> {
    vtype: &'a VType,
    alloc: &'a Path,
    crypto: &'a Path,
    vm: &'a Path,
}

impl<'a> TypeTokens<'a> {
    fn new(vtype: &'a VType, alloc: &'a Path, crypto: &'a Path, vm: &'a Path) -> Self {
        Self {
            vtype,
            alloc,
            crypto,
            vm,
        }
    }
}

impl ToTokens for TypeTokens<'_> {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let alloc = self.alloc;
        let crypto = self.crypto;
        let vm = self.vm;
        let item = match &self.vtype.kind {
            aranya_policy_lang::ast::TypeKind::String => quote!(#vm::Text),
            aranya_policy_lang::ast::TypeKind::Bytes => quote!(#alloc::vec::Vec<u8>),
            aranya_policy_lang::ast::TypeKind::Int => quote!(i64),
            aranya_policy_lang::ast::TypeKind::Bool => quote!(bool),
            aranya_policy_lang::ast::TypeKind::Id => quote!(#crypto::Id),
            aranya_policy_lang::ast::TypeKind::Struct(name) => {
                let ident = format_ident!("{name}");
                quote!(#ident)
            }
            aranya_policy_lang::ast::TypeKind::Enum(name) => {
                let ident = format_ident!("{name}");
                quote!(#ident)
            }
            aranya_policy_lang::ast::TypeKind::Optional(vtype) => {
                let vtype = TypeTokens::new(vtype, alloc, crypto, vm);
                quote!(::core::option::Option<#vtype>)
            }
        };
        tokens.extend(item)
    }
}
