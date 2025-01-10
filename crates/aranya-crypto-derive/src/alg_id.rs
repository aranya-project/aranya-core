use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt,
    fs::File,
    hash::{Hash, Hasher},
    io::Write,
};

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote, Data, DeriveInput, Error, Expr, ExprLit, Fields, Ident, Lit, LitInt, Path,
};

pub(crate) fn parse(item: TokenStream) -> syn::Result<TokenStream> {
    let AlgId { name, variants } = syn::parse2(item)?;

    // Our `extern crate`s.
    let postcard: Path = parse_quote!(_postcard);
    let serde: Path = parse_quote!(_serde);

    let postcard_impl = quote! {
        impl #postcard::experimental::max_size::MaxSize for #name {
            const POSTCARD_MAX_SIZE: usize = <u16 as #postcard::experimental::max_size::MaxSize>::POSTCARD_MAX_SIZE;
        }
    };

    let serde_impl = quote! {
        impl #serde::Serialize for #name {
            fn serialize<S>(&self, s: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: #serde::Serializer,
            {
                s.serialize_u16(self.to_u16())
            }
        }

        impl<'de> #serde::Deserialize<'de> for #name {
            fn deserialize<D>(d: D) -> ::core::result::Result<Self, D::Error>
            where
                D: #serde::Deserializer<'de>,
            {
                struct AlgIdVisitor;
                impl<'de> #serde::de::Visitor<'de> for AlgIdVisitor {
                    type Value = #name;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        ::core::write!(f, "{}", ::core::stringify!(#name))
                    }

                    fn visit_u64<E>(self, v: u64) -> ::core::result::Result<Self::Value, E>
                    where
                        E: #serde::de::Error,
                    {
                        let v = u16::try_from(v).map_err(E::custom)?;
                        #name::try_from_u16(v).map_err(E::custom)
                    }
                }
                d.deserialize_u16(AlgIdVisitor)
            }
        }
    };

    let error = format_ident!("Invalid{name}");
    let error_impl = quote! {
        #[derive(
            ::core::marker::Copy,
            ::core::clone::Clone,
            ::core::fmt::Debug,
            ::core::cmp::Eq,
            ::core::cmp::PartialEq,
        )]
        pub(crate) struct #error(());

        impl ::core::fmt::Display for #error {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "invalid {}", ::core::stringify!(#name))
            }
        }

        impl ::core::error::Error for #error {}
    };

    let base_impl = {
        // Self::Foo => 0x0010
        let to_mappings = variants.iter().map(|v| {
            let Variant { ident, discrim } = v;
            match discrim {
                Discriminant::Id(id) => quote! {
                    #name::#ident => #id
                },
                Discriminant::Other => quote! {
                    #name::Other(__id) => __id.get()
                },
            }
        });

        // 0x0010 => Self::Foo
        let from_mappings = variants.iter().map(|v| {
            let Variant { ident, discrim } = v;
            match discrim {
                Discriminant::Id(id) => quote! {
                    #id => ::core::result::Result::Ok(#name::#ident)
                },
                Discriminant::Other => quote! {
                    __id => match ::core::num::NonZeroU16::new(__id) {
                        ::core::option::Option::Some(__id) => ::core::result::Result::Ok(#name::Other(__id)),
                        ::core::option::Option::None => ::core::result::Result::Err(#error(())),
                    }
                },
            }
        });

        quote! {
            impl #name {
                /// Converts the algorithm ID to a `u16`.
                pub const fn to_u16(self) -> u16 {
                    match self {
                        #(#to_mappings),*,
                    }
                }

                /// Converts the algorithm ID to a big-endian
                /// byte array.
                pub const fn to_be_bytes(self) -> [u8; 2] {
                    self.to_u16().to_be_bytes()
                }

                /// Tries to parse the algorithm ID.
                pub const fn try_from_u16(__id: u16) -> ::core::result::Result<Self, #error> {
                    match __id {
                        #(#from_mappings),*,
                    }
                }
            }
        }
    };

    let block = quote! {
        #[doc(hidden)]
        #[allow(missing_docs, unused_extern_crates)]
        const _: () = {
            extern crate postcard as #postcard;
            extern crate serde as #serde;

            #base_impl
            #error_impl
            #serde_impl
            #postcard_impl
        };
    };

    // Undocumented.
    if cfg!(crypto_derive_debug) {
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

/// `#[derive(AlgId)]`
struct AlgId {
    /// Enum that we're deriving.
    name: Ident,
    /// Its variants.
    variants: Vec<Variant>,
}

impl Parse for AlgId {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let span = Span::call_site();
        let input = DeriveInput::parse(input)?;

        let Data::Enum(data) = input.data else {
            return Err(Error::new(span, "input must be an enum"));
        };

        let mut variants = data
            .variants
            .into_iter()
            .map(Variant::new)
            .collect::<syn::Result<Vec<_>>>()?;
        if variants.is_empty() {
            return Err(Error::new(span, "enum must have at least one variant"));
        }
        // Ensure that `Other` is always last.
        variants.sort();

        let mut uniq = HashMap::new();
        for v in variants.iter() {
            if let Some(dup) = uniq.insert(v.discrim.clone(), v) {
                return Err(Error::new(
                    v.ident.span(),
                    format!(
                        "duplicate ID {} for {} and {}",
                        v.discrim, v.ident, dup.ident
                    ),
                ));
            }
        }

        Ok(Self {
            name: input.ident,
            variants,
        })
    }
}

#[derive(Clone)]
struct Variant {
    ident: Ident,
    discrim: Discriminant,
}

impl Variant {
    fn new(v: syn::Variant) -> syn::Result<Self> {
        match v.fields {
            Fields::Unit | Fields::Unnamed(_) => {
                let discrim = Self::parse_discrim(&v)?;
                Ok(Self {
                    ident: v.ident,
                    discrim,
                })
            }
            _ => Err(Error::new(
                v.ident.span(),
                "must be a unit-only enum or else `Other`",
            )),
        }
    }

    fn parse_discrim(v: &syn::Variant) -> syn::Result<Discriminant> {
        let attrs = v
            .attrs
            .iter()
            .filter(|v| v.path().is_ident("alg_id"))
            .collect::<Vec<_>>();
        if attrs.len() != 1 {
            Err(Error::new(
                v.ident.span(),
                "must contain exactly one `alg_id` attr",
            ))
        } else {
            attrs[0].parse_args::<Discriminant>()
        }
    }
}

impl Eq for Variant {}
impl PartialEq for Variant {
    fn eq(&self, other: &Self) -> bool {
        self.discrim == other.discrim
    }
}

// Order variants by their discriminants.
impl Ord for Variant {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&self.discrim, &other.discrim)
    }
}
impl PartialOrd for Variant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Hash, Eq, PartialEq)]
enum Discriminant {
    Id(U16),
    Other,
}

impl Discriminant {
    /// Sort such that `Other` is always last.
    ///
    /// Given code like this:
    ///
    /// ```ignore
    /// enum MyId {
    ///     Foo,
    ///     Bar,
    ///     Other(NonZeroU16),
    /// }
    /// ```
    ///
    /// We generate code like this:
    ///
    /// ```ignore
    /// impl MyId {
    ///     const fn try_from_u16(v: u16) -> Result<Self, InvalidMyId> {
    ///         match v {
    ///             0x0010 => Self::Foo,
    ///             0x0011 => Self::Bar,
    ///             __id => match NonZeroU16::new() { ... }
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// If any enums were to appear after `Other`, we would
    /// generate incorrect code:
    ///
    /// ```ignore
    /// impl MyId {
    ///     const fn try_from_u16(v: u16) -> Result<Self, InvalidMyId> {
    ///         match v {
    ///             0x0010 => Self::Foo,
    ///             0x0011 => Self::Bar,
    ///             __id => match NonZeroU16::new() { ... }
    ///             // Oops, unreachable!
    ///             0xffff => Self::Baz,
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// `Discriminant`s are `u16`, so this just casts to a larger
    /// integer and sets `Other = T::MAX`.
    fn ord(&self) -> u32 {
        match self {
            Self::Id(id) => u32::from(id.repr),
            Self::Other => u32::MAX,
        }
    }
}

impl fmt::Display for Discriminant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{id}"),
            Self::Other => write!(f, "Other"),
        }
    }
}

// Sort such that `Other` is always last.
impl Ord for Discriminant {
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(&self.ord(), &other.ord())
    }
}
impl PartialOrd for Discriminant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Parse for Discriminant {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let expr: Expr = input.parse()?;
        match expr {
            Expr::Lit(ExprLit {
                lit: Lit::Int(lit), ..
            }) => Ok(Self::Id(U16::new(lit)?)),
            Expr::Path(path) if path.path.is_ident("Other") => Ok(Self::Other),
            _ => Err(Error::new(input.span(), "invalid attribute")),
        }
    }
}

/// A `u16` literal.
#[derive(Clone)]
struct U16 {
    repr: u16,
    lit: LitInt,
}

impl U16 {
    fn new(lit: LitInt) -> syn::Result<Self> {
        let repr = lit.base10_parse::<u16>()?;
        Ok(Self { repr, lit })
    }
}

impl fmt::Display for U16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.lit)
    }
}

impl Eq for U16 {}
impl PartialEq for U16 {
    fn eq(&self, other: &Self) -> bool {
        self.repr == other.repr
    }
}

impl Hash for U16 {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.repr.hash(state)
    }
}

impl ToTokens for U16 {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let lit = &self.lit;
        tokens.extend(quote!(#lit))
    }
}
