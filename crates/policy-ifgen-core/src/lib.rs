use policy_ast::{Policy, VType};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};

pub fn generate_code(policy: &Policy) -> TokenStream {
    let structs = policy.structs.iter().map(|s| {
        structify(
            &s.identifier,
            s.fields.iter().map(|f| f.identifier.as_str()),
            s.fields.iter().map(|f| &f.field_type),
        )
    });

    let effects_parsing = quote! {
        /// Possible errors from policy effect parsing.
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum EffectsParseError {
            /// Effect has one or more extra fields.
            ExtraFields,
            /// Effect is missing an expected field.
            MissingField,
            /// Effect has unexpected field type.
            FieldTypeMismatch,
            /// Effect has unknown effect name.
            UnknownEffectName,
        }

        impl trouble::Error for EffectsParseError {}

        impl fmt::Display for EffectsParseError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    Self::ExtraFields => f.write_str("effect has one or more extra fields"),
                    Self::MissingField => f.write_str("effect is missing an expected field"),
                    Self::FieldTypeMismatch => f.write_str("effect has an unexpected field type"),
                    Self::UnknownEffectName => f.write_str("effect has an unknown effect name"),
                }
            }
        }

        fn parse_field<T: TryFrom<Value>>(
            fields: &mut alloc::collections::BTreeMap<String, Value>,
            name: &str,
        ) -> Result<T, EffectsParseError> {
            fields.remove(name)
                .ok_or(EffectsParseError::MissingField)?
                .try_into()
                .map_err(|_| EffectsParseError::FieldTypeMismatch)
        }
    };

    let effects = policy.effects.iter().map(|s| {
        let doc = format!(" {} policy effect.", s.identifier);
        let ident = format_ident!("{}", s.identifier);
        let field_names: Vec<_> = s.fields.iter().map(|f| f.identifier.as_str()).collect();
        let field_idents: Vec<_> = s
            .fields
            .iter()
            .map(|f| format_ident!("{}", f.identifier))
            .collect();
        let field_types: Vec<_> = s
            .fields
            .iter()
            .map(|f| vtype_to_rtype(&f.field_type))
            .collect();
        quote! {
            #[doc = #doc]
            #[derive(
                Clone,
                Debug,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Serialize,
                Deserialize,
            )]
            pub struct #ident {
                #(pub #field_idents: #field_types),*
            }

            impl TryFrom<Vec<KVPair>> for #ident {
                type Error = EffectsParseError;
                fn try_from(value: Vec<KVPair>) -> Result<Self, Self::Error> {
                    let fields = &mut value
                        .into_iter()
                        .map(|kv| kv.into())
                        .collect::<alloc::collections::BTreeMap<String, Value>>();
                    let parsed = Self { #(
                        #field_idents: parse_field(fields, #field_names)?,
                    )* };
                    if !fields.is_empty() {
                        return Err(EffectsParseError::ExtraFields);
                    }
                    Ok(parsed)
                }
            }
        }
    });

    let effect_enum = {
        let names: Vec<_> = policy
            .effects
            .iter()
            .map(|s| s.identifier.as_str())
            .collect();
        let idents: Vec<_> = policy
            .effects
            .iter()
            .map(|s| format_ident!("{}", s.identifier))
            .collect();
        quote! {
            #[derive(
                Clone,
                Debug,
                PartialEq,
                Eq,
                PartialOrd,
                Ord,
                Serialize,
                Deserialize,
            )]
            pub enum Effects {
                #(
                    #idents(#idents)
                ),*
            }
            impl TryFrom<(String, Vec<KVPair>)> for Effects {
                type Error = EffectsParseError;
                fn try_from((name, fields): VmEffects) -> Result<Self, Self::Error> {
                    match name.as_str() {
                        #(
                            #names => fields.try_into().map(Self::#idents),
                        )*
                        _ => Err(EffectsParseError::UnknownEffectName),
                    }
                }
            }
        }
    };

    let actions = {
        let (sigs, bodies): (Vec<_>, Vec<_>) = policy
            .actions
            .iter()
            .map(|action| {
                let name = &action.identifier;
                let ident = format_ident!("{}", name);
                let argnames = action
                    .arguments
                    .iter()
                    .map(|arg| format_ident!("{}", arg.identifier))
                    .collect::<Vec<_>>();
                let argtypes = action
                    .arguments
                    .iter()
                    .map(|arg| vtype_to_rtype(&arg.field_type));
                let argvals = if action.arguments.iter().all(|arg| is_cheap(&arg.field_type)) {
                    quote! {
                        Cow::Borrowed(&[#(Value::from(#argnames)),*])
                    }
                } else {
                    quote! {
                        Cow::Owned(vec![#(Value::from(#argnames)),*])
                    }
                };
                let sig = quote! {
                    fn #ident(&mut self, #(#argnames: #argtypes),*) -> Result<(), ClientError>
                };
                let body = quote! {
                    self.call_action((#name, #argvals))
                };
                (sig, body)
            })
            .unzip();
        quote! {
            /// Implements all supported policy actions.
            pub trait Actor {
                fn call_action(&mut self, action: VmActions<'_>) -> Result<(), ClientError>;
                #( #sigs { #bodies } )*
            }
        }
    };

    quote! {
        //! Code generated by `policy-ifgen`. DO NOT EDIT.
        #![allow(
            clippy::enum_variant_names,
            non_snake_case,
            unused_imports
        )]

        extern crate alloc;

        use alloc::{borrow::Cow, string::String, vec, vec::Vec};
        use core::fmt;

        use policy_vm::{Id, KVPair, Value};
        use runtime::{ClientError, Policy, VmPolicy};
        pub use runtime::{VmActions, VmEffects};
        use serde::{Serialize, Deserialize};

        #(#structs)*

        /// Enum of policy effects that can occur in response to a policy action.
        #effect_enum
        #(#effects)*
        #effects_parsing

        #actions
    }
}

fn vtype_to_rtype(ty: &VType) -> TokenStream {
    match ty {
        VType::String => quote! { String },
        VType::Bytes => quote! { Vec<u8> },
        VType::Int => quote! { i64 },
        VType::Bool => quote! { bool },
        VType::Id => quote! { Id },
        VType::Struct(st) => {
            let ident = format_ident!("{}", st);
            quote! { #ident }
        }
        VType::Optional(opt) => {
            let inner = vtype_to_rtype(opt);
            quote! {
                Option<#inner>
            }
        }
    }
}

fn is_cheap(ty: &VType) -> bool {
    match ty {
        VType::Int | VType::Bool | VType::Id => true,
        VType::String | VType::Bytes | VType::Struct(_) => false,
        VType::Optional(inner) => is_cheap(inner),
    }
}

fn structify<'a, N, T>(name: &str, names: N, types: T) -> TokenStream
where
    N: IntoIterator<Item = &'a str>,
    T: IntoIterator<Item = &'a VType>,
{
    let doc = format!(" {} policy struct.", name);
    let name = format_ident!("{name}");
    let names = names.into_iter().map(|n| format_ident!("{n}"));
    let types = types.into_iter().map(vtype_to_rtype);
    quote! {
        #[doc = #doc]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub struct #name {
            #(pub #names: #types),*
        }
    }
}
