use std::collections::{HashMap, HashSet};

use aranya_policy_ast::{FieldDefinition, Policy, VType};
use proc_macro2::{Span, TokenStream};
use quote::quote;

/// Generate rust source code from a [`Policy`] AST.
pub fn generate_code(policy: &Policy) -> String {
    let reachable = collect_reachable_types(policy);

    let structs = policy
        .structs
        .iter()
        .filter(|s| reachable.contains(s.identifier.as_str()))
        .map(|s| {
            let doc = format!(" {} policy struct.", s.identifier);
            let name = mk_ident(&s.identifier);
            let names = s.fields.iter().map(|f| mk_ident(&f.identifier));
            let types = s.fields.iter().map(|f| vtype_to_rtype(&f.field_type));
            quote! {
                #[doc = #doc]
                #[value]
                pub struct #name {
                    #(pub #names: #types),*
                }
            }
        });

    let enums = policy
        .enums
        .iter()
        .filter(|e| reachable.contains(e.identifier.as_str()))
        .map(|e| {
            let doc = format!(" {} policy enum.", e.identifier);
            let name = mk_ident(&e.identifier);
            let names = e.values.iter().map(|v| mk_ident(v));
            quote! {
                #[doc = #doc]
                #[value]
                pub enum #name {
                    #(#names),*
                }
            }
        });

    let effects = policy.effects.iter().map(|s| {
        let doc = format!(" {} policy effect.", s.identifier);
        let ident = mk_ident(&s.identifier);
        let field_idents = s.fields.iter().map(|f| mk_ident(&f.identifier));
        let field_types = s.fields.iter().map(|f| vtype_to_rtype(&f.field_type));
        quote! {
            #[doc = #doc]
            #[effect]
            pub struct #ident {
                #(pub #field_idents: #field_types),*
            }
        }
    });

    let effect_enum = {
        let idents = policy.effects.iter().map(|s| mk_ident(&s.identifier));
        quote! {
            #[effects]
            pub enum Effect {
                #(
                    #idents(#idents)
                ),*
            }
        }
    };

    let actions = {
        let sigs = policy.actions.iter().map(|action| {
            let ident = mk_ident(&action.identifier);
            let argnames = action.arguments.iter().map(|arg| mk_ident(&arg.identifier));
            let argtypes = action
                .arguments
                .iter()
                .map(|arg| vtype_to_rtype(&arg.field_type));
            quote! {
                fn #ident(&mut self, #(#argnames: #argtypes),*) -> Result<(), ClientError>;
            }
        });
        quote! {
            /// Implements all supported policy actions.
            #[actions]
            pub trait ActorExt {
                #( #sigs )*
            }
        }
    };

    prettyplease::unparse(&syn::parse_quote! {
        //! This code is @generated by `policy-ifgen`. DO NOT EDIT.
        #![allow(clippy::duplicated_attributes)]
        #![allow(clippy::enum_variant_names)]
        #![allow(missing_docs)]
        #![allow(non_snake_case)]
        #![allow(unused_imports)]

        extern crate alloc;

        use alloc::{string::String, vec::Vec};

        use aranya_policy_ifgen::{
            macros::{actions, effect, effects, value},
            ClientError, Id, Value,
        };

        #(#structs)*
        #(#enums)*

        /// Enum of policy effects that can occur in response to a policy action.
        #effect_enum
        #(#effects)*

        #actions
    })
}

fn vtype_to_rtype(ty: &VType) -> TokenStream {
    match ty {
        VType::String => quote! { String },
        VType::Bytes => quote! { Vec<u8> },
        VType::Int => quote! { i64 },
        VType::Bool => quote! { bool },
        VType::Id => quote! { Id },
        VType::Struct(st) => {
            let ident = mk_ident(st);
            quote! { #ident }
        }
        VType::Enum(st) => {
            let ident = mk_ident(st);
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

/// Returns the name of all custom types reachable from actions or effects.
fn collect_reachable_types(policy: &Policy) -> HashSet<&str> {
    fn visit<'a>(
        struct_defs: &HashMap<&str, &'a [FieldDefinition]>,
        found: &mut HashSet<&'a str>,
        ty: &'a VType,
    ) {
        match ty {
            VType::Struct(s) => {
                if found.insert(s.as_str()) {
                    for field in struct_defs[s.as_str()] {
                        visit(struct_defs, found, &field.field_type);
                    }
                }
            }
            VType::Enum(s) => {
                found.insert(s.as_str());
            }
            VType::Optional(inner) => visit(struct_defs, found, inner),
            _ => {}
        }
    }

    let struct_defs = policy
        .structs
        .iter()
        .map(|s| (s.identifier.as_str(), s.fields.as_slice()))
        .collect::<HashMap<_, _>>();

    let mut found = HashSet::new();

    for action in &policy.actions {
        for arg in &action.arguments {
            visit(&struct_defs, &mut found, &arg.field_type);
        }
    }

    for effect in &policy.effects {
        for field in &effect.fields {
            visit(&struct_defs, &mut found, &field.field_type);
        }
    }

    found
}

/// Makes an identifier from a string, using raw identifiers (`r#mod`) when necessary.
fn mk_ident(string: &str) -> syn::Ident {
    syn::parse_str::<syn::Ident>(string)
        .unwrap_or_else(|_| syn::Ident::new_raw(string, Span::call_site()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mk_ident() {
        assert_eq!(mk_ident("foo").to_string(), "foo");
        assert_eq!(mk_ident("mod").to_string(), "r#mod");
    }
}
