use proc_macro2::{Span, TokenStream};
use quote::{quote, ToTokens};
use syn::{
    parse_quote,
    punctuated::Punctuated,
    spanned::Spanned,
    token::{Bracket, Paren},
    Expr, Ident, Token,
};

use super::{node::FnArg, types::Type};

/// `#[instrument(...)]` or `#[tracing::instrument(...)]`, etc.
#[derive(Clone, Default, Debug, Eq, PartialEq)]
pub struct Instrument {
    pub name: Option<String>,
    pub target: Option<String>,
    pub level: Option<String>,
    pub skip: Punctuated<Ident, Token![,]>,
    pub skip_all: bool,
    pub fields: Punctuated<Field, Token![,]>,
}

impl Instrument {
    /// Generates `#[instrument(...)]` from function inputs.
    pub fn from_inputs<'a, I>(capi: &Ident, inputs: I) -> Self
    where
        I: IntoIterator<Item = &'a FnArg>,
    {
        let mut instrument = Self {
            level: Some("trace".to_owned()),
            ..Default::default()
        };
        for arg in inputs {
            let span = arg.span();
            let name = &arg.name;
            let field = match &arg.ty {
                // TODO(eric): Add support for other types.
                Type::OwnedPtr(_) => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: Some(Token![%](span)),
                    value: parse_quote! {
                        #capi::internal::util::Addr::from_owned_ptr(&#name)
                    },
                },
                Type::Scalar(_) => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: None,
                    value: parse_quote!(#name),
                },
                Type::Ptr(_) => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: Some(Token![%](span)),
                    value: parse_quote! {
                        #capi::internal::util::Addr::from_ptr(#name)
                    },
                },
                Type::Ref(xref) if xref.mutability.is_some() => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: Some(Token![%](span)),
                    value: parse_quote! {
                        #capi::internal::util::Addr::from_mut(#name)
                    },
                },
                Type::Ref(xref) if xref.mutability.is_some() => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: Some(Token![%](span)),
                    value: parse_quote! {
                        #capi::internal::util::Addr::from_ref(#name)
                    },
                },
                _ => Field {
                    name: Some((name.clone(), Token![=](span))),
                    debug: None,
                    display: None,
                    value: parse_quote! {
                        ::tracing::field::Empty
                    },
                },
            };
            instrument.fields.push(field);
        }
        instrument
    }
}

impl ToTokens for Instrument {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        mod kw {
            syn::custom_keyword!(fields);
            syn::custom_keyword!(skip);
            syn::custom_keyword!(skip_all);
        }

        // TODO(eric): use a better span.
        let span = Span::call_site();
        Token![#](span).to_tokens(tokens);
        Bracket::default().surround(tokens, |tokens| {
            tokens.extend(quote!(::tracing::instrument));
            Paren::default().surround(tokens, |tokens| {
                if let Some(name) = &self.name {
                    tokens.extend(quote!(name = #name,));
                }
                if let Some(target) = &self.target {
                    tokens.extend(quote!(target = #target,));
                }
                if let Some(level) = &self.level {
                    tokens.extend(quote!(level = #level,));
                }
                if self.skip_all {
                    tokens.extend(quote!(skip_all,));
                } else if !self.skip.is_empty() {
                    tokens.extend(quote!(skip));
                    Paren::default().surround(tokens, |tokens| {
                        self.skip.to_tokens(tokens);
                    });
                    Token![,](span).to_tokens(tokens);
                }
                if !self.fields.is_empty() {
                    tokens.extend(quote!(fields));
                    Paren::default().surround(tokens, |tokens| {
                        self.fields.to_tokens(tokens);
                    });
                }
            })
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Field {
    pub name: Option<(Ident, Token![=])>,
    pub debug: Option<Token![?]>,
    pub display: Option<Token![%]>,
    pub value: Expr,
}

impl ToTokens for Field {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        if let Some((name, eq)) = &self.name {
            name.to_tokens(tokens);
            eq.to_tokens(tokens);
        }
        self.debug.to_tokens(tokens);
        self.display.to_tokens(tokens);
        self.value.to_tokens(tokens);
    }
}
