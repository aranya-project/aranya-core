use proc_macro2::TokenStream;
use quote::quote;
use syn::{spanned::Spanned, FnArg, Ident, ItemTrait, Pat, Signature, TraitItem};

pub(super) fn parse(_attr: TokenStream, item: TokenStream) -> syn::Result<TokenStream> {
    let act: ItemTrait = syn::parse2(item)?;

    let ident = &act.ident;

    let methods = act
        .items
        .iter()
        .map(|item| {
            let TraitItem::Fn(func) = item else {
                return Err(syn::Error::new(item.span(), "unexpected item in trait"));
            };

            let sig = &func.sig;
            let action_ident = &sig.ident;
            let arg_idents = get_args(sig)?;

            Ok(quote! {
                #sig {
                    self.call_action(::aranya_policy_ifgen::vm_action! {
                        #action_ident( #(#arg_idents),* )
                    })
                }
            })
        })
        .collect::<syn::Result<TokenStream>>()?;

    Ok(quote! {
        #act

        impl<A: ::aranya_policy_ifgen::Actor> #ident for A {
            #methods
        }
    })
}

fn get_args(sig: &Signature) -> syn::Result<Vec<&Ident>> {
    let mut iter = sig.inputs.iter();
    match iter.next() {
        Some(FnArg::Receiver(_)) => {}
        Some(FnArg::Typed(typed)) => {
            return Err(syn::Error::new(typed.span(), "expected receiver"))
        }
        None => return Err(syn::Error::new(sig.span(), "expected receiver")),
    }
    iter.map(|arg| {
        let FnArg::Typed(typed) = arg else {
            return Err(syn::Error::new(arg.span(), "unexpected receiver"));
        };
        let Pat::Ident(ident) = typed.pat.as_ref() else {
            return Err(syn::Error::new(typed.span(), "expected identifier"));
        };
        Ok(&ident.ident)
    })
    .collect()
}
