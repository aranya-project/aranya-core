#![cfg_attr(docsrs, doc(cfg(feature = "spira")))]
#![cfg(feature = "spira")]

use std::ops::Deref;

use log::debug;
use proc_macro2::TokenStream;
use quote::quote;
use syn::{
    bracketed,
    parse::{Parse, ParseStream, Result},
    Attribute, ItemFn, LitInt, ReturnType, Token,
};

/// See the documentation in the `rtrack` crate.
pub(crate) fn parse(attr: TokenStream, item: TokenStream) -> TokenStream {
    debug!("attr = {}", attr);
    debug!("item = {}", item);

    let Spira { project_id, tests } = match syn::parse2(attr) {
        Ok(t) => t,
        Err(err) => return err.into_compile_error(),
    };

    let f: ItemFn = match syn::parse2(item) {
        Ok(f) => f,
        Err(err) => return err.into_compile_error(),
    };
    let should_panic = f.attrs.iter().any(|a| {
        a.meta
            .path()
            .get_ident()
            .is_some_and(|v| *v == "should_panic")
    });
    let test_name = f.sig.ident.to_string();
    let name = f.sig.ident;
    let vis = f.vis;
    let block = f.block;
    let attrs: Vec<Attribute> = f.attrs.into_iter().collect();

    match f.sig.output {
        ReturnType::Default => {
            quote! {
                #(#attrs)
                *
                #vis fn #name () {
                    const TEST: ::rtrack::spira::Test = ::rtrack::spira::Test {
                        name: #test_name,
                        project_id: #project_id,
                        tests: &[#(#tests),*],
                        should_panic: #should_panic,
                    };
                    fn inner() {
                        #block
                    }
                    ::rtrack::spira::run_test_unit(&TEST, inner)
                }
            }
        }
        ReturnType::Type(_, ref v) => {
            let ret = v.deref();
            quote! {
                #(#attrs)
                *
                #vis fn #name () -> #ret {
                    const TEST: ::rtrack::spira::Test = ::rtrack::spira::Test {
                        name: #test_name,
                        project_id: #project_id,
                        tests: &[#(#tests),*],
                        should_panic: #should_panic,
                    };
                    fn inner() -> #ret {
                        #block
                    }
                    ::rtrack::spira::run_test_result(&TEST, inner)
                }
            }
        }
    }
}

mod kw {
    syn::custom_keyword!(project_id);
    syn::custom_keyword!(test_cases);
}

/// A tracked project.
#[derive(Clone, Debug)]
pub(crate) struct Spira {
    /// The project's ID.
    project_id: i32,
    /// The project tests that this test covers.
    tests: Vec<i32>,
}

impl Parse for Spira {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        // Parses `project_id = 4` with an optional trailing
        // comma.`
        let project_id = {
            let _ = input.parse::<kw::project_id>()?;
            let _: Token![=] = input.parse()?;
            let id: LitInt = input.parse()?;
            skip_comma(input)?;
            id.base10_parse::<i32>()?
        };
        // Parses `test_cases = [1, 2, 3]` with an optional
        // trailing comma.
        let tests = {
            let _ = input.parse::<kw::test_cases>()?;
            let _: Token![=] = input.parse()?;
            let tests: I32Array = input.parse()?;
            skip_comma(input)?;
            tests.0
        };
        Ok(Self { project_id, tests })
    }
}

/// Skips the next token if it's a comma.
fn skip_comma(input: ParseStream<'_>) -> Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}

/// Parses `[1, 2, 3]`, etc.
#[derive(Clone)]
struct I32Array(Vec<i32>);

impl Parse for I32Array {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let content;
        let _ = bracketed!(content in input);
        let mut elems = Vec::new();

        while !content.is_empty() {
            let lit: LitInt = content.parse()?;
            let value = lit.base10_parse::<i32>()?;
            elems.push(value);
            if content.is_empty() {
                break;
            }
            let _: Token![,] = content.parse()?;
        }

        Ok(I32Array(elems))
    }
}
