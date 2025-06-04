use std::fmt;

use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{GenericArgument, Ident, Path, PathArguments, Type, TypePath};

/// Converts `ty` to a string, but strips out whitespace.
pub struct Trimmed<'a, T>(pub &'a T);

impl fmt::Display for Trimmed<'_, TypePath> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.qself.is_some() {
            // TODO(eric): proper qself support?
            write!(f, "<...>::")?;
        }
        write_path(f, &self.0.path)
    }
}

impl fmt::Display for Trimmed<'_, Path> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_path(f, self.0)
    }
}

impl fmt::Display for Trimmed<'_, Ident> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_path(f, &self.0.clone().into())
    }
}

fn write_path(f: &mut fmt::Formatter<'_>, path: &Path) -> fmt::Result {
    write!(f, "\"")?;
    if path.leading_colon.is_some() {
        write!(f, "::")?;
    }
    for pair in path.segments.pairs() {
        let seg = pair.value();
        write!(f, "{}", seg.ident)?;
        match &seg.arguments {
            PathArguments::None => {}
            PathArguments::AngleBracketed(args) => {
                write!(f, "<")?;
                for arg in &args.args {
                    match &arg {
                        GenericArgument::Type(ty) => write_type(f, ty)?,
                        GenericArgument::Lifetime(lt) => write!(f, "'{}", lt.ident)?,
                        _ => write!(f, "???")?,
                    }
                }
                write!(f, ">")?;
            }
            PathArguments::Parenthesized(_) => {
                unreachable!("Parenthesized")
            }
        }
        if pair.punct().is_some() {
            write!(f, "::")?;
        }
    }
    write!(f, "\"")
}

fn write_type(f: &mut fmt::Formatter<'_>, ty: &Type) -> fmt::Result {
    let mut code = quote!(const _: #ty = ();).to_string();
    if let Ok(file) = syn::parse_file(&code) {
        code = prettyplease::unparse(&file);
    }
    let code = code
        .trim()
        .strip_prefix("const _: ")
        .unwrap_or(&code)
        .strip_suffix(" = ();")
        .unwrap_or(&code);

    let mut space = false;
    for c in code.chars() {
        if c == '\n' || c == '\t' {
            continue;
        }
        if c.is_whitespace() {
            if !space {
                write!(f, " ")?;
                space = true;
            }
        } else {
            write!(f, "{c}")?;
            space = false;
        }
    }
    Ok(())
}

#[allow(dead_code)] // TODO
pub(super) struct Quote<'a, T>(pub &'a T);

impl<T: ToTokens> fmt::Display for Quote<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let v = &self.0;
        write!(f, "\"{}\"", quote!(#v))
    }
}

/// Ensures that `Option<T: ToTokens>` still prints the token.
pub(super) struct TokensOrDefault<'a, T>(pub &'a Option<T>);

impl<T> ToTokens for TokensOrDefault<'_, T>
where
    T: ToTokens + Default,
{
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self.0 {
            Some(t) => t.to_tokens(tokens),
            None => T::default().to_tokens(tokens),
        }
    }
}
