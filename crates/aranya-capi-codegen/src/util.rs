use quote::{format_ident, IdentFragment};
use syn::{
    parse::{Parse, ParseStream},
    Ident, Path, PathSegment, Result, Token,
};

macro_rules! parse_doc {
    ($($arg:tt)*) => {{
        let doc = ::std::format!($($arg)*);
        let mut tokens = ::proc_macro2::TokenStream::new();
        for frag in doc.trim().split("\n") {
            let frag = frag
                .strip_prefix("///")
                .unwrap_or(&frag);
            tokens.extend(::quote::quote! {
                #[doc = #frag]
            })
        }
        tokens
    }};
}
pub(crate) use parse_doc;

/// Skips the next token if it's a comma.
pub fn skip_comma(input: ParseStream<'_>) -> Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}

/// Extension trait for [`Path`].
pub trait PathExt {
    /// Joins the two paths.
    #[must_use]
    fn join<S>(&self, seg: S) -> Self
    where
        S: Into<PathSegment>;

    /// Returns the last [`Ident`] in the path.
    fn ty_name(&self) -> &Ident;
}

impl PathExt for Path {
    fn join<S>(&self, seg: S) -> Self
    where
        S: Into<PathSegment>,
    {
        let mut path = self.clone();
        path.segments.push(seg.into());
        path
    }

    /// Returns the last [`Ident`] in the path.
    #[allow(clippy::arithmetic_side_effects)]
    fn ty_name(&self) -> &Ident {
        &self.segments[self.segments.len() - 1].ident
    }
}

/// Extension trait for [`struct@Ident`].
pub trait IdentExt {
    /// Adds `prefix` to the identifier.
    #[must_use]
    fn with_prefix<I>(&self, prefix: I) -> Self
    where
        I: IdentFragment;

    /// Adds `suffix` to the identifier.
    #[must_use]
    fn with_suffix<I>(&self, suffix: I) -> Self
    where
        I: IdentFragment;

    /// Converts the identifier to snake_case.
    fn to_snake_case(&self) -> Self;

    /// Converts the identifier to SCREAMING_SNAKE_CASE.
    fn to_screaming_snake_case(&self) -> Self;
}

impl IdentExt for Ident {
    fn with_prefix<I>(&self, prefix: I) -> Self
    where
        I: IdentFragment,
    {
        format_ident!("{}{}", prefix, self, span = self.span())
    }

    fn with_suffix<I>(&self, suffix: I) -> Self
    where
        I: IdentFragment,
    {
        format_ident!("{}{}", self, suffix, span = self.span())
    }

    fn to_snake_case(&self) -> Ident {
        let mut new = String::new();
        let mut in_word = false;
        for c in self.to_string().chars() {
            if c.is_uppercase() {
                if in_word {
                    new.push('_');
                }
                in_word = true;
                new.extend(c.to_lowercase());
            } else {
                new.push(c);
            }
        }
        Ident::new(&new, self.span())
    }

    fn to_screaming_snake_case(&self) -> Ident {
        let mut new = String::new();
        let mut in_word = false;
        for c in self.to_string().chars() {
            if c.is_uppercase() {
                if in_word {
                    new.push('_');
                }
                in_word = true;
            }
            new.extend(c.to_uppercase());
        }
        Ident::new(&new, self.span())
    }
}

/// A key-value pair.
pub struct KeyValPair<K, V> {
    pub key: K,
    pub val: V,
}

impl<K, V> Parse for KeyValPair<K, V>
where
    K: Parse,
    V: Parse,
{
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let key = input.parse()?;
        let _: Token![=] = input.parse()?;
        let val = input.parse()?;
        skip_comma(input)?;
        Ok(Self { key, val })
    }
}

#[cfg(test)]
mod tests {
    use proc_macro2::Span;
    use syn::Ident;

    use super::*;

    #[test]
    fn test_ident_with_prefix() {
        let tests = [
            ("SomeType", "OsSomeType", format_ident!("Os")),
            ("some_func", "os_some_func", format_ident!("os_")),
        ];
        for (i, (input, want, prefix)) in tests.into_iter().enumerate() {
            let orig = Ident::new(input, Span::call_site());
            let got = orig.with_prefix(&prefix);
            let want = Ident::new(want, Span::call_site());
            assert_eq!(got, want, "#{i}");

            let got = got.to_string();
            let got = got.strip_prefix(&prefix.to_string()).unwrap();
            assert_eq!(got, orig.to_string(), "#{i}");
        }
    }

    #[test]
    fn test_ident_with_suffix() {
        let tests = [
            ("os_some_func", "os_some_func_ext", format_ident!("_ext")),
            ("os_some_func", "os_some_func_v2_1", format_ident!("_v2_1")),
        ];
        for (i, (input, want, suffix)) in tests.into_iter().enumerate() {
            let got = Ident::new(input, Span::call_site()).with_suffix(suffix);
            let want = Ident::new(want, Span::call_site());
            assert_eq!(got, want, "#{i}");
        }
    }

    #[test]
    fn test_ident_to_snake_case() {
        let tests = [
            ("ABCD", "a_b_c_d"),
            ("OsFoo", "os_foo"),
            ("OsFooInit", "os_foo_init"),
        ];
        for (i, (input, want)) in tests.into_iter().enumerate() {
            let got = Ident::new(input, Span::call_site()).to_snake_case();
            let want = Ident::new(want, Span::call_site());
            assert_eq!(got, want, "#{i}");
        }
    }
}
