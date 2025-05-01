use alloc::borrow::Cow;
use core::{fmt, str::FromStr};

// I plan to move to using a smart string type roughly like
// enum {
//     Static(&'static str),
//     Stack([u8; 16]),
//     Heap(Arc<str>),
// }
//
// This makes sense for identifiers and I guess text too?
//
// We can intern during compilation and then use a serializer which handles arc pooling.
//
// This is worse than doing manual string pooling but it's also easier...

const fn cow_str_as_bytes<'a>(cow: &'a Cow<'a, str>) -> &'a [u8] {
    match cow {
        Cow::Borrowed(x) => x.as_bytes(),
        Cow::Owned(_) => panic!("wow why is this not const"),
    }
}

// TODO: Better repr than cow
// TODO: Deserialize check for nul
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct Text(Cow<'static, str>);

impl PartialEq<str> for Text {
    fn eq(&self, other: &str) -> bool {
        self.0.eq(other)
    }
}
impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq(other)
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<String> for Text {
    type Error = ();
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.as_bytes().contains(&0) {
            return Err(());
        }
        Ok(Self(value.into()))
    }
}

impl Text {
    pub const fn const_eq(&self, other: &Self) -> bool {
        let lhs = cow_str_as_bytes(&self.0);
        let rhs = cow_str_as_bytes(&other.0);
        if lhs.len() != rhs.len() {
            return false;
        }
        let mut i = 0;
        while i < lhs.len() && i < rhs.len() {
            if lhs[i] != rhs[i] {
                return false;
            }
            // Cannot overflow or wrap since `i` is
            // `usize` and `<[_]>::len()` is at most
            // `isize::MAX`.
            #[allow(clippy::arithmetic_side_effects)]
            {
                i += 1;
            }
        }
        true
    }

    #[doc(hidden)]
    pub const fn __from_literal(lit: &'static str) -> Self {
        let bytes = lit.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0 {
                panic!()
            }
            i += 1;
        }
        Self(Cow::Borrowed(lit))
    }
}

#[macro_export]
macro_rules! text {
    ($lit:literal) => {
        const { $crate::Text::__from_literal($lit) }
    };
}

// TODO: Deserialize check
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "proptest", derive(proptest_derive::Arbitrary))]
pub struct Identifier(Text);

impl Identifier {
    pub const fn const_eq(&self, other: &Self) -> bool {
        self.0.const_eq(&other.0)
    }

    #[doc(hidden)]
    pub const fn __from_literal(lit: &'static str) -> Self {
        let bytes = lit.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                panic!()
            }
            i += 1;
        }
        Self(Text::__from_literal(lit))
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// identifiers are more strict than text
impl From<Identifier> for Text {
    fn from(value: Identifier) -> Self {
        value.0
    }
}

impl PartialEq<str> for Identifier {
    fn eq(&self, other: &str) -> bool {
        self.0.eq(other)
    }
}
impl PartialEq<&str> for Identifier {
    fn eq(&self, other: &&str) -> bool {
        self.0.eq(other)
    }
}

#[macro_export]
macro_rules! ident {
    ($lit:literal) => {
        const { $crate::Identifier::__from_literal($lit) }
    };
}

impl FromStr for Identifier {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

impl quote::ToTokens for Identifier {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0 .0.as_ref().to_tokens(tokens);
    }
}
