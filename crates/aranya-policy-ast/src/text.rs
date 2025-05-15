#![warn(clippy::undocumented_unsafe_blocks)]

use alloc::string::String;
use core::{borrow::Borrow, fmt, num::NonZeroUsize, str::FromStr};

use serde::de;

mod imp;

/// Not a valid `Text` value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid text value")]
pub enum InvalidText {
    /// Text contained nul byte.
    #[error("text contained nul byte at index {index}")]
    ContainsNul {
        /// Index of first nul byte.
        index: usize,
    },
}

/// Not a valid `Identifier` value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid identifier value")]
pub enum InvalidIdentifier {
    /// Identifier must start with alphabetic character.
    #[error("identifier must start with alphabetic character")]
    InitialNotAlphabetic,
    /// Identifier contained invalid character.
    #[error("identifier contained invalid character at index {index}")]
    TrailingNotValid {
        /// Index of first invalid character.
        index: NonZeroUsize,
    },
}

/// A string-like value which is utf8 without nul bytes.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct Text(imp::Repr);

/// Creates a `Text` from a string literal.
///
/// Fails at compile time for invalid values.
#[macro_export]
macro_rules! text {
    ($lit:literal) => {
        const { $crate::Text::__from_literal($lit) }
    };
}

impl Text {
    fn validate(s: &str) -> Result<(), InvalidText> {
        if let Some(index) = s.bytes().position(|b| b == 0) {
            return Err(InvalidText::ContainsNul { index });
        }
        Ok(())
    }

    #[doc(hidden)]
    pub const fn __from_literal(lit: &'static str) -> Self {
        let bytes = lit.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0 {
                panic!("text contained nul byte")
            }
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "string cannot be that large"
            )]
            {
                i += 1;
            }
        }
        Self(imp::Repr::from_static(lit))
    }

    /// Compare two text values for equality.
    ///
    /// Like `Eq` but `const`.
    pub const fn const_eq(&self, other: &Self) -> bool {
        let lhs = self.0.as_str().as_bytes();
        let rhs = other.0.as_str().as_bytes();
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

    /// Extracts a string slice containing the entire text.
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_str().fmt(f)
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_str().fmt(f)
    }
}

impl PartialEq<str> for Text {
    fn eq(&self, other: &str) -> bool {
        self.0.as_str().eq(other)
    }
}
impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0.as_str().eq(*other)
    }
}

impl FromStr for Text {
    type Err = InvalidText;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::validate(value)?;
        Ok(Self(imp::Repr::from_str(value)))
    }
}

impl TryFrom<String> for Text {
    type Error = InvalidText;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl core::ops::Add for &Text {
    type Output = Text;
    fn add(self, rhs: Self) -> Self::Output {
        let mut s = String::from(self.0.as_str());
        s.push_str(rhs.as_str());
        Text(imp::Repr::from_str(&s))
    }
}

impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let r = imp::Repr::deserialize(deserializer)?;
        Self::validate(r.as_str()).map_err(|_| {
            de::Error::invalid_value(de::Unexpected::Str(r.as_str()), &"no nul bytes")
        })?;
        Ok(Self(r))
    }
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
/// A textual identifier which matches `[a-zA-Z][a-zA-Z0-9_]*`.
pub struct Identifier(Text);

/// Creates an `Identifier` from a string literal.
///
/// Fails at compile time for invalid values.
#[macro_export]
macro_rules! ident {
    ($lit:literal) => {
        const { $crate::Identifier::__from_literal($lit) }
    };
    // hacky
    (stringify!($ident:ident)) => {
        const { $crate::Identifier::__from_literal(stringify!($ident)) }
    };
}

impl Identifier {
    fn validate(s: &str) -> Result<(), InvalidIdentifier> {
        for (i, b) in s.bytes().enumerate() {
            // Check tail characters
            if let Some(index) = NonZeroUsize::new(i) {
                if !(b.is_ascii_alphanumeric() || b == b'_') {
                    return Err(InvalidIdentifier::TrailingNotValid { index });
                }
            // Check first character
            } else if !b.is_ascii_alphabetic() {
                return Err(InvalidIdentifier::InitialNotAlphabetic);
            }
        }
        Ok(())
    }

    #[doc(hidden)]
    pub const fn __from_literal(lit: &'static str) -> Self {
        let bytes = lit.as_bytes();
        if !bytes[0].is_ascii_alphabetic() {
            panic!("must start with alphabetic")
        }
        let mut i = 1;
        while i < bytes.len() {
            if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                panic!("must be alphanumeric or '_'")
            }
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "string cannot be that large"
            )]
            {
                i += 1;
            }
        }
        Self(Text::__from_literal(lit))
    }

    /// Compare two identifiers for equality.
    ///
    /// Like `Eq` but `const`.
    pub const fn const_eq(&self, other: &Self) -> bool {
        self.0.const_eq(&other.0)
    }

    /// Extracts a string slice containing the entire identifier.
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for Identifier {
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

impl TryFrom<Text> for Identifier {
    type Error = InvalidIdentifier;
    fn try_from(value: Text) -> Result<Self, Self::Error> {
        Self::validate(value.as_str())?;
        Ok(Self(value))
    }
}

impl FromStr for Identifier {
    type Err = InvalidIdentifier;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::validate(s)?;
        Ok(Self(Text(imp::Repr::from_str(s))))
    }
}

impl TryFrom<String> for Identifier {
    type Error = InvalidIdentifier;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().parse()
    }
}

impl AsRef<str> for Identifier {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for Identifier {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<'de> de::Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let r = imp::Repr::deserialize(deserializer)?;
        Self::validate(r.as_str()).map_err(|_| {
            de::Error::invalid_value(
                de::Unexpected::Str(r.as_str()),
                &"must match `[a-zA-Z][a-zA-Z0-9_]*`",
            )
        })?;
        Ok(Self(Text(r)))
    }
}

#[cfg(feature = "proptest")]
mod proptest_impls {
    use proptest::prelude::*;

    use super::{Identifier, Text};

    impl Arbitrary for Text {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            ("[^\0]+")
                .prop_map(|s| s.try_into().expect("regex produces valid text"))
                .boxed()
        }
    }

    impl Arbitrary for Identifier {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            ("[a-zA-Z][a-zA-Z0-9_]*")
                .prop_map(|s| s.try_into().expect("regex produces valid identifiers"))
                .boxed()
        }
    }
}
