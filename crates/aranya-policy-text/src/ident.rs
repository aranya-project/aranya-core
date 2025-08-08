use alloc::string::String;
use core::{borrow::Borrow, fmt, num::NonZeroUsize, str::FromStr};

use serde::de;

use crate::{
    error::{InvalidIdentifier, InvalidIdentifierRepr},
    repr::Repr,
    Text,
};

/// A textual identifier which matches `[a-zA-Z][a-zA-Z0-9_]*`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Identifier(Text);

/// Creates an `Identifier` from a string literal.
///
/// Fails at compile time for invalid values.
#[macro_export]
macro_rules! ident {
    ($($e:tt)+) => {
        // SAFETY: `validate_identifier` validates `Identifier`'s requirements.
        unsafe {
            $crate::Identifier::__from_literal($crate::__hidden::validate_identifier!($($e)+))
        }
    };
}

impl Identifier {
    fn validate(s: &str) -> Result<(), InvalidIdentifier> {
        if s.is_empty() {
            return Err(InvalidIdentifier(InvalidIdentifierRepr::NotEmpty));
        }
        for (i, b) in s.bytes().enumerate() {
            // Check tail characters
            if let Some(index) = NonZeroUsize::new(i) {
                if !(b.is_ascii_alphanumeric() || b == b'_') {
                    return Err(InvalidIdentifier(InvalidIdentifierRepr::TrailingNotValid {
                        index,
                    }));
                }
            // Check first character
            } else if !b.is_ascii_alphabetic() {
                return Err(InvalidIdentifier(
                    InvalidIdentifierRepr::InitialNotAlphabetic,
                ));
            }
        }
        debug_assert!(Text::validate(s).is_ok(), "identifiers are valid text");
        Ok(())
    }

    /// SAFETY: The string must meet `Identifier`'s requirements.
    #[doc(hidden)]
    pub const unsafe fn __from_literal(lit: &'static str) -> Self {
        // SAFETY: Valid identifiers are valid text.
        unsafe { Self(Text::__from_literal(lit)) }
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
        Ok(Self(Text(Repr::from_str(s))))
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

impl serde::Serialize for Identifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> de::Deserialize<'de> for Identifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let r = Repr::deserialize(deserializer)?;
        Self::validate(r.as_str()).map_err(|_| {
            de::Error::invalid_value(
                de::Unexpected::Str(r.as_str()),
                &"must match `[a-zA-Z][a-zA-Z0-9_]*`",
            )
        })?;
        Ok(Self(Text(r)))
    }
}
