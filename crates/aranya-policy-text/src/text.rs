use alloc::string::String;
use core::{
    ffi::CStr,
    fmt,
    ops::{Add, Deref},
    str::FromStr,
};

use serde::de;

use crate::{
    error::{InvalidText, InvalidTextRepr},
    repr::Repr,
};

/// A string-like value which is utf8 without nul bytes.
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Text(pub(crate) Repr);

/// Creates a `Text` from a string literal.
///
/// Fails at compile time for invalid values.
#[macro_export]
macro_rules! text {
    () => {
        $crate::Text::new()
    };
    ($($e:tt)+) => {
        // SAFETY: `validate_text` validates `Text`'s requirements.
        unsafe {
            $crate::Text::__from_literal($crate::__hidden::validate_text!($($e)+))
        }
    };
}

impl Text {
    pub(crate) fn validate(s: &str) -> Result<(), InvalidText> {
        if let Some(index) = s.bytes().position(|b| b == 0) {
            return Err(InvalidText(InvalidTextRepr::ContainsNul { index }));
        }
        Ok(())
    }

    /// Creates an empty text.
    pub const fn new() -> Self {
        Self(Repr::empty())
    }

    /// SAFETY: The string must meet `Text`'s requirements.
    #[doc(hidden)]
    pub const unsafe fn __from_literal(lit: &'static str) -> Self {
        Self(Repr::from_static(lit))
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
        Ok(Self(Repr::from_str(value)))
    }
}

impl TryFrom<String> for Text {
    type Error = InvalidText;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().parse()
    }
}

impl TryFrom<&CStr> for Text {
    type Error = core::str::Utf8Error;
    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        let s: &str = value.to_str()?;
        // NB: CStr cannot contain nul.
        Ok(Self(Repr::from_str(s)))
    }
}

impl Add for &Text {
    type Output = Text;
    fn add(self, rhs: Self) -> Self::Output {
        let mut s = String::from(self.0.as_str());
        s.push_str(rhs.as_str());
        debug_assert!(
            Text::validate(&s).is_ok(),
            "text should stay valid under concatenation"
        );
        Text(Repr::from_str(&s))
    }
}

impl serde::Serialize for Text {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let r = Repr::deserialize(deserializer)?;
        Self::validate(r.as_str()).map_err(|_| {
            de::Error::invalid_value(de::Unexpected::Str(r.as_str()), &"no nul bytes")
        })?;
        Ok(Self(r))
    }
}

impl Deref for Text {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl<T> AsRef<T> for Text
where
    T: ?Sized,
    <Text as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}
