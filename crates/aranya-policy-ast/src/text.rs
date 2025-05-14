use core::{borrow::Borrow, fmt, str::FromStr};

use serde::de;

mod imp {
    use alloc::sync::Arc;

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

    // TODO: Better repr
    #[derive(Clone)]
    pub enum Repr {
        Static(&'static str),
        Heap(Arc<str>),
    }

    impl Repr {
        pub const fn from_static(s: &'static str) -> Self {
            Self::Static(s)
        }

        pub fn from_str(s: &str) -> Self {
            // TODO: stack variant
            Self::Heap(s.into())
        }

        pub const fn as_str(&self) -> &str {
            match self {
                Repr::Static(s) => s,
                Repr::Heap(s) => {
                    // TODO(jdygert): yuck

                    #[repr(C)]
                    struct ArcInner<T: ?Sized> {
                        strong: core::sync::atomic::AtomicUsize,
                        weak: core::sync::atomic::AtomicUsize,
                        data: T,
                    }

                    let inner =
                        unsafe { &**core::mem::transmute::<&Arc<str>, &*const ArcInner<str>>(s) };

                    &inner.data
                }
            }
        }
    }

    impl Default for Repr {
        fn default() -> Self {
            Self::Static("")
        }
    }

    impl core::fmt::Debug for Repr {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            self.as_str().fmt(f)
        }
    }

    impl PartialEq for Repr {
        fn eq(&self, other: &Self) -> bool {
            self.as_str().eq(other.as_str())
        }
    }

    impl Eq for Repr {}

    impl PartialOrd for Repr {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Ord for Repr {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.as_str().cmp(other.as_str())
        }
    }

    impl core::hash::Hash for Repr {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_str().hash(state)
        }
    }

    impl<'de> serde::Deserialize<'de> for Repr {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            // no arc pooling for serde :(
            let s = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
            Ok(Self::from_str(&s))
        }
    }

    impl serde::Serialize for Repr {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            self.as_str().serialize(serializer)
        }
    }
}

/// Not a valid `Text` value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid text value")]
pub struct InvalidText(());

/// Not a valid `Identifier` value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid identifier value")]
pub struct InvalidIdentifier(());

/// A string-like value which is utf8 without nul bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct Text(imp::Repr);

impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let r = imp::Repr::deserialize(deserializer)?;
        if r.as_str().contains('\0') {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(r.as_str()),
                &"no nul bytes",
            ));
        }
        Ok(Self(r))
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

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.as_str().fmt(f)
    }
}

impl FromStr for Text {
    type Err = InvalidText;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.as_bytes().contains(&0) {
            return Err(InvalidText(()));
        }
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
        let s = self.0.as_str().to_owned() + rhs.as_str();
        Text(imp::Repr::from_str(&s))
    }
}

impl Text {
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

    #[doc(hidden)]
    pub const fn __from_literal(lit: &'static str) -> Self {
        let bytes = lit.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == 0 {
                panic!()
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

    /// Extracts a string slice containing the entire text.
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Creates a `Text` from a string literal.
///
/// Fails at compile time for invalid values.
#[macro_export]
macro_rules! text {
    ($lit:literal) => {
        const { $crate::Text::__from_literal($lit) }
    };
}

// TODO: Deserialize check
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
/// A textual identifier which matches `[a-zA-Z][a-zA-Z0-9_]*`.
pub struct Identifier(Text);

impl Identifier {
    /// Compare two identifiers for equality.
    ///
    /// Like `Eq` but `const`.
    pub const fn const_eq(&self, other: &Self) -> bool {
        self.0.const_eq(&other.0)
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
        if !s
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic())
        {
            return Err(InvalidIdentifier(()));
        }
        for b in s.bytes().skip(1) {
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                return Err(InvalidIdentifier(()));
            }
        }
        Ok(())
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

impl quote::ToTokens for Identifier {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        self.0.as_str().to_tokens(tokens);
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
