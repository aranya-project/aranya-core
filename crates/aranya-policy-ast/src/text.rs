use alloc::sync::Arc;
use core::{borrow::Borrow, fmt, str::FromStr};

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
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
enum Repr {
    #[serde(skip)]
    Static(&'static str),
    Heap(Arc<str>),
}

impl Repr {
    const fn as_str(&self) -> &str {
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid text value")]
pub struct InvalidText(());

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, thiserror::Error)]
#[error("invalid identifier value")]
pub struct InvalidIdentifier(());

// TODO: Ensure ord and hash impl matches str
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
pub struct Text(Repr);

impl<'de> serde::Deserialize<'de> for Text {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        todo!("check for nul")
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
        Ok(Self(Repr::Heap(value.into())))
    }
}

impl TryFrom<String> for Text {
    type Error = InvalidText;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.as_bytes().contains(&0) {
            return Err(InvalidText(()));
        }
        Ok(Self(Repr::Heap(value.into())))
    }
}

impl core::ops::Add for &Text {
    type Output = Text;
    fn add(self, rhs: Self) -> Self::Output {
        let s = Arc::<str>::from(self.0.as_str().to_owned() + rhs.as_str());
        Text(Repr::Heap(s))
    }
}

impl Text {
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
            i += 1;
        }
        Self(Repr::Static(lit))
    }

    pub const fn as_str(&self) -> &str {
        self.0.as_str()
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

impl TryFrom<Text> for Identifier {
    type Error = InvalidIdentifier;
    fn try_from(value: Text) -> Result<Self, Self::Error> {
        for b in value.as_str().bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                return Err(InvalidIdentifier(()));
            }
        }
        Ok(Self(value))
    }
}

impl FromStr for Identifier {
    type Err = InvalidIdentifier;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        for b in s.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                return Err(InvalidIdentifier(()));
            }
        }
        Ok(Self(Text(Repr::Heap(s.into()))))
    }
}

impl TryFrom<String> for Identifier {
    type Error = InvalidIdentifier;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        for b in s.bytes() {
            if !(b.is_ascii_alphanumeric() || b == b'_') {
                return Err(InvalidIdentifier(()));
            }
        }
        Ok(Self(Text(Repr::Heap(s.into()))))
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

#[cfg(feature = "proptest")]
mod proptest_impls {
    use proptest::prelude::*;

    use super::*;

    impl Arbitrary for Text {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            ("[^\0]+").prop_map(|s| s.try_into().unwrap()).boxed()
        }
    }

    impl Arbitrary for Identifier {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            ("[\\w_]+").prop_map(|s| s.try_into().unwrap()).boxed()
        }
    }
}
