#![forbid(unsafe_code)]

use {
    crate::{
        ciphersuite::SuiteIds,
        engine::Engine,
        groupkey::GroupKeyId,
        hash::tuple_hash,
        mac::Tag,
        userkeys::{EncryptionKeyId, Signature, SigningKeyId, UserId},
    },
    base58::{String64, ToBase58},
    core::{
        borrow::Borrow,
        fmt::{self, Debug, Display},
    },
    serde::{
        de::{self, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserialize, Deserializer, Serialize, Serializer,
    },
};

/// A unique cryptographic ID.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Id([u8; 64]);

impl Id {
    /// Derives an [`Id`] from the hash of some data.
    pub fn new<E: Engine + ?Sized>(data: &[u8], tag: &'static str) -> Id {
        // id = H("ID-v1" || eng_id || suites || data || tag)
        tuple_hash::<E::Hash, _>([
            "ID-v1".as_bytes(),
            E::ID.as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            data,
            tag.as_bytes(),
        ])
        .into()
    }

    /// Derives an [`Id`] from `msg` and a signature over `msg`.
    pub fn from_sig<E: Engine + ?Sized>(msg: &[u8], sig: &Signature<E>) -> Id {
        // id = H("ID-v1" || eng_id || suites || sig || msg)
        tuple_hash::<E::Hash, _>([
            "ID-v1".as_bytes(),
            E::ID.as_bytes(),
            &SuiteIds::from_suite::<E>().into_bytes(),
            sig.raw_sig().borrow(),
            msg,
        ])
        .into()
    }

    /// Same as [`Default`], but const.
    pub const fn default() -> Self {
        Self([0u8; 64])
    }

    /// Returns the [`Id`] as a byte slice.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Default for Id {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl AsRef<[u8]> for Id {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<[u8; 64]> for Id {
    #[inline]
    fn from(id: [u8; 64]) -> Self {
        Self(id)
    }
}

impl From<Id> for [u8; 64] {
    #[inline]
    fn from(id: Id) -> Self {
        id.0
    }
}

impl From<Tag<64>> for Id {
    #[inline]
    fn from(id: Tag<64>) -> Self {
        Self(id.into())
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

impl ToBase58 for Id {
    type Output = String64;

    fn to_base58(&self) -> Self::Output {
        self.0.to_base58()
    }
}

impl Serialize for Id {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut t = serializer.serialize_tuple(self.0.len())?;
        for c in self.0 {
            t.serialize_element(&c)?;
        }
        t.end()
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IdVisitor;
        impl<'de> Visitor<'de> for IdVisitor {
            type Value = Id;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "an array of length {}", Id::default().0.len())
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut id = Id::default();
                for (i, v) in id.0.iter_mut().enumerate() {
                    match seq.next_element()? {
                        Some(e) => *v = e,
                        None => return Err(de::Error::invalid_length(i, &self)),
                    }
                }
                Ok(id)
            }
        }
        deserializer.deserialize_tuple(Self::default().0.len(), IdVisitor)
    }
}

macro_rules! custom_id {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Copy, Clone, Default, Eq, PartialEq)]
        pub struct $name($crate::id::Id);

        impl $name {
            /// Same as [`Default`], but const.
            pub const fn default() -> Self {
                Self(Id::default())
            }

            /// Returns itself as a byte slice.
            pub const fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }

        impl From<$crate::id::Id> for $name {
            #[inline]
            fn from(id: $crate::id::Id) -> Self {
                Self(id)
            }
        }

        impl From<$name> for $crate::id::Id {
            #[inline]
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), " {}"), self.0)
            }
        }
    };
}
pub(crate) use custom_id;

/// Enumerates the possible key IDs.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum KeyId {
    /// See [`EncryptionKeyId`].
    EncryptionKey(EncryptionKeyId),
    /// See [`GroupKeyId`].
    GroupKey(GroupKeyId),
    /// See [`UserId`].
    IdentityKey(UserId),
    /// See [`SigningKeyId`].
    SigningKey(SigningKeyId),
}

impl KeyId {
    /// Returns the underlying [`Id`].
    pub fn id(&self) -> Id {
        match self {
            Self::EncryptionKey(id) => (*id).into(),
            Self::GroupKey(id) => (*id).into(),
            Self::IdentityKey(id) => (*id).into(),
            Self::SigningKey(id) => (*id).into(),
        }
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionKey(id) => Display::fmt(id, f),
            Self::GroupKey(id) => Display::fmt(id, f),
            Self::IdentityKey(id) => Display::fmt(id, f),
            Self::SigningKey(id) => Display::fmt(id, f),
        }
    }
}

impl Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncryptionKey(id) => Debug::fmt(id, f),
            Self::GroupKey(id) => Debug::fmt(id, f),
            Self::IdentityKey(id) => Debug::fmt(id, f),
            Self::SigningKey(id) => Debug::fmt(id, f),
        }
    }
}
