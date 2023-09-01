//! Utility routines for `userkeys` and `apq`.

use {
    crate::{
        ciphersuite::{CipherSuite, SuiteIds},
        engine::Engine,
        id::Id,
        import::Import,
        kem::Kem,
        keys::{PublicKey, SecretKey},
        signer::{Signature, Signer},
    },
    core::{borrow::Borrow, fmt, marker::PhantomData, result::Result},
    serde::{
        de::{self, Visitor},
        Deserialize, Deserializer, Serialize, Serializer,
    },
};

// These are shorthand for lots::of::turbo::fish.
pub(crate) type SigningKeyData<E> =
    <<<E as CipherSuite>::Signer as Signer>::SigningKey as SecretKey>::Data;
pub(crate) type SigData<E> = <<<E as CipherSuite>::Signer as Signer>::Signature as Signature<
    <E as CipherSuite>::Signer,
>>::Data;
pub(crate) type DecapKeyData<E> = <<<E as CipherSuite>::Kem as Kem>::DecapKey as SecretKey>::Data;

macro_rules! key_misc {
    ($sk:ident, $pk:ident, $id:ident) => {
        $crate::misc::sk_misc!($sk, $pk, $id);
        $crate::misc::pk_misc!($pk, stringify!($sk), $id);
    };
}
pub(crate) use key_misc;

macro_rules! sk_misc {
    ($name:ident, $pk:ident, $id:ident) => {
        $crate::id::custom_id!(
            $id,
            concat!("Uniquely identifies [`", stringify!($name), "`].")
        );

        impl<E: $crate::engine::Engine + ?Sized> $name<E> {
            #[doc = concat!("Uniquely identifies the `", stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            #[inline]
            pub fn id(&self) -> $id {
                self.public().id()
            }

            /// Returns the public half of the key.
            #[inline]
            pub fn public(&self) -> $pk<E> {
                $pk(self.0.public())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::clone::Clone for $name<E> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::fmt::Display for $name<E> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}", self.id())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::fmt::Debug for $name<E> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), " {}"), self.id())
            }
        }
    };
}
pub(crate) use sk_misc;

macro_rules! pk_misc {
    ($name:ident, $sk:expr, $id:ident) => {
        impl<E: $crate::engine::Engine + ?Sized> $name<E> {
            #[doc = concat!("Uniquely identifies the `", stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            pub fn id(&self) -> $id {
                $id($crate::id::Id::new::<E>(self.0.export().borrow(), $sk))
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::clone::Clone for $name<E> {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::cmp::Eq for $name<E> {}
        impl<E: $crate::engine::Engine + ?Sized> ::core::cmp::PartialEq for $name<E> {
            fn eq(&self, other: &Self) -> bool {
                self.id() == other.id()
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::fmt::Display for $name<E> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}", self.id())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::core::fmt::Debug for $name<E> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), " {}"), self.id())
            }
        }

        impl<E: $crate::engine::Engine + ?Sized> ::serde::Serialize for $name<E> {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                $crate::misc::ExportedData::from_key::<E>(
                    &self.0,
                    $crate::misc::ExportedDataType::$name,
                )
                .serialize(serializer)
            }
        }

        impl<'de, E: $crate::engine::Engine + ?Sized> ::serde::Deserialize<'de> for $name<E> {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let data =
                    $crate::misc::ExportedData::<$crate::misc::SerdeOwnedKey<_>>::deserialize(
                        deserializer,
                    )?;
                if !data.valid_context::<E>($crate::misc::ExportedDataType::$name) {
                    Err(::serde::de::Error::custom(ImportError::InvalidContext))
                } else {
                    Ok(Self(data.data.0))
                }
            }
        }
    };
}
pub(crate) use pk_misc;

// Allow repeated suffixes since different types will be added in
// a future PR.
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ExportedDataType {
    EncryptionPublicKey,
    IdentityVerifyingKey,
    ReceiverPublicKey,
    SenderPublicKey,
    SenderVerifyingKey,
    Signature,
    VerifyingKey,
}

/// Non-secret exported from an `Engine`.
#[derive(Serialize, Deserialize)]
pub(crate) struct ExportedData<T> {
    /// Uniquely identifies the [`Engine`].
    eng_id: Id,
    /// Uniquely idenitifies the chosen algorithms.
    suite_id: SuiteIds,
    /// Uniquely idenitifes the type of data.
    name: ExportedDataType,
    /// The exported data.
    pub(crate) data: T,
}

impl<T> ExportedData<T> {
    pub(crate) fn valid_context<E: Engine + ?Sized>(&self, name: ExportedDataType) -> bool {
        self.eng_id == E::ID && self.suite_id == SuiteIds::from_suite::<E>() && self.name == name
    }
}

impl<'a, K: PublicKey> ExportedData<SerdeBorrowedKey<'a, K>> {
    pub(crate) fn from_key<E: Engine + ?Sized>(pk: &'a K, name: ExportedDataType) -> Self {
        Self {
            eng_id: E::ID,
            suite_id: SuiteIds::from_suite::<E>(),
            name,
            data: SerdeBorrowedKey(pk),
        }
    }
}

/// An owned [`PublicKey`] for deserializing.
pub(crate) struct SerdeOwnedKey<K: PublicKey>(pub(crate) K);

impl<'de, K: PublicKey> Deserialize<'de> for SerdeOwnedKey<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PkVisitor<K: PublicKey>(PhantomData<K>);

        impl<'de, K: PublicKey> Visitor<'de> for PkVisitor<K> {
            type Value = K;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a public key")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                K::import(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                K::import(v).map_err(de::Error::custom)
            }
        }
        let pk = deserializer.deserialize_bytes(PkVisitor::<K>(PhantomData))?;
        Ok(SerdeOwnedKey(pk))
    }
}

/// A borrowed [`PublicKey`] for serializing.
pub(crate) struct SerdeBorrowedKey<'a, K: PublicKey>(&'a K);

impl<K: PublicKey> Serialize for SerdeBorrowedKey<'_, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.export().borrow())
    }
}

impl<'a, T: Signer + ?Sized> ExportedData<SerdeBorrowedSig<'a, T>> {
    pub(crate) fn from_sig<E: Engine + ?Sized>(
        sig: &'a T::Signature,
        name: ExportedDataType,
    ) -> Self {
        Self {
            eng_id: E::ID,
            suite_id: SuiteIds::from_suite::<E>(),
            name,
            data: SerdeBorrowedSig(sig),
        }
    }
}

/// An owned [`Signature`] for deserializing.
pub(crate) struct SerdeOwnedSig<T: Signer + ?Sized>(pub(crate) T::Signature);

impl<'de, T: Signer + ?Sized> Deserialize<'de> for SerdeOwnedSig<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor<T: Signer + ?Sized>(PhantomData<T>);

        impl<'de, T: Signer + ?Sized> Visitor<'de> for SigVisitor<T> {
            type Value = T::Signature;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a public signature")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                T::Signature::import(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                T::Signature::import(v).map_err(de::Error::custom)
            }
        }
        let sig = deserializer.deserialize_bytes(SigVisitor::<T>(PhantomData))?;
        Ok(SerdeOwnedSig(sig))
    }
}

/// A borrowed [`Signature`] for serializing.
pub(crate) struct SerdeBorrowedSig<'a, T: Signer + ?Sized>(&'a T::Signature);

impl<T: Signer + ?Sized> Serialize for SerdeBorrowedSig<'_, T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.export().borrow())
    }
}