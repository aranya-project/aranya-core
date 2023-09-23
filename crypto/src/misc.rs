//! Utility routines for `userkeys` and `apq`.

use {
    crate::{
        ciphersuite::{CipherSuite, SuiteIds},
        engine::Engine,
        id::Id,
        kem::Kem,
        keys::{PublicKey, SecretKey},
        signer::{Signature, Signer},
    },
    core::{borrow::Borrow, fmt, marker::PhantomData, result::Result},
    postcard::experimental::max_size::MaxSize,
    serde::{de, Deserialize, Deserializer, Serialize, Serializer},
};

// These are shorthand for lots::of::turbo::fish.
pub(crate) type SigningKeyData<E> =
    <<<E as CipherSuite>::Signer as Signer>::SigningKey as SecretKey>::Data;
pub(crate) type SigData<E> = <<<E as CipherSuite>::Signer as Signer>::Signature as Signature<
    <E as CipherSuite>::Signer,
>>::Data;
pub(crate) type DecapKeyData<E> = <<<E as CipherSuite>::Kem as Kem>::DecapKey as SecretKey>::Data;

// A fixed-size ciphertext.
macro_rules! ciphertext {
    ($name:ident, $size:ty, $doc:expr) => {
        #[doc = $doc]
        pub struct $name<E>(
            $crate::hybrid_array::ByteArray<
                $crate::hybrid_array::typenum::operator_aliases::Sum<
                    <E::Aead as $crate::aead::Aead>::Overhead,
                    $size,
                >,
            >,
        )
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize;

        impl<E> $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
        {
            /// The size in bytes of the ciphertext.
            pub const SIZE: usize =
                <$size as $crate::hybrid_array::typenum::marker_traits::Unsigned>::USIZE
                    + E::Aead::OVERHEAD;

            /// Encodes itself as bytes.
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }

            /// Returns itself from its byte encoding.
            pub fn from_bytes(
                data: &[u8],
            ) -> ::core::result::Result<Self, $crate::import::InvalidSizeError> {
                let v = data
                    .try_into()
                    .map_err(|_| $crate::import::InvalidSizeError {
                        got: data.len(),
                        want: Self::SIZE..Self::SIZE,
                    })?;
                Ok(Self(v))
            }
        }

        impl<E> Clone for $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
        {
            fn clone(&self) -> Self {
                Self(self.0.clone())
            }
        }

        impl<E> ::postcard::experimental::max_size::MaxSize for $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
            $crate::hybrid_array::ByteArray<
                $crate::hybrid_array::typenum::operator_aliases::Sum<
                    <E::Aead as $crate::aead::Aead>::Overhead,
                    $size,
                >,
            >: ::postcard::experimental::max_size::MaxSize,
        {
            const POSTCARD_MAX_SIZE: usize =
                <ByteArray<Sum<<E::Aead as Aead>::Overhead, $size>> as MaxSize>::POSTCARD_MAX_SIZE;
        }

        impl<E>
            From<
                $crate::hybrid_array::ByteArray<
                    $crate::hybrid_array::typenum::operator_aliases::Sum<
                        <E::Aead as $crate::aead::Aead>::Overhead,
                        $size,
                    >,
                >,
            > for $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
        {
            fn from(
                buf: $crate::hybrid_array::ByteArray<
                    $crate::hybrid_array::typenum::operator_aliases::Sum<
                        <E::Aead as $crate::aead::Aead>::Overhead,
                        $size,
                    >,
                >,
            ) -> Self {
                Self(buf)
            }
        }

        impl<E> ::serde::Serialize for $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
        {
            fn serialize<S>(&self, s: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                s.serialize_bytes(self.as_bytes())
            }
        }

        impl<'de, E> ::serde::Deserialize<'de> for $name<E>
        where
            E: $crate::engine::Engine + ?Sized,
            <E::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::hybrid_array::typenum::operator_aliases::Sum<
                <E::Aead as $crate::aead::Aead>::Overhead,
                $size,
            >: $crate::hybrid_array::ArraySize,
        {
            fn deserialize<D>(d: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct CiphertextVisitor<G>(::core::marker::PhantomData<G>);
                impl<'de, G> ::serde::de::Visitor<'de> for CiphertextVisitor<G>
                where
                    G: $crate::engine::Engine + ?Sized,
                    <G::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
                    $crate::hybrid_array::typenum::operator_aliases::Sum<
                        <G::Aead as $crate::aead::Aead>::Overhead,
                        $size,
                    >: $crate::hybrid_array::ArraySize,
                {
                    type Value = $name<G>;

                    fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                        ::core::write!(f, "ciphertext")
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> ::core::result::Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        $name::<G>::from_bytes(v).map_err(E::custom)
                    }

                    fn visit_borrowed_bytes<E>(
                        self,
                        v: &'de [u8],
                    ) -> ::core::result::Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        $name::<G>::from_bytes(v).map_err(E::custom)
                    }
                }
                d.deserialize_bytes(CiphertextVisitor(::core::marker::PhantomData))
            }
        }
    };
}
pub(crate) use ciphertext;

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

        impl<E: $crate::engine::Engine + ?Sized> ::core::convert::AsRef<$name<E>> for $name<E> {
            fn as_ref(&self) -> &Self {
                self
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
// the future.
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize, MaxSize)]
pub(crate) enum ExportedDataType {
    EncryptionPublicKey,
    IdentityVerifyingKey,
    ReceiverPublicKey,
    SenderPublicKey,
    SenderVerifyingKey,
    VerifyingKey,
}

/// Non-secret exported from an `Engine`.
#[derive(Serialize, Deserialize, MaxSize)]
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

        impl<'de, K: PublicKey> de::Visitor<'de> for PkVisitor<K> {
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
