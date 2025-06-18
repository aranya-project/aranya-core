//! Utility routines for `apq`.

use core::{borrow::Borrow, fmt, fmt::Debug, marker::PhantomData, result::Result};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use spideroak_crypto::{
    keys::PublicKey,
    signer::{Signature, Signer},
};

use crate::ciphersuite::{CipherSuite, Oids};

// Shorthand for lots::of::turbo::fish.
pub(crate) type SigData<CS> = <<<CS as CipherSuite>::Signer as Signer>::Signature as Signature<
    <CS as CipherSuite>::Signer,
>>::Data;

// A fixed-size ciphertext.
#[cfg(feature = "apq")]
macro_rules! ciphertext {
    ($name:ident, $size:ty, $doc:expr) => {
        #[doc = $doc]
        pub struct $name<CS>(
            pub(crate)  $crate::generic_array::GenericArray<
                u8,
                $crate::typenum::Sum<
                    <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                    $size,
                >,
            >,
        )
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength;

        impl<CS> $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            /// The size in bytes of the ciphertext.
            pub const SIZE: usize =
                <$size as $crate::typenum::Unsigned>::USIZE + CS::Aead::OVERHEAD;

            /// Encodes itself as bytes.
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_ref()
            }

            /// Returns itself from its byte encoding.
            pub fn from_bytes(
                data: &[u8],
            ) -> ::core::result::Result<
                Self,
                $crate::dangerous::spideroak_crypto::import::InvalidSizeError,
            > {
                let v: &$crate::generic_array::GenericArray<u8, _> =
                    data.try_into().map_err(|_| {
                        $crate::dangerous::spideroak_crypto::import::InvalidSizeError {
                            got: data.len(),
                            want: Self::SIZE..Self::SIZE,
                        }
                    })?;
                Ok(Self(v.clone()))
            }
        }

        impl<CS> ::core::convert::TryFrom<&[u8]> for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            type Error = $crate::dangerous::spideroak_crypto::import::InvalidSizeError;

            fn try_from(data: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                $name::<CS>::from_bytes(data)
            }
        }

        impl<CS> ::core::clone::Clone for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            fn clone(&self) -> Self {
                Self(::core::clone::Clone::clone(&self.0))
            }
        }

        impl<CS>
            ::core::convert::From<
                $crate::generic_array::GenericArray<
                    u8,
                    $crate::typenum::Sum<
                        <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                        $size,
                    >,
                >,
            > for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            fn from(
                buf: $crate::generic_array::GenericArray<
                    u8,
                    $crate::typenum::Sum<
                        <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                        $size,
                    >,
                >,
            ) -> Self {
                Self(buf)
            }
        }

        impl<CS> ::serde::Serialize for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            fn serialize<S>(&self, s: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                s.serialize_bytes(self.as_bytes())
            }
        }

        impl<'de, CS> ::serde::Deserialize<'de> for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                ::core::ops::Add<$size>,
            $crate::typenum::Sum<
                <CS::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                $size,
            >: $crate::generic_array::ArrayLength,
        {
            fn deserialize<D>(d: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct CiphertextVisitor<G: ?Sized>(::core::marker::PhantomData<G>);
                impl<'de, G> ::serde::de::Visitor<'de> for CiphertextVisitor<G>
                where
                    G: $crate::CipherSuite,
                    <G::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead:
                        ::core::ops::Add<$size>,
                    $crate::typenum::Sum<
                        <G::Aead as $crate::dangerous::spideroak_crypto::aead::Aead>::Overhead,
                        $size,
                    >: $crate::generic_array::ArrayLength,
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
#[cfg(feature = "apq")]
pub(crate) use ciphertext;

/// Generate boilerplate for asymmetric key pairs.
///
/// It generates the following:
///
/// - The type definition for `id`.
/// - A `fn id(&self) -> Result<id, IdError>` method on both
///   `sk` and `pk`.
/// - A `fn public(&self) -> Result<pk, PkError>` method on `sk`.
/// - `Clone`, `Display`, `Debug`, and `Identified` methods for
///   both `sk` and `pk`.
/// - `AsRef`, `Eq`, `PartialEq`, `Serialize`, and `Deserialize`
///   methods for `pk`.
///
/// # Arguments
///
/// - `sk` is the secret (private) key type.
/// - `pk` is the public key type.
/// - `id` is the key's unique ID.
///
/// It assumes `sk` and `pk` are already defined and that both
/// are unary tuple structs.
///
/// # Example
///
/// ```rust,ignore
/// pub struct FooKey<CS: CipherSuite>(<CS::Kem as Kem>::DecapKey);
/// pub struct FooPublicKey<CS: CipherSuite>(<CS::Kem as Kem>::EncapKey);
/// key_misc!(FooKey, FooPublicKey, FooKeyId);
/// ```
macro_rules! key_misc {
    ($sk:ident, $pk:ident, $id:ident) => {
        $crate::misc::sk_misc!($sk, $pk, $id);
        $crate::misc::pk_misc!($pk, $id);
    };
}
pub(crate) use key_misc;

/// Generate boilerplate for secret keys.
///
/// See [`key_misc`] for more information.
macro_rules! sk_misc {
    // For symmetric keys, or asymmetric key pairs when the
    // public half isn't used.
    ($name:ident, $id:ident) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
            #[derive(
                ::zerocopy::Immutable,
                ::zerocopy::IntoBytes,
                ::zerocopy::KnownLayout,
                ::zerocopy::Unaligned,
            )]
            pub struct $id;
        }

        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", ::core::stringify!($name), "`")]
            #[doc = ::core::concat!("Two `", ::core::stringify!($name), "s` with the same ID are the same secret.")]
            #[inline]
            pub fn id(&self) -> Result<$id, $crate::id::IdError> {
                self.id
                    .get_or_init(|| {
                        let context = <$name<CS>>::CONTEXT;

                        let pk = $crate::dangerous::spideroak_crypto::keys::PublicKey::export(&self.key.public()?);
                        let id = $crate::id::Id::new::<CS>(
                            ::core::borrow::Borrow::borrow(&pk),
                            context.as_bytes(),
                        );
                        Ok($id(id))
                    })
                    .clone()
            }
        }

        $crate::misc::sk_misc_inner!($name, $id);
    };

    // For asymmetric key pairs when the public half *is* used.
    ($name:ident, $pk:ident, $id:ident) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
            #[derive(
                ::zerocopy::Immutable,
                ::zerocopy::IntoBytes,
                ::zerocopy::KnownLayout,
                ::zerocopy::Unaligned,
            )]
            pub struct $id;
        }

        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", ::core::stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            #[inline]
            pub fn id(&self) -> ::core::result::Result<$id, $crate::id::IdError> {
                self.id
                    .get_or_init(|| self.public()?.id())
                    .clone()
            }

            /// Returns the public half of the key.
            #[inline]
            pub fn public(&self) -> ::core::result::Result<$pk<CS>, $crate::dangerous::spideroak_crypto::signer::PkError> {
                ::core::result::Result::Ok($pk(self.key.public()?))
            }
        }

        $crate::misc::sk_misc_inner!($name, $id);
    };
}
pub(crate) use sk_misc;

macro_rules! sk_misc_inner {
    ($name:ident, $id:ident) => {
        impl<CS: $crate::CipherSuite> ::core::clone::Clone for $name<CS> {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    key: ::core::clone::Clone::clone(&self.key),
                    id: ::core::cell::OnceCell::new(),
                }
            }
        }

        impl<CS: $crate::CipherSuite> $crate::subtle::ConstantTimeEq for $name<CS> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> $crate::subtle::Choice {
                $crate::subtle::ConstantTimeEq::ct_eq(&self.key, &other.key)
            }
        }

        impl<CS: $crate::CipherSuite> ::core::fmt::Display for $name<CS> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}", self.id().map_err(|_| ::core::fmt::Error)?)
            }
        }

        impl<CS: $crate::CipherSuite> ::core::fmt::Debug for $name<CS> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(
                    f,
                    ::core::concat!(::core::stringify!($name), " {}"),
                    self.id().map_err(|_| ::core::fmt::Error)?
                )
            }
        }

        impl<CS: $crate::CipherSuite> $crate::id::Identified for $name<CS> {
            type Id = $id;

            #[inline]
            fn id(&self) -> ::core::result::Result<Self::Id, $crate::id::IdError> {
                self.id()
            }
        }
    };
}
pub(crate) use sk_misc_inner;

/// Generate boilerplate for public keys.
///
/// See [`key_misc`] for more information.
macro_rules! pk_misc {
    ($name:ident, $id:ident) => {
        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            pub fn id(&self) -> ::core::result::Result<$id, $crate::id::IdError> {
                ::core::result::Result::Ok($id($crate::id::Id::new::<CS>(
                    ::core::borrow::Borrow::borrow(&self.0.export()),
                    <$name<CS>>::CONTEXT.as_bytes(),
                )))
            }
        }

        impl<CS: $crate::CipherSuite> ::core::clone::Clone for $name<CS> {
            #[inline]
            fn clone(&self) -> Self {
                Self(::core::clone::Clone::clone(&self.0))
            }
        }

        impl<CS: $crate::CipherSuite> ::core::convert::AsRef<$name<CS>> for $name<CS> {
            #[inline]
            fn as_ref(&self) -> &Self {
                self
            }
        }

        impl<CS: $crate::CipherSuite> ::core::cmp::Eq for $name<CS> {}
        impl<CS: $crate::CipherSuite> ::core::cmp::PartialEq for $name<CS> {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                self.id() == other.id()
            }
        }

        impl<CS: $crate::CipherSuite> ::core::fmt::Display for $name<CS> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(f, "{}", self.id().map_err(|_| ::core::fmt::Error)?)
            }
        }

        impl<CS: $crate::CipherSuite> ::core::fmt::Debug for $name<CS> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::write!(
                    f,
                    ::core::concat!(stringify!($name), " {}"),
                    self.id().map_err(|_| ::core::fmt::Error)?
                )
            }
        }

        impl<CS: $crate::CipherSuite> ::serde::Serialize for $name<CS> {
            fn serialize<S>(&self, serializer: S) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                $crate::misc::ExportedData::<CS, _>::from_key(
                    &self.0,
                    $crate::misc::ExportedDataType::$name,
                )
                .serialize(serializer)
            }
        }

        impl<'de, CS: $crate::CipherSuite> ::serde::Deserialize<'de> for $name<CS> {
            fn deserialize<D>(deserializer: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let data =
                    $crate::misc::ExportedData::<CS, $crate::misc::SerdeOwnedKey<_>>::deserialize(
                        deserializer,
                    )?;
                if !data.is_type($crate::misc::ExportedDataType::$name) {
                    ::core::result::Result::Err(::serde::de::Error::custom(
                        ImportError::InvalidContext,
                    ))
                } else {
                    ::core::result::Result::Ok(Self(data.data.0))
                }
            }
        }

        impl<CS: $crate::CipherSuite> $crate::id::Identified for $name<CS> {
            type Id = $id;

            #[inline]
            fn id(&self) -> ::core::result::Result<Self::Id, $crate::id::IdError> {
                self.id()
            }
        }
    };
}
pub(crate) use pk_misc;

// Allow repeated suffixes since different types will be added in
// the future.
#[allow(clippy::enum_variant_names)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ExportedDataType {
    EncryptionPublicKey,
    IdentityVerifyingKey,
    ReceiverPublicKey,
    SenderPublicKey,
    SenderVerifyingKey,
    VerifyingKey,
}

/// Non-secret exported from an `Engine`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportedData<CS, T>
where
    CS: CipherSuite,
{
    /// Uniquely idenitifies the chosen algorithms.
    #[serde(bound = "CS: CipherSuite")]
    oids: Oids<CS>,
    /// Uniquely idenitifes the type of data.
    name: ExportedDataType,
    /// The exported data.
    pub(crate) data: T,
}

impl<CS, T> ExportedData<CS, T>
where
    CS: CipherSuite,
{
    pub(crate) fn is_type(&self, name: ExportedDataType) -> bool {
        self.name == name
    }
}

impl<'a, CS, K: PublicKey> ExportedData<CS, SerdeBorrowedKey<'a, K>>
where
    CS: CipherSuite,
{
    pub(crate) fn from_key(pk: &'a K, name: ExportedDataType) -> Self {
        Self {
            oids: CS::OIDS,
            name,
            data: SerdeBorrowedKey(pk),
        }
    }
}

/// An owned [`PublicKey`] for deserializing.
pub(crate) struct SerdeOwnedKey<K>(pub(crate) K);

impl<'de, K: PublicKey> Deserialize<'de> for SerdeOwnedKey<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PkVisitor<K>(PhantomData<K>);

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
pub(crate) struct SerdeBorrowedKey<'a, K>(&'a K);

impl<K: PublicKey> Serialize for SerdeBorrowedKey<'_, K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.export().borrow())
    }
}
