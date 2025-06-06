//! Utility routines for `apq`.

use core::{borrow::Borrow, fmt, fmt::Debug, marker::PhantomData, result::Result};

use postcard::experimental::max_size::MaxSize;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    ciphersuite::{CipherSuite, SuiteIds},
    keys::PublicKey,
    signer::{Signature, Signer},
};

// Shorthand for lots::of::turbo::fish.
pub(crate) type SigData<CS> = <<<CS as CipherSuite>::Signer as Signer>::Signature as Signature<
    <CS as CipherSuite>::Signer,
>>::Data;

// A fixed-size ciphertext.
macro_rules! ciphertext {
    ($name:ident, $size:ty, $doc:expr) => {
        #[doc = $doc]
        pub struct $name<CS>(
            pub(crate)  $crate::generic_array::GenericArray<
                u8,
                $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>,
            >,
        )
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength;

        impl<CS> $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
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
            ) -> ::core::result::Result<Self, $crate::import::InvalidSizeError> {
                let v: &$crate::generic_array::GenericArray<u8, _> =
                    data.try_into()
                        .map_err(|_| $crate::import::InvalidSizeError {
                            got: data.len(),
                            want: Self::SIZE..Self::SIZE,
                        })?;
                Ok(Self(v.clone()))
            }
        }

        impl<CS> ::core::convert::TryFrom<&[u8]> for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
        {
            type Error = $crate::import::InvalidSizeError;

            fn try_from(data: &[u8]) -> ::core::result::Result<Self, Self::Error> {
                $name::<CS>::from_bytes(data)
            }
        }

        impl<CS> ::core::clone::Clone for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
        {
            fn clone(&self) -> Self {
                Self(::core::clone::Clone::clone(&self.0))
            }
        }

        impl<CS> ::postcard::experimental::max_size::MaxSize for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
            $crate::generic_array::GenericArray<
                u8,
                $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>,
            >: ::postcard::experimental::max_size::MaxSize,
        {
            const POSTCARD_MAX_SIZE: usize = <$crate::generic_array::GenericArray<
                u8,
                $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>,
            > as ::postcard::experimental::max_size::MaxSize>::POSTCARD_MAX_SIZE;
        }

        impl<CS>
            ::core::convert::From<
                $crate::generic_array::GenericArray<
                    u8,
                    $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>,
                >,
            > for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
        {
            fn from(
                buf: $crate::generic_array::GenericArray<
                    u8,
                    $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>,
                >,
            ) -> Self {
                Self(buf)
            }
        }

        impl<CS> ::serde::Serialize for $name<CS>
        where
            CS: $crate::CipherSuite,
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
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
            <CS::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
            $crate::typenum::Sum<<CS::Aead as $crate::aead::Aead>::Overhead, $size>:
                $crate::generic_array::ArrayLength,
        {
            fn deserialize<D>(d: D) -> ::core::result::Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                struct CiphertextVisitor<G: ?Sized>(::core::marker::PhantomData<G>);
                impl<'de, G> ::serde::de::Visitor<'de> for CiphertextVisitor<G>
                where
                    G: $crate::CipherSuite,
                    <G::Aead as $crate::aead::Aead>::Overhead: ::core::ops::Add<$size>,
                    $crate::typenum::Sum<<G::Aead as $crate::aead::Aead>::Overhead, $size>:
                        $crate::generic_array::ArrayLength,
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

/// Asymmetric key misc. impls.
macro_rules! key_misc {
    ($sk:ident, $pk:ident, $id:ident) => {
        $crate::misc::sk_misc!($sk, $pk, $id);
        $crate::misc::pk_misc!($pk, ::core::stringify!($sk), $id);
    };
}
pub(crate) use key_misc;

/// Secret key misc. impls.
macro_rules! sk_misc {
    // For when the public key isn't used.
    ($name:ident, $id:ident) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
            pub struct $id;
        }

        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", ::core::stringify!($name), "`")]
            #[doc = ::core::concat!("Two `", ::core::stringify!($name), "s` with the same ID are the same secret.")]
            #[inline]
            pub fn id(&self) -> Result<$id, $crate::id::IdError> {
                const CONTEXT: &'static str = ::core::stringify!($sk);

                let pk = $crate::keys::PublicKey::export(&self.0.public()?);
                let id = $crate::id::Id::new::<CS>(
                    ::core::borrow::Borrow::borrow(&pk),
                    CONTEXT.as_bytes(),
                );
                Ok($id(id))
            }
        }

        $crate::misc::sk_misc_inner!($name, $id);
    };

    // For when the public key *is* used.
    ($name:ident, $pk:ident, $id:ident) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
            pub struct $id;
        }

        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", ::core::stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            #[inline]
            pub fn id(&self) -> Result<$id,$crate::id::IdError> {
                self.public()?.id()
            }

            /// Returns the public half of the key.
            #[inline]
            pub fn public(&self) -> Result<$pk<CS>,$crate::signer::PkError>{
                Ok($pk(self.0.public()?))
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
                Self(::core::clone::Clone::clone(&self.0))
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
            fn id(&self) -> Result<Self::Id, $crate::id::IdError> {
                self.id()
            }
        }
    };
}
pub(crate) use sk_misc_inner;

/// Public key misc. impls.
macro_rules! pk_misc {
    ($name:ident, $sk:expr, $id:ident) => {
        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            pub fn id(&self) -> Result<$id, $crate::id::IdError> {
                Ok($id($crate::id::Id::new::<CS>(
                    self.0.export().borrow(),
                    $sk.as_bytes(),
                )))
            }
        }

        impl<CS: $crate::CipherSuite> ::core::clone::Clone for $name<CS> {
            #[inline]
            fn clone(&self) -> Self {
                Self(self.0.clone())
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
                $crate::misc::ExportedData::from_key::<CS>(
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
                    $crate::misc::ExportedData::<$crate::misc::SerdeOwnedKey<_>>::deserialize(
                        deserializer,
                    )?;
                if !data.valid_context::<CS>($crate::misc::ExportedDataType::$name) {
                    Err(::serde::de::Error::custom(ImportError::InvalidContext))
                } else {
                    Ok(Self(data.data.0))
                }
            }
        }

        impl<CS: $crate::CipherSuite> $crate::id::Identified for $name<CS> {
            type Id = $id;

            #[inline]
            fn id(&self) -> Result<Self::Id, $crate::id::IdError> {
                self.id()
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
#[serde(deny_unknown_fields)]
pub(crate) struct ExportedData<T> {
    /// Uniquely idenitifies the chosen algorithms.
    suite_id: SuiteIds,
    /// Uniquely idenitifes the type of data.
    name: ExportedDataType,
    /// The exported data.
    pub(crate) data: T,
}

impl<T> ExportedData<T> {
    pub(crate) fn valid_context<CS: CipherSuite>(&self, name: ExportedDataType) -> bool {
        self.suite_id == SuiteIds::from_suite::<CS>() && self.name == name
    }
}

impl<'a, K: PublicKey> ExportedData<SerdeBorrowedKey<'a, K>> {
    pub(crate) fn from_key<CS: CipherSuite>(pk: &'a K, name: ExportedDataType) -> Self {
        Self {
            suite_id: SuiteIds::from_suite::<CS>(),
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
