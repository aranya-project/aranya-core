//! Utility routines for `apq`.

use core::{borrow::Borrow as _, fmt, fmt::Debug, marker::PhantomData, result::Result};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
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

/// Generates a signing key pair.
///
/// - `sk` is the name of the secret (signing) half.
/// - `pk` is the name of the public (verifying) half.
/// - `id` is the name of the key pair's unique ID.
///
/// The inner types for `sk` and `pk` come from
/// [`CipherSuite::Signer`]. `sk` uses `SigningKey` and `pk` uses
/// `VerifyingKey`.
///
/// See [`keypair!`] for more information.
macro_rules! signing_key {
    (
        $(#[$meta:meta])*
        sk = $sk:ident,
        pk = $pk:ident,
        id = $id:ident,
        context = $context:expr,
    ) => {
        $crate::misc::keypair! {
            $(#[$meta])*
            struct $sk<CS>(<<CS as $crate::CipherSuite>::Signer as ::spideroak_crypto::signer::Signer>::SigningKey);
            struct $pk<CS>(<<CS as $crate::CipherSuite>::Signer as ::spideroak_crypto::signer::Signer>::VerifyingKey);
            id = $id,
            context = $context,
        }

        $crate::engine::unwrapped! {
            name: $sk;
            type: Signing;
            into: |key: Self| { key.sk };
            from: |sk| { Self::from_inner(sk) };
        }
    };
}
pub(crate) use signing_key;

/// Generates a KEM key pair.
///
/// - `sk` is the name of the secret (decapsulation) half.
/// - `pk` is the name of the public (encapsulation) half.
/// - `id` is the name of the key pair's unique ID.
///
/// The inner types for `sk` and `pk` come from
/// [`CipherSuite::Kem`]. `sk` uses `DecapKey` and `pk` uses
/// `EncapKey`.
///
/// See [`keypair!`] for more information.
macro_rules! kem_key {
    (
        $(#[$meta:meta])*
        sk = $sk:ident,
        pk = $pk:ident,
        id = $id:ident,
        context = $context:expr,
    ) => {
        $crate::misc::keypair! {
            $(#[$meta])*
            struct $sk<CS>(<<CS as $crate::CipherSuite>::Kem as ::spideroak_crypto::kem::Kem>::DecapKey);
            struct $pk<CS>(<<CS as $crate::CipherSuite>::Kem as ::spideroak_crypto::kem::Kem>::EncapKey);
            id = $id,
            context = $context,
        }

        $crate::engine::unwrapped! {
            name: $sk;
            type: Decap;
            into: |key: Self| { key.sk };
            from: |sk| { Self::from_inner(sk) };
        }
    };
}
pub(crate) use kem_key;

/// Generates an asymmetric key pair.
///
/// - `sk` is the name of the secret half.
/// - `sk_inner` is the underlying secret key type.
/// - `pk` is the name of the public half.
/// - `pk_inner` is the underlying public key type.
///
/// It generates the following:
///
/// - A `fn id(&self) -> Result<id, IdError>` method on both
///   `sk` and `pk`.
/// - A `fn public(&self) -> Result<pk, PkError>` method on `sk`.
/// - `Clone`, `Display`, `Debug`, and `Identified` methods for
///   both `sk` and `pk`.
/// - `AsRef`, `Eq`, `PartialEq`, `Serialize`, and `Deserialize`
///   methods for `pk`.
/// - The type definition for `id`.
///
/// The key pair is generic over the parameter `CS`, which must
/// be [`CipherSuite`].
macro_rules! keypair {
    (
        $(#[$meta:meta])*
        struct $sk:ident<CS>($sk_inner:ty);
        struct $pk:ident<CS>($pk_inner:ty);
        id = $id:ident,
        context = $context:expr,
    ) => {
        $(#[$meta])*
        pub struct $sk<CS: $crate::CipherSuite> {
            pub(crate) sk: $sk_inner,
            id: ::core::cell::OnceCell<::core::result::Result<$id, $crate::id::IdError>>,
        }

        impl<CS: $crate::CipherSuite> $sk<CS> {
            /// Creates a random
            #[doc = ::core::concat!("`", ::core::stringify!($sk), "`")]
            pub fn new<R: $crate::Csprng>(rng: R) -> Self {
                Self::from_inner($crate::Random::random(rng))
            }

            pub(crate) fn from_inner(sk: $sk_inner) -> Self {
                Self {
                    sk,
                    id: ::core::cell::OnceCell::new(),
                }
            }

            #[allow(dead_code)]
            fn __assert_is_zeroize_on_drop() {
                $crate::util::type_is_zeroize_on_drop::<$sk_inner>();
            }
        }

        impl<CS: $crate::CipherSuite> $crate::zeroize::ZeroizeOnDrop for $sk<CS> {}

        $crate::misc::sk_misc!(@keypair $sk, $pk, $id);

        /// The public half of
        #[doc = ::core::concat!("`", ::core::stringify!($sk), "`")]
        pub struct $pk<CS: $crate::CipherSuite> {
            pub(crate) pk: $pk_inner,
            id: ::core::cell::OnceCell<::core::result::Result<$id, $crate::id::IdError>>,
        }

        impl<CS: $crate::CipherSuite> $pk<CS> {
            pub(crate) fn from_inner(pk: $pk_inner) -> Self {
                Self {
                    pk,
                    id: ::core::cell::OnceCell::new(),
                }
            }
        }

        $crate::misc::pk_misc!($pk, $id, $context);
    };
}
pub(crate) use keypair;

/// Generate boilerplate for secret keys.
///
/// See [`key_misc`] for more information.
macro_rules! sk_misc {
    // For symmetric keys, or asymmetric key pairs when the
    // public half isn't used.
    ($name:ident, $id:ident, $context:expr) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
            pub struct $id;
        }

        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", ::core::stringify!($name), "`")]
            #[doc = ::core::concat!("Two `", ::core::stringify!($name), "s` with the same ID are the same secret.")]
            #[inline]
            pub fn id(&self) -> Result<$id, $crate::id::IdError> {
                self.id
                    .get_or_init(|| {
                        let pk = $crate::dangerous::spideroak_crypto::keys::PublicKey::export(&self.sk.public()?);
                        let id = $crate::id::IdExt::new::<CS>(
                            $context.as_bytes(),
                            ::core::iter::once(::core::borrow::Borrow::borrow(&pk)),
                        );
                        Ok(id)
                    })
                    .clone()
            }
        }

        $crate::misc::sk_misc_inner!($name, $id);
    };

    // For asymmetric key pairs when the public half *is* used.
    (@keypair $name:ident, $pk:ident, $id:ident) => {
        $crate::id::custom_id! {
            #[doc = ::core::concat!("Uniquely identifies [`", ::core::stringify!($name), "`].")]
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
                let pk = $pk::from_inner(self.sk.public()?);
                ::core::result::Result::Ok(pk)
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
                    sk: ::core::clone::Clone::clone(&self.sk),
                    id: ::core::clone::Clone::clone(&self.id),
                }
            }
        }

        impl<CS: $crate::CipherSuite> $crate::subtle::ConstantTimeEq for $name<CS> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> $crate::subtle::Choice {
                $crate::subtle::ConstantTimeEq::ct_eq(&self.sk, &other.sk)
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
    ($name:ident, $id:ident, $context:expr) => {
        impl<CS: $crate::CipherSuite> $name<CS> {
            #[doc = ::core::concat!("Uniquely identifies the `", stringify!($name), "`")]
            #[doc = "Two keys with the same ID are the same key."]
            pub fn id(&self) -> ::core::result::Result<$id, $crate::id::IdError> {
                const CONTEXT: &'static str = $context;
                ::core::result::Result::Ok($crate::id::IdExt::new::<CS>(
                    CONTEXT.as_bytes(),
                    ::core::iter::once(::core::borrow::Borrow::borrow(&self.pk.export())),
                ))
            }
        }

        impl<CS: $crate::CipherSuite> ::core::clone::Clone for $name<CS> {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    pk: ::core::clone::Clone::clone(&self.pk),
                    id: ::core::clone::Clone::clone(&self.id),
                }
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
                    &self.pk,
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
                    ::core::result::Result::Ok(Self::from_inner(data.data.0))
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
        Ok(Self(pk))
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
