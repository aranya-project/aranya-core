use subtle::{Choice, ConstantTimeEq};

use crate::{
    csprng::{Csprng, Random},
    engine::Engine,
    import::{ExportError, Import, ImportError},
    kem::{DecapKey, Kem},
    keys::{SecretKey, SecretKeyBytes},
    zeroize::ZeroizeOnDrop,
};

/// The root key material for a channel.
pub(crate) struct RootChannelKey<E: Engine>(<E::Kem as Kem>::DecapKey);

impl<E: Engine> RootChannelKey<E> {
    pub(super) fn new(sk: <E::Kem as Kem>::DecapKey) -> Self {
        Self(sk)
    }

    pub(super) fn public(&self) -> <E::Kem as Kem>::EncapKey {
        self.0.public()
    }

    pub(super) fn into_inner(self) -> <E::Kem as Kem>::DecapKey {
        self.0
    }
}

impl<E: Engine> Clone for RootChannelKey<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E: Engine> ConstantTimeEq for RootChannelKey<E> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<E: Engine> Random for RootChannelKey<E> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(<<E::Kem as Kem>::DecapKey as SecretKey>::new(rng))
    }
}

impl<E: Engine> SecretKey for RootChannelKey<E> {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        Random::random(rng)
    }

    type Size = <<E::Kem as Kem>::DecapKey as SecretKey>::Size;

    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<E: Engine> ZeroizeOnDrop for RootChannelKey<E> {
    // The only field is `DecapKey`, which is `ZeroizeOnDrop`.
}

impl<'a, E: Engine> Import<&'a [u8]> for RootChannelKey<E> {
    fn import(key: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(Import::import(key)?))
    }
}

macro_rules! raw_key {
    ($name:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        #[repr(C)]
        pub struct $name<E: $crate::engine::Engine> {
            /// The key data.
            pub key: $crate::aead::KeyData<E::Aead>,
            /// The base nonce.
            pub base_nonce: $crate::aead::Nonce<<E::Aead as $crate::aead::Aead>::NonceSize>,
        }

        impl<E: $crate::engine::Engine> $crate::subtle::ConstantTimeEq for $name<E> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                let key = $crate::subtle::ConstantTimeEq::ct_eq(&self.key, &other.key);
                let base_nonce =
                    $crate::subtle::ConstantTimeEq::ct_eq(&self.base_nonce, &other.base_nonce);
                key & base_nonce
            }
        }

        impl<E: $crate::engine::Engine> $crate::subtle::ConstantTimeEq for &$name<E> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                $crate::subtle::ConstantTimeEq::ct_eq(*self, other)
            }
        }

        impl<E: $crate::engine::Engine> ::core::clone::Clone for $name<E> {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    key: ::core::clone::Clone::clone(&self.key),
                    base_nonce: ::core::clone::Clone::clone(&self.base_nonce),
                }
            }
        }

        impl<E: $crate::engine::Engine> $crate::csprng::Random for $name<E> {
            fn random<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                Self {
                    key: $crate::csprng::Random::random(rng),
                    base_nonce: $crate::csprng::Random::random(rng),
                }
            }
        }
    };
}
raw_key!(RawSealKey, "A raw [`SealKey`][crate::aps::SealKey].");
raw_key!(RawOpenKey, "A raw [`OpenKey`][crate::aps::OpenKey].");

// Add some hooks for `test_util`.
#[cfg(any(test, feature = "test_util"))]
mod test_misc {
    use core::fmt;

    use super::*;

    raw_key!(
        TestingKey,
        "Unifies `RawSealKey` and `RawOpenKey` for testing.",
    );

    impl<E: Engine> fmt::Debug for TestingKey<E> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestingKey")
                .field("key", &self.key.as_bytes())
                .field("nonce", &self.base_nonce)
                .finish()
        }
    }

    impl<E: Engine> RawSealKey<E> {
        pub(crate) fn to_testing_key(&self) -> TestingKey<E> {
            TestingKey {
                key: self.key.clone(),
                base_nonce: self.base_nonce.clone(),
            }
        }
    }

    impl<E: Engine> RawOpenKey<E> {
        pub(crate) fn to_testing_key(&self) -> TestingKey<E> {
            TestingKey {
                key: self.key.clone(),
                base_nonce: self.base_nonce.clone(),
            }
        }
    }

    impl<E: Engine> From<RawSealKey<E>> for RawOpenKey<E> {
        fn from(key: RawSealKey<E>) -> Self {
            Self {
                key: key.key.clone(),
                base_nonce: key.base_nonce.clone(),
            }
        }
    }

    impl<E: Engine> From<RawOpenKey<E>> for RawSealKey<E> {
        fn from(key: RawOpenKey<E>) -> Self {
            Self {
                key: key.key.clone(),
                base_nonce: key.base_nonce.clone(),
            }
        }
    }
}
