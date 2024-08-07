use subtle::{Choice, ConstantTimeEq};

use crate::{
    csprng::{Csprng, Random},
    import::{ExportError, Import, ImportError},
    kem::{DecapKey, Kem},
    keys::{SecretKey, SecretKeyBytes},
    signer::PkError,
    zeroize::ZeroizeOnDrop,
    CipherSuite,
};

/// The root key material for a channel.
pub(crate) struct RootChannelKey<CS: CipherSuite>(<CS::Kem as Kem>::DecapKey);

impl<CS: CipherSuite> RootChannelKey<CS> {
    pub(super) fn new(sk: <CS::Kem as Kem>::DecapKey) -> Self {
        Self(sk)
    }

    pub(super) fn public(&self) -> Result<<CS::Kem as Kem>::EncapKey, PkError> {
        self.0.public()
    }

    pub(super) fn into_inner(self) -> <CS::Kem as Kem>::DecapKey {
        self.0
    }
}

impl<CS: CipherSuite> Clone for RootChannelKey<CS> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<CS: CipherSuite> ConstantTimeEq for RootChannelKey<CS> {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<CS: CipherSuite> Random for RootChannelKey<CS> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(<<CS::Kem as Kem>::DecapKey as SecretKey>::new(rng))
    }
}

impl<CS: CipherSuite> SecretKey for RootChannelKey<CS> {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        Random::random(rng)
    }

    type Size = <<CS::Kem as Kem>::DecapKey as SecretKey>::Size;

    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<CS: CipherSuite> ZeroizeOnDrop for RootChannelKey<CS> {
    // The only field is `DecapKey`, which is `ZeroizeOnDrop`.
}

impl<'a, CS: CipherSuite> Import<&'a [u8]> for RootChannelKey<CS> {
    fn import(key: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(Import::import(key)?))
    }
}

macro_rules! raw_key {
    ($name:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        #[repr(C)]
        pub struct $name<CS: $crate::CipherSuite> {
            /// The key data.
            pub key: $crate::aead::KeyData<CS::Aead>,
            /// The base nonce.
            pub base_nonce: $crate::aead::Nonce<<CS::Aead as $crate::aead::Aead>::NonceSize>,
        }

        impl<CS: $crate::CipherSuite> $crate::subtle::ConstantTimeEq for $name<CS> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                let key = $crate::subtle::ConstantTimeEq::ct_eq(&self.key, &other.key);
                let base_nonce =
                    $crate::subtle::ConstantTimeEq::ct_eq(&self.base_nonce, &other.base_nonce);
                key & base_nonce
            }
        }

        impl<CS: $crate::CipherSuite> $crate::subtle::ConstantTimeEq for &$name<CS> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                $crate::subtle::ConstantTimeEq::ct_eq(*self, other)
            }
        }

        impl<CS: $crate::CipherSuite> ::core::clone::Clone for $name<CS> {
            #[inline]
            fn clone(&self) -> Self {
                Self {
                    key: ::core::clone::Clone::clone(&self.key),
                    base_nonce: ::core::clone::Clone::clone(&self.base_nonce),
                }
            }
        }

        impl<CS: $crate::CipherSuite> $crate::csprng::Random for $name<CS> {
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

    impl<CS: CipherSuite> fmt::Debug for TestingKey<CS> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TestingKey")
                .field("key", &self.key.as_bytes())
                .field("nonce", &self.base_nonce)
                .finish()
        }
    }

    impl<CS: CipherSuite> RawSealKey<CS> {
        pub(crate) fn to_testing_key(&self) -> TestingKey<CS> {
            TestingKey {
                key: self.key.clone(),
                base_nonce: self.base_nonce.clone(),
            }
        }
    }

    impl<CS: CipherSuite> RawOpenKey<CS> {
        pub(crate) fn to_testing_key(&self) -> TestingKey<CS> {
            TestingKey {
                key: self.key.clone(),
                base_nonce: self.base_nonce.clone(),
            }
        }
    }

    impl<CS: CipherSuite> From<RawSealKey<CS>> for RawOpenKey<CS> {
        fn from(key: RawSealKey<CS>) -> Self {
            Self {
                key: key.key.clone(),
                base_nonce: key.base_nonce.clone(),
            }
        }
    }

    impl<CS: CipherSuite> From<RawOpenKey<CS>> for RawSealKey<CS> {
        fn from(key: RawOpenKey<CS>) -> Self {
            Self {
                key: key.key.clone(),
                base_nonce: key.base_nonce.clone(),
            }
        }
    }
}
