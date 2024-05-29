//! [RustCrypto] cryptography.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [RustCrypto]: https://github.com/RustCrypto

#![cfg(not(fips))]
#![cfg_attr(docsrs, doc(cfg(not(fips))))]

use core::{borrow::Borrow, fmt, result::Result};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit, KeySizeUser},
    A_MAX, C_MAX, P_MAX,
};
use crypto_common::BlockSizeUser;
use ecdsa::{
    der,
    signature::{Signer as Signer_, Verifier},
};
use elliptic_curve::{
    ecdh,
    scalar::NonZeroScalar,
    sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint},
    CurveArithmetic, FieldBytesSize,
};
use rand_core::{impls, CryptoRng, RngCore};
use sha2::digest::OutputSizeUser;
use subtle::{Choice, ConstantTimeEq};
use typenum::{Unsigned, U12, U16};

use crate::{
    aead::{
        check_open_in_place_params, check_seal_in_place_params, Aead, AeadId, AeadKey, IndCca2,
        Lifetime, OpenError, SealError,
    },
    csprng::Csprng,
    ec::{Curve, Secp256r1, Secp384r1},
    hash::{Block, Digest, Hash, HashId},
    hex,
    hkdf::hkdf_impl,
    hmac::hmac_impl,
    import::{try_from_slice, ExportError, Import, ImportError},
    kem::{dhkem_impl, DecapKey, DhKem, Ecdh, EcdhError, EncapKey, Kem, KemError, KemId},
    keys::{PublicKey, SecretKey, SecretKeyBytes},
    signer::{Signature, Signer, SignerError, SignerId, SigningKey, VerifyingKey},
    zeroize::ZeroizeOnDrop,
};

/// AES-256-GCM.
#[cfg_attr(feature = "clone-aead", derive(Clone))]
pub struct Aes256Gcm(aes_gcm::Aes256Gcm);

impl Aead for Aes256Gcm {
    const ID: AeadId = AeadId::Aes256Gcm;

    // Assumes a random nonce.
    const LIFETIME: Lifetime = Lifetime::Messages(u32::MAX as u64);

    type KeySize = <aes_gcm::Aes256Gcm as KeySizeUser>::KeySize;
    type NonceSize = U12;
    type Overhead = U16; // tag only

    const MAX_PLAINTEXT_SIZE: u64 = P_MAX;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = A_MAX;
    const MAX_CIPHERTEXT_SIZE: u64 = C_MAX;

    type Key = AeadKey<Self::KeySize>;

    #[inline]
    fn new(key: &Self::Key) -> Self {
        let key: &[u8; 32] = key.as_array();
        Self(aes_gcm::Aes256Gcm::new(key.into()))
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        check_seal_in_place_params::<Self>(nonce, data, tag, additional_data)?;

        let got_tag = self
            .0
            .encrypt_in_place_detached(
                // From<&[T]> for GenericArray<T, _> panics on incorrect length
                #[allow(clippy::unnecessary_fallible_conversions)]
                nonce
                    .try_into()
                    .map_err(|_| SealError::InvalidNonceSize(InvalidNonceSize))?,
                additional_data,
                data,
            )
            .map_err(|_| SealError::Encryption)?;
        tag.copy_from_slice(&got_tag[..]);

        Ok(())
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        check_open_in_place_params::<Self>(nonce, data, tag, additional_data)?;

        self.0
            .decrypt_in_place_detached(
                // From<&[T]> for GenericArray<T, _> panics on incorrect length
                #[allow(clippy::unnecessary_fallible_conversions)]
                nonce
                    .try_into()
                    .map_err(|_| OpenError::InvalidNonceSize(InvalidNonceSize))?,
                additional_data,
                data,
                // From<&[T]> for GenericArray<T, _> panics on incorrect length
                #[allow(clippy::unnecessary_fallible_conversions)]
                tag.try_into().map_err(|_| OpenError::InvalidOverheadSize)?,
            )
            .map_err(|_| OpenError::Authentication)
    }
}

impl IndCca2 for Aes256Gcm {}

#[cfg(feature = "committing-aead")]
mod committing {
    use aes::cipher::{BlockEncrypt, BlockSizeUser, KeyInit};
    use generic_array::GenericArray;
    use typenum::{Unsigned, U32};

    use super::{Aes256Gcm, Sha256};
    use crate::aead::{AeadKey, BlockCipher};

    /// AES-256.
    #[doc(hidden)]
    pub struct Aes256(aes::Aes256);

    impl BlockCipher for Aes256 {
        type BlockSize = <aes::Aes256 as BlockSizeUser>::BlockSize;
        const BLOCK_SIZE: usize = Self::BlockSize::USIZE;
        type Key = AeadKey<U32>;

        fn new(key: &Self::Key) -> Self {
            let key: &[u8; 32] = key.as_array();
            let cipher = <aes::Aes256 as KeyInit>::new(key.into());
            Self(cipher)
        }

        fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
            // Mismatched GenericArray versions, yay.
            let block: &mut [u8; 16] = block.as_mut();
            self.0.encrypt_block(block.into())
        }
    }

    crate::aead::utc_aead!(Cmt1Aes256Gcm, Aes256Gcm, Aes256, "CMT-1 AES-256-GCM.");
    crate::aead::hte_aead!(Cmt4Aes256Gcm, Cmt1Aes256Gcm, Sha256, "CMT-4 AES-256-GCM.");
}
#[cfg(feature = "committing-aead")]
pub use committing::*;

use crate::aead::InvalidNonceSize;

macro_rules! curve_impl {
    ($name:ident, $doc:expr, $inner:ty, $point:ident, $curve:ident) => {
        #[doc = concat!($doc, ".")]
        pub use $inner as $name;

        impl Curve for $inner {
            type ScalarSize = <$curve as Curve>::ScalarSize;
            type CompressedSize = <$curve as Curve>::CompressedSize;
            type UncompressedSize = <$curve as Curve>::UncompressedSize;
        }

        #[doc = concat!("An encoded ", $doc, "point.")]
        #[derive(Copy, Clone)]
        pub struct $point(EncodedPoint<$inner>);

        impl Borrow<[u8]> for $point {
            fn borrow(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }

        impl<'a> Import<&'a [u8]> for $point {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let point = EncodedPoint::<$inner>::from_bytes(data)
                    .map_err(|_| ImportError::InvalidSyntax)?;
                Ok(Self(point))
            }
        }
    };
}
curve_impl!(P256, "NIST-P256", p256::NistP256, P256Point, Secp256r1);
curve_impl!(P384, "NIST-P256", p384::NistP384, P384Point, Secp384r1);

/// An ECDH shared secret.
#[derive(ZeroizeOnDrop)]
pub struct SharedSecret<C>(ecdh::SharedSecret<C>)
where
    C: CurveArithmetic;

impl<C> Borrow<[u8]> for SharedSecret<C>
where
    C: CurveArithmetic,
{
    fn borrow(&self) -> &[u8] {
        self.0.raw_secret_bytes().as_slice()
    }
}

macro_rules! ecdh_impl {
    (
        $curve:ident,
        $doc:expr,
        $sk:ident,
        $pk:ident,
        $point:ident $(,)?
    ) => {
        #[doc = concat!($doc, " ECDH private key.")]
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $sk(NonZeroScalar<$curve>);

        impl DecapKey for $sk {
            type EncapKey = $pk;

            #[inline]
            fn public(&self) -> $pk {
                $pk(elliptic_curve::PublicKey::from_secret_scalar(&self.0))
            }
        }

        impl SecretKey for $sk {
            type Size = FieldBytesSize<$curve>;

            #[inline]
            fn new<R: Csprng>(rng: &mut R) -> Self {
                let sk = NonZeroScalar::random(&mut RngWrapper(rng));
                Self(sk)
            }

            #[inline]
            fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
                // Mismatched GenericArray versions, yay.
                let secret: [u8; FieldBytesSize::<$curve>::USIZE] = self.0.to_bytes().into();
                Ok(SecretKeyBytes::new(secret.into()))
            }
        }

        #[cfg(test)]
        impl fmt::Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex::ct_write(f, self.0.to_bytes().as_slice())
            }
        }

        impl ConstantTimeEq for $sk {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let bytes = *try_from_slice(data)?;
                let sk = Option::from(NonZeroScalar::from_repr(bytes.into()))
                    .ok_or(ImportError::InvalidSyntax)?;
                Ok(Self(sk))
            }
        }

        #[doc = concat!($doc, " ECDH public key.")]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk(elliptic_curve::PublicKey<$curve>);

        impl EncapKey for $pk {}

        impl PublicKey for $pk {
            type Data = $point;

            fn export(&self) -> Self::Data {
                $point(self.0.to_encoded_point(false))
            }
        }

        impl fmt::Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex::ct_write(f, self.export().borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $pk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let point = EncodedPoint::<$curve>::from_bytes(data)
                    .map_err(|_| ImportError::InvalidSyntax)?;
                let pk = Option::from(elliptic_curve::PublicKey::from_encoded_point(&point))
                    .ok_or(ImportError::InvalidSyntax)?;
                Ok(Self(pk))
            }
        }

        impl Ecdh for $curve {
            const SCALAR_SIZE: usize = <$curve as Curve>::ScalarSize::USIZE;

            type PrivateKey = $sk;
            type PublicKey = $pk;
            type SharedSecret = SharedSecret<$curve>;

            fn ecdh(
                local: &Self::PrivateKey,
                remote: &Self::PublicKey,
            ) -> Result<Self::SharedSecret, EcdhError> {
                let secret = ecdh::diffie_hellman(&local.0, remote.0.as_affine());
                Ok(SharedSecret(secret))
            }
        }
    };
}
ecdh_impl!(P256, "P-256", P256PrivateKey, P256PublicKey, P256Point);
ecdh_impl!(P384, "P-384", P384PrivateKey, P384PublicKey, P384Point);
// RustCrypto hasn't really implemented P-521.

dhkem_impl!(
    DhKemP256HkdfSha256,
    "DHKEM(P256, HKDF-SHA256)",
    P256,
    HkdfSha256,
    P256PrivateKey,
    P256PublicKey,
);

/// An ASN.1 DER encoded ECDSA signature.
#[derive(Clone)]
pub struct SigBytes<T>(T);

impl<T> Borrow<[u8]> for SigBytes<T>
where
    T: AsRef<[u8]>,
{
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

macro_rules! ecdsa_impl {
    (
        $curve:ident,
        $doc:expr,
        $sk:ident,
        $pk:ident,
        $sig:ident,
        $point:ident $(,)?
    ) => {
        #[doc = concat!($doc, " ECDSA private key.")]
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $sk(ecdsa::SigningKey<$curve>);

        impl SigningKey<$curve> for $sk {
            fn sign(&self, msg: &[u8]) -> Result<$sig, SignerError> {
                let sig = self.0.sign(msg);
                Ok($sig(sig))
            }

            #[inline]
            fn public(&self) -> $pk {
                $pk(ecdsa::VerifyingKey::from(&self.0))
            }
        }

        impl SecretKey for $sk {
            type Size = FieldBytesSize<$curve>;

            #[inline]
            fn new<R: Csprng>(rng: &mut R) -> Self {
                let sk = ecdsa::SigningKey::random(&mut RngWrapper(rng));
                Self(sk)
            }

            #[inline]
            fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
                // Mismatched GenericArray versions, yay.
                let secret: [u8; FieldBytesSize::<$curve>::USIZE] = self.0.to_bytes().into();
                Ok(SecretKeyBytes::new(secret.into()))
            }
        }

        #[cfg(test)]
        impl fmt::Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex::ct_write(f, self.0.to_bytes().as_slice())
            }
        }

        impl ConstantTimeEq for $sk {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let sk =
                    ecdsa::SigningKey::from_slice(data).map_err(|_| ImportError::InvalidSyntax)?;
                Ok(Self(sk))
            }
        }

        #[doc = concat!($doc, " ECDSA public key.")]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk(ecdsa::VerifyingKey<$curve>);

        impl VerifyingKey<$curve> for $pk {
            fn verify(&self, msg: &[u8], sig: &$sig) -> Result<(), SignerError> {
                self.0
                    .verify(msg, &sig.0)
                    .map_err(|_| SignerError::Verification)
            }
        }

        impl PublicKey for $pk {
            type Data = $point;

            fn export(&self) -> Self::Data {
                $point(self.0.to_encoded_point(false))
            }
        }

        impl fmt::Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                hex::ct_write(f, self.export().borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $pk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let point = EncodedPoint::<$curve>::from_bytes(data)
                    .map_err(|_| ImportError::InvalidSyntax)?;
                let pk = ecdsa::VerifyingKey::from_encoded_point(&point)
                    .map_err(|_| ImportError::InvalidSyntax)?;
                Ok(Self(pk))
            }
        }

        #[doc = concat!($doc, " ECDSA signature.")]
        #[derive(Clone, Debug)]
        pub struct $sig(ecdsa::Signature<$curve>);

        impl Signature<$curve> for $sig {
            type Data = SigBytes<der::Signature<$curve>>;

            fn export(&self) -> Self::Data {
                SigBytes(self.0.to_der())
            }
        }

        impl<'a> Import<&'a [u8]> for $sig {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let sig =
                    ecdsa::Signature::from_der(data).map_err(|_| ImportError::InvalidSyntax)?;
                Ok(Self(sig))
            }
        }

        impl Signer for $curve {
            const ID: SignerId = SignerId::$curve;

            type SigningKey = $sk;
            type VerifyingKey = $pk;
            type Signature = $sig;
        }
    };
}
ecdsa_impl!(
    P256,
    "P-256",
    P256SigningKey,
    P256VerifyingKey,
    P256Signature,
    P256Point,
);
ecdsa_impl!(
    P384,
    "P-384",
    P384SigningKey,
    P384VerifyingKey,
    P384Signature,
    P384Point,
);

macro_rules! hash_impl {
    (
        $name:ident,
        $doc:expr
    ) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone, Debug, Default)]
        pub struct $name(sha2::$name);

        impl Hash for $name {
            const ID: HashId = HashId::$name;

            type DigestSize = <sha2::$name as OutputSizeUser>::OutputSize;
            const DIGEST_SIZE: usize =
                <<sha2::$name as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

            const BLOCK_SIZE: usize = <sha2::$name as BlockSizeUser>::BlockSize::USIZE;
            type Block = Block<{ Self::BLOCK_SIZE }>;

            #[inline]
            fn new() -> Self {
                Self(<sha2::$name as sha2::Digest>::new())
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                sha2::Digest::update(&mut self.0, data)
            }

            #[inline]
            fn digest(self) -> Digest<Self::DigestSize> {
                Digest::from_array(sha2::Digest::finalize(self.0).into())
            }

            #[inline]
            fn hash(data: &[u8]) -> Digest<Self::DigestSize> {
                Digest::from_array(<sha2::$name as sha2::Digest>::digest(data).into())
            }
        }
    };
}
hash_impl!(Sha256, "SHA-256");
hash_impl!(Sha384, "SHA-384");
hash_impl!(Sha512, "SHA-512");

hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

hmac_impl!(HmacSha256, "HMAC-SHA256", Sha256);
hmac_impl!(HmacSha384, "HMAC-SHA384", Sha384);
hmac_impl!(HmacSha512, "HMAC-SHA512", Sha512);

/// Translates [`Csprng`] to [`RngCore`].
struct RngWrapper<'a, R>(&'a mut R);

impl<R> CryptoRng for RngWrapper<'_, R> {}

impl<R: Csprng> RngCore for RngWrapper<'_, R> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        self.0.fill_bytes(dst)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test some [`CipherSuite`] configurations.
    mod ciphersuite_tests {
        use super::*;
        use crate::test_util::{test_ciphersuite, TestCs};

        test_ciphersuite!(p256, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            P256,
        >);
        test_ciphersuite!(p384, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha384,
            DhKemP256HkdfSha256, // DhKemP384HkdfSha384 does not exist
            HmacSha512,
            P384,
        >);
    }

    mod aead_tests {
        use super::*;
        use crate::test_util::test_aead;

        test_aead!(aes256gcm, Aes256Gcm, AeadTest::AesGcm);

        #[cfg(feature = "committing-aead")]
        mod committing {
            use super::*;

            test_aead!(cmd1_aead_aes256_gcm, Cmt1Aes256Gcm);
            test_aead!(cmd4_aead_aes256_gcm, Cmt4Aes256Gcm);
        }
    }

    mod ecdh_tests {
        use super::*;
        use crate::test_util::vectors::{test_ecdh, EcdhTest};

        #[test]
        fn test_ecdh_p256() {
            test_ecdh::<P256>(EcdhTest::EcdhSecp256r1Ecpoint);
        }

        #[test]
        fn test_ecdh_p384() {
            test_ecdh::<P384>(EcdhTest::EcdhSecp384r1Ecpoint);
        }
    }

    mod ecdsa_tests {
        use super::*;
        use crate::test_util::test_signer;

        test_signer!(p256, P256, EcdsaTest::EcdsaSecp256r1Sha256);
        test_signer!(p384, P384, EcdsaTest::EcdsaSecp384r1Sha384);
    }

    mod hkdf_tests {
        use super::*;
        use crate::test_util::test_kdf;

        test_kdf!(test_hkdf_sha256, HkdfSha256, HkdfTest::HkdfSha256);
        test_kdf!(test_hkdf_sha384, HkdfSha384, HkdfTest::HkdfSha384);
        test_kdf!(test_hkdf_sha512, HkdfSha512, HkdfTest::HkdfSha512);
    }

    mod hmac_tests {
        use super::*;
        use crate::test_util::test_mac;

        test_mac!(test_hmac_sha256, HmacSha256, MacTest::HmacSha256);
        test_mac!(test_hmac_sha384, HmacSha384, MacTest::HmacSha384);
        test_mac!(test_hmac_sha512, HmacSha512, MacTest::HmacSha512);
    }

    mod hpke_tests {
        use super::*;
        use crate::test_util::test_hpke;

        test_hpke!(
            sha256,
            DhKemP256HkdfSha256,
            HkdfSha256,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
        );
        test_hpke!(
            sha512,
            DhKemP256HkdfSha256,
            HkdfSha512,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
        );
    }
}
