//! [BearSSL] cryptography.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [BearSSL]: https://bearssl.org/

#![cfg(not(fips))]
#![cfg_attr(docs, doc(cfg(not(fips))))]

use {
    crate::{
        aead::{
            check_open_in_place_params, check_seal_in_place_params, Aead, AeadError, AeadId,
            AeadKey, Nonce,
        },
        asn1::{max_sig_len, raw_sig_len, RawSig, Sig},
        csprng::Csprng,
        ec::{Curve, Curve25519, Scalar, Secp256r1, Secp384r1, Secp521r1, Uncompressed},
        hash::{Block, Hash, HashId},
        hex::ToHex,
        hkdf::hkdf_impl,
        hmac::hmac_impl,
        hybrid_array::typenum::{Unsigned, U12, U16, U32},
        import::{try_import, ExportError, Import, ImportError},
        kdf::{Kdf, KdfError, Prk},
        kem::{
            dhkem_impl, DecapKey, DhKem, Ecdh, EcdhError, EncapKey, Kem, KemError, KemId,
            SharedSecret,
        },
        keys::{PublicKey, SecretKey},
        signer::{Signer, SignerError, SignerId, SigningKey, VerifyingKey},
        zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
    },
    core::{
        borrow::Borrow,
        cell::RefCell,
        cmp,
        ffi::c_void,
        fmt::{self, Debug},
        mem,
        ops::Range,
        pin::Pin,
        ptr,
        result::Result,
        slice,
    },
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess},
};

#[allow(clippy::wildcard_imports)]
use bearssl_sys::*;

pub use bearssl_sys;

/// Reports in constant time whether `x == 0`.
fn ct_eq_zero(x: &[u8]) -> Choice {
    let mut v = Choice::from(0u8);
    for c in x {
        v |= c.ct_ne(&0);
    }
    v
}

/// Compares the big-endian integers `x` and `y`, which must have
/// the same length, in constant time and reports whether `x
/// < y`.
fn ct_be_lt(x: &[u8], y: &[u8]) -> Choice {
    assert_eq!(x.len(), y.len());

    let mut done = Choice::from(0u8);
    let mut lt = 0u8;
    for (x, y) in x.iter().zip(y) {
        // done = 1 if x != y
        //        0 if x == y
        done |= x.ct_ne(y);
        // lt = 1 if done == 1 && x < y
        //      0 if done == 1 && x >= y
        //      0 if done == 0 (x == y)
        lt |= u8::conditional_select(&0, &x.ct_lt(y).unwrap_u8(), done);
    }
    lt.into()
}

/// AES-256-GCM.
pub struct Aes256Gcm(RefCell<br_aes_ct_ctr_keys>);

impl ZeroizeOnDrop for Aes256Gcm {}
impl Drop for Aes256Gcm {
    fn drop(&mut self) {
        // Per the BearSSL docs we're not really supposed to
        // fiddle with these fields, but since we're about to
        // drop the memory it's probably fine.
        self.0.get_mut().skey.zeroize();
    }
}

impl Aead for Aes256Gcm {
    const ID: AeadId = AeadId::Aes256Gcm;

    type KeySize = U32;
    type NonceSize = U12;
    type TagSize = U16;

    const MAX_PLAINTEXT_SIZE: u64 = (1 << 36) - 32; // 2^36 - 32
    const MAX_ADDITIONAL_DATA_SIZE: u64 = (1 << 61) - 1; // 2^61 - 1

    type Key = AeadKey<{ Self::KEY_SIZE }>;
    type Nonce = Nonce<{ Self::NONCE_SIZE }>;

    #[inline]
    fn new(key: &Self::Key) -> Self {
        let mut bc = br_aes_ct_ctr_keys::default();
        // SAFETY: FFI call, no invariants
        unsafe {
            br_aes_ct_ctr_init(
                ptr::addr_of_mut!(bc),
                key.as_ptr() as *const c_void,
                key.len(),
            );
        }
        Self(RefCell::new(bc))
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        check_seal_in_place_params::<Self>(nonce, data, tag, additional_data)?;

        // SAFETY: FFI calls, no invariants
        unsafe {
            // Ideally, we'd make the `br_gcm_context` part of
            // `Aes256Gcm` so that we don't have to call
            // `br_gcm_init` for each encryption/decryption.
            // However, it requires an internal pointer so it's
            // easier to do it here. We can revisit this if it
            // has a bad enough performance impact.
            let mut gc = br_gcm_context::default();
            br_gcm_init(
                ptr::addr_of_mut!(gc),
                ptr::addr_of_mut!(self.0.borrow_mut().vtable),
                Some(br_ghash_ctmul),
            );
            br_gcm_reset(
                ptr::addr_of_mut!(gc),
                nonce.as_ptr() as *const c_void,
                nonce.len(),
            );
            br_gcm_aad_inject(
                ptr::addr_of_mut!(gc),
                additional_data.as_ptr() as *const c_void,
                additional_data.len(),
            );
            br_gcm_flip(ptr::addr_of_mut!(gc));
            br_gcm_run(
                ptr::addr_of_mut!(gc),
                1,
                data.as_mut_ptr() as *mut c_void,
                data.len(),
            );
            br_gcm_get_tag(ptr::addr_of_mut!(gc), tag.as_mut_ptr() as *mut c_void);
        }
        Ok(())
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), AeadError> {
        check_open_in_place_params::<Self>(nonce, data, tag, additional_data)?;

        // SAFETY: FFI calls, no invariants
        let ret = unsafe {
            // Ideally, we'd make the `br_gcm_context` part of
            // `Aes256Gcm` so that we don't have to call
            // `br_gcm_init` for each encryption/decryption.
            // However, it requires an internal pointer so it's
            // easier to do it here. We can revisit this if it
            // has a bad enough performance impact.
            let mut gc = br_gcm_context::default();
            br_gcm_init(
                ptr::addr_of_mut!(gc),
                ptr::addr_of_mut!(self.0.borrow_mut().vtable),
                Some(br_ghash_ctmul),
            );
            br_gcm_reset(
                ptr::addr_of_mut!(gc),
                nonce.as_ptr() as *const c_void,
                nonce.len(),
            );
            br_gcm_aad_inject(
                ptr::addr_of_mut!(gc),
                additional_data.as_ptr() as *const c_void,
                additional_data.len(),
            );
            br_gcm_flip(ptr::addr_of_mut!(gc));
            br_gcm_run(
                ptr::addr_of_mut!(gc),
                0,
                data.as_mut_ptr() as *mut c_void,
                data.len(),
            );
            br_gcm_check_tag(ptr::addr_of_mut!(gc), tag.as_ptr() as *mut c_void)
        };
        if ret == 1 {
            Ok(())
        } else {
            Err(AeadError::Authentication)
        }
    }
}

macro_rules! curve_impl {
    ($name:ident, $doc:expr, $id:expr, $curve:ident) => {
        #[doc = concat!($doc, ".")]
        #[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
        pub struct $name;

        impl Curve for $name {
            type ScalarSize = <$curve as Curve>::ScalarSize;
            type CompressedSize = <$curve as Curve>::CompressedSize;
            type UncompressedSize = <$curve as Curve>::UncompressedSize;
        }

        impl $name {
            /// Uniquely identifies the curve.
            const ID: i32 = $id;

            /// The range of the X coordinate (DH value) in the
            /// (uncompressed) point format.
            ///
            /// We could use `get_impl().xoff`, but why do all
            /// that work when we know the offsets?
            #[allow(non_upper_case_globals)]
            const X_RANGE: Range<usize> = match $id {
                // 0x4 || x || y
                BR_EC_secp256r1 | BR_EC_secp384r1 | BR_EC_secp521r1 => {
                    (1..1 + <$curve as Curve>::ScalarSize::USIZE)
                }
                // x
                _ => (0..<$curve as Curve>::ScalarSize::USIZE),
            };

            /// Returns the order of the curve.
            fn order() -> &'static [u8; $name::SCALAR_SIZE] {
                let f = Self::get_impl().order.expect("`order` should be non-null");
                let mut len = 0;
                // SAFETY: FFI call, no invariants
                let order = unsafe { f(Self::ID, ptr::addr_of_mut!(len)) };
                // Sanity check: this is only false if something
                // is corrupted.
                assert!(len == $name::SCALAR_SIZE);
                // SAFETY: *const u8 has the same memory layout
                // as the array &[u8; N].
                unsafe { &*(order as *const [u8; $name::SCALAR_SIZE]) }
            }

            /// Chooses the correct curve impl for `C`.
            fn get_impl() -> &'static br_ec_impl {
                // The only optimized implementations are for
                // 64-bit architectures.
                #[allow(non_upper_case_globals)]
                let mut ptr = match Self::ID {
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    BR_EC_secp256r1 => {
                        // SAFETY: FFI call, no invariants
                        unsafe { br_ec_p256_m64_get() }
                    }
                    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                    BR_EC_curve25519 => {
                        // SAFETY: FFI call, no invariants
                        unsafe { br_ec_c25519_m64_get() }
                    }
                    _ => ptr::null::<br_ec_impl>(),
                };

                if ptr.is_null() {
                    // SAFETY: FFI call, no invariants
                    ptr = unsafe { br_ec_get_default() };
                }

                // SAFETY: `ptr` should be aligned,
                // dereferenceable, initialized, and valid for
                // the 'static lifetime.
                (unsafe { ptr.as_ref() }).expect("`ptr` should not be null")
            }
        }
    };
}
curve_impl!(P256, "NIST Curve P-256", BR_EC_secp256r1, Secp256r1);
curve_impl!(P384, "NIST Curve P-384", BR_EC_secp384r1, Secp384r1);
curve_impl!(P521, "NIST Curve P-521", BR_EC_secp521r1, Secp521r1);
curve_impl!(X25519, "Curve25519", BR_EC_curve25519, Curve25519);

dhkem_impl!(
    DhKemP256HkdfSha256,
    "DHKEM(P256, HKDF-SHA256)",
    P256,
    HkdfSha256,
    P256PrivateKey,
    P256PublicKey,
);
dhkem_impl!(
    DhKemP521HkdfSha512,
    "DHKEM(P521, HKDF-SHA512)",
    P521,
    HkdfSha512,
    P521PrivateKey,
    P521PublicKey,
);

macro_rules! ecdh_impl {
    (
        $curve:ident,
        $doc:expr,
        $sk:ident,
        $pk:ident $(,)?
    ) => {
        #[doc = concat!($doc, " ECDH private key.")]
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $sk {
            /// The secret data.
            ///
            /// We store this instead of a `br_ec_private_key`
            /// because `br_ec_private_key` only stores `unsigned
            /// char* x`, meaning we'd have to store this data
            /// anyway. Plus, we'd have to deal with internal
            /// pointers which is a pain.
            kbuf: Scalar<$curve>,
        }

        impl $sk {
            /// Used to implement [`SecretKey`].
            fn public(self: Pin<&Self>) -> $pk {
                let sk = self.into();

                // Check that `$curve::CompressedSize` is
                // correct.
                #[cfg(debug_assertions)]
                {
                    // SAFETY: FFI call, no invariants
                    let n = unsafe {
                        br_ec_compute_pub(
                            $curve::get_impl(), // impl
                            ptr::null_mut(),    // pk
                            ptr::null_mut(),    // kbuf
                            ptr::addr_of!(sk),  // sk
                        )
                    };
                    assert_eq!(n, <$curve as Curve>::UncompressedSize::USIZE);
                }

                let mut kbuf = Uncompressed::default();
                // SAFETY: FFI call, no invariants
                unsafe {
                    br_ec_compute_pub(
                        $curve::get_impl(),               // impl
                        ptr::null_mut(),                  // pk
                        kbuf.as_mut_ptr() as *mut c_void, // kbuf
                        ptr::addr_of!(sk),                // sk
                    );
                }
                $pk { kbuf }
            }
        }

        impl DecapKey for $sk {
            type EncapKey = $pk;

            #[inline]
            fn public(&self) -> $pk {
                let p = Pin::new(self);
                Self::public(p)
            }
        }

        impl SecretKey for $sk {
            fn new<R: Csprng>(rng: &mut R) -> Self {
                // We don't know what `rng` is, so construct our
                // own.
                let mut rng = RngWrapper::new(rng);

                // Check that `$curve::SCALAR_SIZE` is correct.
                #[cfg(debug_assertions)]
                {
                    let n = unsafe {
                        br_ec_keygen(
                            ptr::addr_of_mut!(rng.vtable), // rng_ctx
                            $curve::get_impl(),            // impl
                            ptr::null_mut(),               // sk
                            ptr::null_mut(),               // kbuf
                            $curve::ID,                    // id
                        )
                    };
                    assert_eq!(n, $curve::SCALAR_SIZE);
                }

                let mut kbuf = Scalar::default();
                // SAFETY: FFI call, no invariants
                unsafe {
                    br_ec_keygen(
                        ptr::addr_of_mut!(rng.vtable),    // rng_ctx
                        $curve::get_impl(),               // impl
                        ptr::null_mut(),                  // sk
                        kbuf.as_mut_ptr() as *mut c_void, // kbuf
                        $curve::ID,                       // id
                    );
                }
                Self { kbuf }
            }

            type Data = Scalar<$curve>;

            #[inline]
            fn try_export_secret(&self) -> Result<Self::Data, ExportError> {
                Ok(self.kbuf.clone())
            }
        }

        impl ConstantTimeEq for $sk {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.kbuf.ct_eq(&other.kbuf)
            }
        }

        #[cfg(test)]
        impl Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.kbuf.to_hex())
            }
        }

        impl Import<<Self as SecretKey>::Data> for $sk {
            #[inline]
            fn import(data: <Self as SecretKey>::Data) -> Result<Self, ImportError> {
                Self::import(data.borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                // We only create keys that are exactly
                // `$curve::SCALAR_SIZE` bytes long, so `data`
                // should be exactly that length.
                let kbuf: Scalar<$curve> = try_import(data)?;

                // The key must be in [1, N). I.e., non-zero and
                // less than the (subgroup) order.

                // First check that the key is non-zero.
                if !bool::from(ct_eq_zero(kbuf.as_ref())) {
                    return Err(ImportError::InvalidSyntax);
                }

                // Then check that the key is less than the
                // (subgroup) order.
                if !bool::from(ct_be_lt(kbuf.as_ref(), $curve::order())) {
                    return Err(ImportError::InvalidSyntax);
                }

                Ok(Self { kbuf })
            }
        }

        // We use Pin<&T> because `br_ec_private_key` holds
        // a pointer to `kbuf`.
        impl From<Pin<&$sk>> for br_ec_private_key {
            fn from(sk: Pin<&$sk>) -> Self {
                Self {
                    curve: $curve::ID,
                    // NB: this is "safe" because the pointer
                    // passed into `br_ec_*` is `const` and isn't
                    // mutated.
                    x: sk.kbuf.as_ptr() as *mut u8,
                    xlen: $curve::SCALAR_SIZE,
                }
            }
        }

        #[doc = concat!($doc, " ECDH public key.")]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk {
            /// The public data.
            ///
            /// We store this instead of a `br_ec_public_key`
            /// because `br_ec_public_key` only stores `unsigned
            /// char* q`, meaning we'd have to store this data
            /// anyway. Plus, we'd have to deal with internal
            /// pointers which is a pain.
            kbuf: Uncompressed<$curve>,
        }

        impl EncapKey for $pk {}

        impl PublicKey for $pk {
            type Data = Uncompressed<$curve>;

            fn export(&self) -> Self::Data {
                self.kbuf
            }
        }

        impl Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.kbuf.to_hex())
            }
        }

        impl Import<Uncompressed<$curve>> for $pk {
            #[inline]
            fn import(data: Uncompressed<$curve>) -> Result<Self, ImportError> {
                Self::import(data.borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $pk {
            #[inline]
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let kbuf = try_import(data)?;
                Ok(Self { kbuf })
            }
        }

        // We use Pin<&T> because `br_ec_public_key` holds
        // a pointer to `kbuf`.
        impl From<Pin<&$pk>> for br_ec_public_key {
            fn from(pk: Pin<&$pk>) -> Self {
                Self {
                    curve: $curve::ID,
                    // NB: this is "safe" because the pointer
                    // passed into `br_ec_*` is `const` and isn't
                    // mutated.
                    q: pk.kbuf.as_ptr() as *mut u8,
                    qlen: <$curve as Curve>::UncompressedSize::USIZE,
                }
            }
        }

        impl Ecdh for $curve {
            const SCALAR_SIZE: usize = <$curve as Curve>::ScalarSize::USIZE;

            type PrivateKey = $sk;
            type PublicKey = $pk;
            type SharedSecret = SharedSecret<{ $curve::SCALAR_SIZE }>;

            fn ecdh(
                local: &Self::PrivateKey,
                remote: &Self::PublicKey,
            ) -> Result<Self::SharedSecret, EcdhError> {
                let mut g = Zeroizing::new(remote.kbuf);

                // If `mul` is null then the `br_ec_impl` is
                // corrupted.
                let f = Self::get_impl().mul.expect("`mul` should be non-null");
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    f(
                        g.as_mut_ptr(),      // G
                        g.len(),             // Glen
                        local.kbuf.as_ptr(), // x
                        local.kbuf.len(),    // xlen
                        Self::ID,            // id
                    )
                };
                if ret == 1 {
                    // The result is written to `g`.
                    let dh = g.as_ref()[$curve::X_RANGE]
                        .try_into()
                        .expect("DH value should have an exact length");
                    Ok(dh)
                } else {
                    Err(EcdhError::Other("point not on curve"))
                }
            }
        }
    };
}
ecdh_impl!(P256, "P-256", P256PrivateKey, P256PublicKey);
ecdh_impl!(P384, "P-384", P384PrivateKey, P384PublicKey);
ecdh_impl!(P521, "P-521", P521PrivateKey, P521PublicKey);
ecdh_impl!(X25519, "X25519", X25519PrivateKey, X25519PublicKey);

macro_rules! ecdsa_impl {
    (
        $curve:ident,
        $doc:expr,
        $hash:ident,
        $sk:ident,
        $pk:ident,
        $sig:ident $(,)?
    ) => {
        #[doc = concat!($doc, " ECDSA private key.")]
        #[derive(Clone, ZeroizeOnDrop)]
        pub struct $sk {
            /// The secret data.
            ///
            /// We store this instead of a `br_ec_private_key`
            /// because `br_ec_private_key` only stores `unsigned
            /// char* x`, meaning we'd have to store this data
            /// anyway. Plus, we'd have to deal with internal
            /// pointers which is a pain.
            kbuf: Scalar<$curve>,
        }

        impl $sk {
            /// Used to implement [`SigningKey`].
            fn sign(self: Pin<&Self>, msg: &[u8]) -> Result<$sig, SignerError> {
                let digest = $hash::hash(msg);
                let sk = self.into();
                let mut raw = RawSig::<{ raw_sig_len($curve::SCALAR_SIZE * 8) }>::default();
                // SAFETY: FFI call, no invariants
                let len = unsafe {
                    br_ecdsa_i31_sign_raw(
                        $curve::get_impl() as *const br_ec_impl,
                        $hash::vtable(),
                        digest.as_ptr() as *const c_void,
                        ptr::addr_of!(sk),
                        raw.as_mut_ptr() as *mut c_void,
                    )
                };
                // Only returns zero (error) if the curve isn't
                // supported, which is a programmer error.
                assert!(len != 0);

                Ok($sig::from_raw(raw)?)
            }

            /// Used to implement [`SigningKey`].
            fn public(self: Pin<&Self>) -> $pk {
                let sk = self.into();

                // Check that `$curve::UncompressedSize` is correct.
                #[cfg(debug_assertions)]
                {
                    // SAFETY: FFI call, no invariants
                    let n = unsafe {
                        br_ec_compute_pub(
                            $curve::get_impl(), // impl
                            ptr::null_mut(),    // pk
                            ptr::null_mut(),    // kbuf
                            ptr::addr_of!(sk),  // sk
                        )
                    };
                    assert_eq!(n, <$curve as Curve>::UncompressedSize::USIZE);
                }

                let mut kbuf = Uncompressed::default();
                // SAFETY: FFI call, no invariants
                unsafe {
                    br_ec_compute_pub(
                        $curve::get_impl(),               // impl
                        ptr::null_mut(),                  // pk
                        kbuf.as_mut_ptr() as *mut c_void, // kbuf
                        ptr::addr_of!(sk),                // sk
                    );
                }
                $pk { kbuf }
            }
        }

        impl SigningKey<$curve> for $sk {
            #[inline]
            fn sign(&self, msg: &[u8]) -> Result<$sig, SignerError> {
                let p = Pin::new(self);
                $sk::sign(p, msg)
            }

            #[inline]
            fn public(&self) -> $pk {
                let p = Pin::new(self);
                Self::public(p)
            }
        }

        impl SecretKey for $sk {
            #[inline]
            fn new<R: Csprng>(rng: &mut R) -> Self {
                // We don't know what `rng` is, so construct our
                // own.
                let mut rng = RngWrapper::new(rng);

                // Check that `$curve::SCALAR_SIZE` is correct.
                #[cfg(debug_assertions)]
                {
                    let n = unsafe {
                        br_ec_keygen(
                            ptr::addr_of_mut!(rng.vtable), // rng_ctx
                            $curve::get_impl(),            // impl
                            ptr::null_mut(),               // sk
                            ptr::null_mut(),               // kbuf
                            $curve::ID,                    // id
                        )
                    };
                    assert_eq!(n, $curve::SCALAR_SIZE);
                }

                let mut kbuf = Scalar::default();
                // SAFETY: FFI call, no invariants
                let len = unsafe {
                    br_ec_keygen(
                        ptr::addr_of_mut!(rng.vtable),    // rng_ctx
                        $curve::get_impl(),               // impl
                        ptr::null_mut(),                  // sk
                        kbuf.as_mut_ptr() as *mut c_void, // kbuf
                        $curve::ID,                       // id
                    )
                };
                // `br_ec_keygen` returns a scalar of the same
                // length as the curve order, excluding leading
                // zeros. None of the curves we support have
                // leading zeros, so we should get as many bytes
                // as we expect.
                assert!(len == kbuf.len());

                Self { kbuf }
            }

            type Data = Scalar<$curve>;

            #[inline]
            fn try_export_secret(&self) -> Result<Self::Data, ExportError> {
                Ok(self.kbuf.clone())
            }
        }

        #[cfg(test)]
        impl Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.kbuf.to_hex())
            }
        }

        impl ConstantTimeEq for $sk {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.kbuf.ct_eq(&other.kbuf)
            }
        }

        impl Import<Scalar<$curve>> for $sk {
            #[inline]
            fn import(data: Scalar<$curve>) -> Result<Self, ImportError> {
                Self::import(data.borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                // We only create keys that are exactly
                // `$curve::SCALAR_SIZE` bytes long, so `data`
                // should be exactly that length.
                let kbuf: Scalar<$curve> = try_import(data)?;

                // The key must be in [1, N). I.e., non-zero and
                // less than the (subgroup) order.

                // First check that the key is non-zero.
                if !bool::from(ct_eq_zero(kbuf.as_ref())) {
                    return Err(ImportError::InvalidSyntax);
                }

                // Then check that the key is less than the
                // (subgroup) order.
                if !bool::from(ct_be_lt(kbuf.as_ref(), $curve::order())) {
                    return Err(ImportError::InvalidSyntax);
                }

                Ok(Self { kbuf })
            }
        }

        // We use Pin<&T> because `br_ec_private_key` holds
        // a pointer to `kbuf`.
        impl From<Pin<&$sk>> for br_ec_private_key {
            fn from(sk: Pin<&$sk>) -> Self {
                Self {
                    curve: $curve::ID,
                    // NB: this is "safe" because the pointer
                    // passed into `br_ec_*` is `const` and isn't
                    // mutated.
                    x: sk.kbuf.as_ptr() as *mut u8,
                    xlen: $curve::SCALAR_SIZE,
                }
            }
        }

        #[doc = concat!($doc, " ECDSA public key.")]
        #[derive(Clone, Eq, PartialEq)]
        pub struct $pk {
            /// The public data.
            ///
            /// We store this instead of a `br_ec_public_key`
            /// because `br_ec_public_key` only stores `unsigned
            /// char* q`, meaning we'd have to store this data
            /// anyway. Plus, we'd have to deal with internal
            /// pointers which is a pain.
            kbuf: Uncompressed<$curve>,
        }

        impl $pk {
            fn verify(self: Pin<&Self>, msg: &[u8], sig: &$sig) -> Result<(), SignerError> {
                let digest = $hash::hash(msg);
                let pk = self.into();
                let raw: RawSig<{ raw_sig_len($curve::SCALAR_SIZE * 8) }> = sig.to_raw()?;
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    br_ecdsa_i31_vrfy_raw(
                        $curve::get_impl() as *const br_ec_impl,
                        digest.as_ptr() as *const c_void,
                        digest.len(),
                        ptr::addr_of!(pk),
                        raw.as_ptr() as *const c_void,
                        raw.len(),
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(SignerError::Verification)
                }
            }
        }

        impl VerifyingKey<$curve> for $pk {
            #[inline]
            fn verify(&self, msg: &[u8], sig: &$sig) -> Result<(), SignerError> {
                let p = Pin::new(self);
                $pk::verify(p, msg, sig)
            }
        }

        impl PublicKey for $pk {
            type Data = Uncompressed<$curve>;

            #[inline]
            fn export(&self) -> Self::Data {
                self.kbuf
            }
        }

        impl Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.kbuf.to_hex())
            }
        }

        impl Import<Uncompressed<$curve>> for $pk {
            #[inline]
            fn import(data: Uncompressed<$curve>) -> Result<Self, ImportError> {
                Self::import(data.borrow())
            }
        }

        impl<'a> Import<&'a [u8]> for $pk {
            #[inline]
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                let kbuf = try_import(data)?;
                Ok(Self { kbuf })
            }
        }

        // We use Pin<&T> because `br_ec_public_key` holds
        // a pointer to `kbuf`.
        impl From<Pin<&$pk>> for br_ec_public_key {
            fn from(pk: Pin<&$pk>) -> Self {
                Self {
                    curve: $curve::ID,
                    // NB: this is "safe" because the pointer
                    // passed into `br_ec_*` is `const` and isn't
                    // mutated.
                    q: pk.kbuf.as_ptr() as *mut u8,
                    qlen: <$curve as Curve>::UncompressedSize::USIZE,
                }
            }
        }

        #[doc = concat!($doc, " ECDSA signature.")]
        pub type $sig = Sig<$curve, { max_sig_len($curve::SCALAR_SIZE * 8) }>;

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
    "NIST Curve P-256",
    Sha256,
    P256SigningKey,
    P256VerifyingKey,
    P256Signature,
);
ecdsa_impl!(
    P384,
    "NIST Curve P-384",
    Sha384,
    P384SigningKey,
    P384VerifyingKey,
    P384Signature,
);
ecdsa_impl!(
    P521,
    "NIST Curve P-521",
    Sha512,
    P521SigningKey,
    P521VerifyingKey,
    P521Signature,
);

macro_rules! hash_impl {
    (
        $name:ident,
        $doc:expr,
        $ctx:ident,
        $vtable:ident,
        $digest_size:expr,
        $block_size:expr,
        $init:ident,
        $update:ident,
        $digest:ident $(,)?
    ) => {
        #[doc = concat!($doc, ".")]
        #[derive(Copy, Clone, Debug, Default)]
        pub struct $name($ctx);

        impl $name {
            fn vtable() -> *const br_hash_class {
                // SAFETY: $vtable is static, constant memory
                unsafe { ptr::addr_of!($vtable) }
            }
        }

        impl Hash for $name {
            const ID: HashId = HashId::$name;

            const DIGEST_SIZE: usize = $digest_size as usize;
            type Digest = [u8; { Self::DIGEST_SIZE }];

            const BLOCK_SIZE: usize = $block_size;
            type Block = Block<{ Self::BLOCK_SIZE }>;

            #[inline]
            fn new() -> Self {
                let mut ctx = $ctx::default();
                // SAFETY: FFI call, no invariants
                unsafe { $init(&mut ctx) }
                Self(ctx)
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                // SAFETY: FFI call, no invariants
                unsafe {
                    $update(
                        ptr::addr_of_mut!(self.0),
                        data.as_ptr() as *const c_void,
                        data.len(),
                    )
                }
            }

            #[inline]
            fn digest(mut self) -> Self::Digest {
                let mut out = [0u8; Self::DIGEST_SIZE];
                // SAFETY: FFI call, no invariants
                unsafe { $digest(ptr::addr_of_mut!(self.0), out.as_mut_ptr() as *mut c_void) }
                out
            }
        }
    };
}
hash_impl!(
    Sha256,
    "SHA-256",
    br_sha256_context,
    br_sha256_vtable,
    br_sha256_SIZE,
    64,
    br_sha256_init,
    br_sha256_update,
    br_sha256_out,
);
hash_impl!(
    Sha384,
    "SHA-384",
    br_sha384_context,
    br_sha384_vtable,
    br_sha384_SIZE,
    128,
    br_sha384_init,
    br_sha384_update,
    br_sha384_out,
);
hash_impl!(
    Sha512,
    "SHA-512",
    br_sha512_context,
    br_sha512_vtable,
    br_sha512_SIZE,
    128,
    br_sha512_init,
    br_sha512_update,
    br_sha512_out,
);

hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

hmac_impl!(HmacSha256, "HMAC-SHA256", Sha256);
hmac_impl!(HmacSha384, "HMAC-SHA384", Sha384);
hmac_impl!(HmacSha512, "HMAC-SHA512", Sha512);

/// A `HMAC_DRBG`-based CSPRNG.
pub struct HmacDrbg(br_hmac_drbg_context);

impl HmacDrbg {
    /// Creates a CSPRNG from a cryptographically secure seed.
    pub fn new(seed: [u8; 64]) -> Self {
        let mut ctx = br_hmac_drbg_context::default();
        // SAFETY: FFI call, no invariants
        unsafe {
            br_hmac_drbg_init(
                ptr::addr_of_mut!(ctx),
                ptr::addr_of!(br_sha256_vtable),
                seed.as_ptr() as *const c_void,
                seed.len(),
            );
        }
        Self(ctx)
    }

    /// Creates a CSPRNG seeded with entropy from `rng`.
    pub fn from_rng<R: Csprng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 64];
        rng.fill_bytes(&mut seed);
        HmacDrbg::new(seed)
    }
}

impl Csprng for HmacDrbg {
    fn fill_bytes(&mut self, mut dst: &mut [u8]) {
        // Max number of bytes that can be requested from
        // a `HMAC_DRBG` per request.
        const MAX: usize = 1 << 16;

        while !dst.is_empty() {
            let n = cmp::min(dst.len(), MAX);
            // SAFETY: FFI call, no invariants
            unsafe {
                br_hmac_drbg_generate(
                    ptr::addr_of_mut!(self.0),
                    dst.as_mut_ptr() as *mut c_void,
                    n,
                );
            }
            dst = &mut dst[n..];
        }
    }
}

/// The vtable that lets BearSSL call [`RngWrapper`].
static RNG_WRAPPER_VTABLE: br_prng_class = br_prng_class {
    context_size: mem::size_of::<RngWrapper<'_>>(),
    init: Some(rng_wrapper_init),
    generate: Some(rng_wrapper_generate),
    update: Some(rng_wrapper_update),
};

unsafe extern "C" fn rng_wrapper_init(
    _ctx: *mut *const br_prng_class,
    _params: *const c_void,
    _seed: *const c_void,
    _seed_len: usize,
) {
}

unsafe extern "C" fn rng_wrapper_update(
    _ctx: *mut *const br_prng_class,
    _seed: *const c_void,
    _seed_len: usize,
) {
}

unsafe extern "C" fn rng_wrapper_generate(
    ctx: *mut *const br_prng_class,
    out: *mut c_void,
    len: usize,
) {
    // SAFETY: this is the Rust version of this BearSSL C code:
    //
    //  typedef struct br_prng_class {
    //      void (*generate)(const br_prng_class** ctx, ...);
    //  } br_prng_class;
    //
    //  typedef struct br_hmac_drbg_context {
    //      const br_prng_class* vtable;
    //  } br_hmac_drbg_context;
    //
    //  void br_hmac_drbg_generate(br_hmac_drbg_context* ctx, ...);
    //
    //  const br_prng_class br_hmac_drbg_vtable = {
    //      .generate = &br_hmac_drbg_generate,
    //  };
    //
    // It works because, in C, a pointer to a structure is
    // equivalent to a pointer to its first field. Since
    // `RngWrapper` is #[repr(C)] and the first field is `*const
    // br_prng_class`, we can convert between the two.
    let rng = &mut *(ctx as *mut RngWrapper<'_>);
    // SAFETY: we have to trust that the caller provided a valid
    // pointer and length.
    let dst = unsafe { slice::from_raw_parts_mut(out as *mut u8, len) };
    rng.rng.fill_bytes(dst)
}

/// A BearSSL PRNG that wraps some an existing [`Csprng`].
#[repr(C)]
struct RngWrapper<'a> {
    // NB: field order matters! Do not change the ordering. See
    // the comment in `rng_wrapper_generate`.
    vtable: *const br_prng_class,
    rng: &'a mut dyn Csprng,
}

impl<'a> RngWrapper<'a> {
    fn new(rng: &'a mut dyn Csprng) -> Self {
        let vtable = ptr::addr_of!(RNG_WRAPPER_VTABLE);
        RngWrapper { vtable, rng }
    }
}

#[cfg(test)]
mod tests {
    pub use {super::*, crate::test_util::*};

    mod ct_test {
        use super::*;

        #[test]
        fn test_ct_be_lt() {
            struct TestCase(u8, &'static [u8], &'static [u8]);
            let tests = &[
                TestCase(0u8, &[], &[]),
                TestCase(0u8, &[0], &[0]),
                TestCase(0u8, &[1], &[1]),
                TestCase(0u8, &[1, 1], &[1, 1]),
                TestCase(1u8, &[1, 0], &[1, 1]),
                TestCase(1u8, &[0, 1], &[1, 1]),
                TestCase(0u8, &[2, 1], &[2, 0]),
                TestCase(0u8, &[2, 1], &[2, 0]),
                TestCase(1u8, &[2, 0], &[2, 1]),
            ];
            for (i, tc) in tests.iter().enumerate() {
                assert_eq!(tc.0, ct_be_lt(tc.1, tc.2).unwrap_u8(), "tc={i}");
            }
        }
    }

    // Test some [`CipherSuite`] configurations.
    mod ciphersuite_test {
        use {super::*, crate::default::Rng};

        #[test]
        fn test_ciphersuite_128() {
            test_ciphersuite::<
                TestCs<Aes256Gcm, Sha512, HkdfSha256, DhKemP256HkdfSha256, HmacSha512, P256>,
                _,
            >(&mut Rng);
        }

        #[test]
        fn test_ciphersuite_192() {
            // DkKemP384HkdfSha384 does not exist, so use P256
            // instead.
            test_ciphersuite::<
                TestCs<Aes256Gcm, Sha512, HkdfSha384, DhKemP256HkdfSha256, HmacSha512, P384>,
                _,
            >(&mut Rng);
        }

        #[test]
        fn test_ciphersuite_256() {
            test_ciphersuite::<
                TestCs<Aes256Gcm, Sha512, HkdfSha512, DhKemP521HkdfSha512, HmacSha512, P521>,
                _,
            >(&mut Rng);
        }
    }

    mod aead_test {
        use super::*;

        #[test]
        fn test_aead_aes256_gcm() {
            test_aead::<Aes256Gcm>(aead::TestName::AesGcm);
        }
    }

    mod ecdh_test {
        use super::*;

        #[test]
        fn test_ecdh_p256() {
            test_ecdh::<P256>(ecdh::TestName::EcdhSecp256r1Ecpoint);
        }

        #[test]
        fn test_ecdh_p384() {
            test_ecdh::<P384>(ecdh::TestName::EcdhSecp384r1Ecpoint);
        }

        #[test]
        fn test_ecdh_p521() {
            test_ecdh::<P521>(ecdh::TestName::EcdhSecp521r1Ecpoint);
        }
    }

    mod ecdsa_test {
        use super::*;

        #[test]
        fn test_ecdsa_p256() {
            test_ecdsa::<P256>(ecdsa::TestName::EcdsaSecp256r1Sha256);
        }

        #[test]
        fn test_ecdsa_p384() {
            test_ecdsa::<P384>(ecdsa::TestName::EcdsaSecp384r1Sha384);
        }

        #[test]
        fn test_ecdsa_p521() {
            test_ecdsa::<P521>(ecdsa::TestName::EcdsaSecp521r1Sha512);
        }
    }

    mod hkdf_test {
        use super::*;

        #[test]
        fn test_hkdf_sha256() {
            test_hkdf::<HkdfSha256>(hkdf::TestName::HkdfSha256);
        }

        #[test]
        fn test_hkdf_sha384() {
            test_hkdf::<HkdfSha384>(hkdf::TestName::HkdfSha384);
        }

        #[test]
        fn test_hkdf_sha512() {
            test_hkdf::<HkdfSha512>(hkdf::TestName::HkdfSha512);
        }
    }

    mod hmac_test {
        use super::*;

        #[test]
        fn test_hmac_sha256() {
            test_mac::<HmacSha256>(mac::TestName::HmacSha256);
        }

        #[test]
        fn test_hmac_sha384() {
            test_mac::<HmacSha384>(mac::TestName::HmacSha384);
        }

        #[test]
        fn test_hmac_sha512() {
            test_mac::<HmacSha512>(mac::TestName::HmacSha512);
        }
    }

    mod hpke_test {
        use super::*;

        #[test]
        fn test_hpke_dhkem_p256_hkdfsha256_hkdfsha256_aes256gcm() {
            test_hpke::<DhKemP256HkdfSha256, HkdfSha256, Aes256Gcm>(
                hpke::TestName::HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
            );
        }

        #[test]
        fn test_hpke_dhkem_p256_hkdfsha256_hkdfsha512_aes256gcm() {
            test_hpke::<DhKemP256HkdfSha256, HkdfSha512, Aes256Gcm>(
                hpke::TestName::HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
            );
        }

        #[test]
        fn test_hpke_dhkem_p521_hkdfsha512_hkdfsha256_aes256gcm() {
            test_hpke::<DhKemP521HkdfSha512, HkdfSha256, Aes256Gcm>(
                hpke::TestName::HpkeDhKemP521HkdfSha512HkdfSha256Aes256Gcm,
            );
        }

        #[test]
        fn test_hpke_dhkem_p521_hkdfsha512_hkdfsha512_aes256gcm() {
            test_hpke::<DhKemP521HkdfSha512, HkdfSha512, Aes256Gcm>(
                hpke::TestName::HpkeDhKemP521HkdfSha512HkdfSha512Aes256Gcm,
            );
        }
    }
}
