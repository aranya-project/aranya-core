//! [BoringSSL] cryptography.
//!
//! # Warning
//!
//! This is a low-level module. You should not be using it
//! directly unless you are implementing an engine.
//!
//! [BoringSSL]: https://boringssl.googlesource.com/boringssl

#![cfg_attr(docsrs, doc(cfg(feature = "boringssl")))]
#![cfg(feature = "boringssl")]

extern crate alloc;

use alloc::alloc::handle_alloc_error;
use core::{
    alloc::Layout,
    borrow::{Borrow, BorrowMut},
    ffi::{c_char, c_int, c_void, CStr},
    fmt::{self, Debug},
    ptr,
    result::Result,
};

pub use bssl_sys;
use bssl_sys::{
    point_conversion_form_t, BN_equal_consttime, ECDH_compute_key, ECDSA_sign, ECDSA_verify,
    EC_KEY_dup, EC_KEY_free, EC_KEY_generate_key, EC_KEY_generate_key_fips, EC_KEY_get0_group,
    EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_is_opaque, EC_KEY_new_by_curve_name,
    EC_KEY_oct2key, EC_KEY_oct2priv, EC_KEY_priv2oct, EC_KEY_set_public_key, EC_POINT_cmp,
    EC_POINT_free, EC_POINT_mul, EC_POINT_new, EC_POINT_point2oct, ED25519_keypair_from_seed,
    ED25519_sign, ED25519_verify, ERR_get_error_line, ERR_lib_error_string,
    ERR_reason_error_string, EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_open,
    EVP_AEAD_CTX_open_gather, EVP_AEAD_CTX_seal, EVP_AEAD_CTX_seal_scatter, EVP_AEAD_CTX_zero,
    EVP_AEAD_key_length, EVP_AEAD_nonce_length, EVP_aead_aes_256_gcm,
    NID_X9_62_prime256v1 as NID_secp256r1, NID_secp384r1, NID_secp521r1, RAND_bytes, SHA256_Final,
    SHA256_Init, SHA256_Update, SHA384_Final, SHA384_Init, SHA384_Update, SHA512_256_Final,
    SHA512_256_Init, SHA512_256_Update, SHA512_Final, SHA512_Init, SHA512_Update,
    CIPHER_R_BAD_KEY_LENGTH, CIPHER_R_BUFFER_TOO_SMALL, CIPHER_R_INVALID_AD_SIZE,
    CIPHER_R_INVALID_KEY_LENGTH, CIPHER_R_INVALID_NONCE_SIZE, CIPHER_R_TAG_TOO_LARGE,
    CIPHER_R_TOO_LARGE, ECDSA_R_BAD_SIGNATURE, EC_KEY, EC_R_INVALID_ENCODING,
    EC_R_INVALID_PRIVATE_KEY, ERR_GET_REASON, EVP_AEAD_CTX, NID_ED25519, SHA256, SHA256_CBLOCK,
    SHA256_CTX, SHA256_DIGEST_LENGTH, SHA384, SHA384_CBLOCK, SHA384_DIGEST_LENGTH, SHA512,
    SHA512_256, SHA512_256_DIGEST_LENGTH, SHA512_CBLOCK, SHA512_CTX, SHA512_DIGEST_LENGTH,
};
use cfg_if::cfg_if;
use more_asserts::assert_ge;
use subtle::{Choice, ConstantTimeEq};
use typenum::{Unsigned, U, U12, U16, U32};

use crate::{
    aead::{
        check_open_in_place_params, check_open_params, check_seal_in_place_params,
        check_seal_params, Aead, AeadId, AeadKey, BufferTooSmallError, IndCca2, InvalidNonceSize,
        Lifetime, OpenError, SealError,
    },
    asn1::{max_sig_len, EncodingError, Sig},
    csprng::Csprng,
    ec::{Curve, Curve25519, Scalar, Secp256r1, Secp384r1, Secp521r1, Uncompressed},
    hash::{Block, Digest, Hash, HashId},
    hex::ToHex,
    import::{try_import, ExportError, Import, ImportError},
    kem::{
        dhkem_impl, DecapKey, DhKem, Ecdh, EcdhError, EncapKey, Kem, KemError, KemId, SharedSecret,
    },
    keys::{PublicKey, SecretKey, SecretKeyBytes},
    signer::{Signature, Signer, SignerError, SignerId, SigningKey, VerifyingKey},
    zeroize::{Zeroize, ZeroizeOnDrop},
};

cfg_if! {
    if #[cfg(any(fips, test_fips))] {
        pub use lame_crypto::*;
    } else {
        pub use fun_crypto::*;
    }
}

// Groups together all of the allocator nonsense.
mod rust_alloc {
    #[allow(clippy::wildcard_imports)]
    use {
        super::*,
        alloc::alloc::{alloc, dealloc},
        core::{
            mem, slice,
            sync::atomic::{AtomicU32, Ordering},
        },
    };

    /// Incremented each time [`mem_alloc`] is called.
    pub static ALLOC_CTR: AtomicU32 = AtomicU32::new(0);
    /// Incremented each time [`mem_free`] is called.
    pub static FREE_CTR: AtomicU32 = AtomicU32::new(0);

    // On non-ELF targets, BoringSSL defines the alt allocators as
    // variables, not functions.
    #[cfg(any(
        target_os = "aix",
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
    ))]
    mod no_elf {
        #[allow(clippy::wildcard_imports)]
        use super::*;

        fn do_init() {
            // Override BoringSSL's memory allocator.
            //
            // SAFETY: there is none
            unsafe {
                bssl_sys::OPENSSL_memory_alloc = Some(mem_alloc);
                bssl_sys::OPENSSL_memory_free = Some(mem_free);
                bssl_sys::OPENSSL_memory_get_size = Some(mem_size);
            }
            bssl_sys::init()
        }
        ctor!(do_init);
    }

    // On ELF targets, BoringSSL defines the alg allocators as
    // weak symbols, so just define the symbol ourself.
    #[cfg(not(any(
        target_os = "aix",
        target_os = "ios",
        target_os = "macos",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
    )))]
    mod elf {
        #[allow(clippy::wildcard_imports)]
        use super::*;

        ctor!(bssl_sys::init);

        #[no_mangle]
        unsafe extern "C" fn OPENSSL_memory_alloc(size: usize) -> *mut c_void {
            unsafe { mem_alloc(size) }
        }

        #[no_mangle]
        unsafe extern "C" fn OPENSSL_memory_free(ptr: *mut c_void) {
            unsafe { mem_free(ptr) }
        }

        #[no_mangle]
        unsafe extern "C" fn OPENSSL_memory_get_size(ptr: *mut c_void) -> usize {
            unsafe { mem_size(ptr) }
        }
    }

    /// The number of bytes we reserve at the beginning of each
    /// memory allocation to stash the size.
    const MALLOC_PREFIX: usize = mem::size_of::<usize>();

    /// Returns the layout for `size` aligned to `*mut c_void` or
    /// invokes [`oom`].
    fn layout(size: usize) -> Layout {
        match Layout::from_size_align(size, mem::align_of::<*mut c_void>()) {
            Ok(v) => v,
            Err(_) => oom(),
        }
    }

    /// An implementation of `OPENSSL_memory_alloc`.
    pub unsafe extern "C" fn mem_alloc(size: usize) -> *mut c_void {
        ALLOC_CTR.fetch_add(1, Ordering::Relaxed);

        let total_size = size.checked_add(MALLOC_PREFIX).unwrap_or_else(|| oom());
        let layout = layout(total_size);
        // We've added `MALLOC_PREFIX`, so by definition it
        // should be nonzero.
        assert!(layout.size() > 0);

        // SAFETY: layout has a non-zero size.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            handle_alloc_error(layout);
        }

        // SAFETY: the pointer is valid for writes and we're
        // aligned to `*mut c_void` which should cover `usize`.
        unsafe { ptr.cast::<usize>().write_unaligned(size) }
        // SAFETY: we added `MALLOC_PREFIX` extra bytes
        unsafe { ptr.add(MALLOC_PREFIX) as *mut c_void }
    }

    /// An implementation of `OPENSSL_memory_free`.
    pub unsafe extern "C" fn mem_free(ptr: *mut c_void) {
        // BoringSSL says it'll never pass a null pointer to
        // `OPENSSL_memory_free`.
        assert!(!ptr.is_null());

        FREE_CTR.fetch_add(1, Ordering::Relaxed);

        // SAFETY: we have to trust that `ptr` is valid.
        unsafe {
            let ptr = ptr.cast::<u8>().sub(MALLOC_PREFIX);
            let size = ptr.cast::<usize>().read_unaligned();
            // Per BoringSSL's docs, we're responsible for
            // zeroing the memory before returning it to the
            // system.
            slice::from_raw_parts_mut(ptr, size).zeroize();
            dealloc(ptr, layout(size))
        }
    }

    /// An implementation of `OPENSSL_memory_get_size`.
    pub unsafe extern "C" fn mem_size(ptr: *mut c_void) -> usize {
        // SAFETY: we have to trust that `ptr` is valid.
        unsafe {
            let ptr = ptr.cast::<u8>().sub(MALLOC_PREFIX);
            ptr.cast::<usize>().read_unaligned()
        }
    }

    fn oom() -> ! {
        handle_alloc_error(Layout::new::<()>());
    }
}

/// A BoringSSL Error.
#[derive(Debug)]
pub struct BoringError {
    code: u32,
    file: &'static str,
    line: i32,
}

impl BoringError {
    fn last() -> Self {
        let mut file = ptr::null();
        let mut line = 0;
        // SAFETY: FFI, no invariants.
        let code = unsafe { ERR_get_error_line(ptr::addr_of_mut!(file), ptr::addr_of_mut!(line)) };
        Self {
            code,
            file: Self::make_str(file),
            line,
        }
    }

    /// Returns `ptr` as a `&str`.
    fn make_str(ptr: *const c_char) -> &'static str {
        if ptr.is_null() {
            return "???";
        }
        // SAFETY: the C string is valid for the lifetime of the
        // program.
        let s = unsafe { CStr::from_ptr(ptr) };
        s.to_str().unwrap_or("???")
    }

    fn reason(&self) -> i32 {
        ERR_GET_REASON(self.code)
    }

    fn lib_str(&self) -> &'static str {
        // SAFETY: FFI, no invariants.
        let ptr = unsafe { ERR_lib_error_string(self.code) };
        Self::make_str(ptr)
    }

    fn reason_str(&self) -> &'static str {
        // SAFETY: FFI, no invariants.
        let ptr = unsafe { ERR_reason_error_string(self.code) };
        Self::make_str(ptr)
    }
}

impl fmt::Display for BoringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code == 0 {
            write!(f, "boring: BUG: no error")
        } else {
            write!(
                f,
                "boring: {}:{}: {}: {}",
                self.file,
                self.line,
                self.lib_str(),
                self.reason_str(),
            )
        }
    }
}

impl trouble::Error for BoringError {}

/// Returns the most recent BoringSSL error as an [`SealError`].
fn seal_error() -> SealError {
    let err = BoringError::last();
    match err.reason() {
        CIPHER_R_BUFFER_TOO_SMALL => BufferTooSmallError(None).into(),
        CIPHER_R_INVALID_NONCE_SIZE => InvalidNonceSize.into(),
        CIPHER_R_INVALID_AD_SIZE => SealError::AdditionalDataTooLong,
        // NB: this also happens if the AD is too large, but it's
        // more likely that the PT is too large than the AD, so
        // we choose that error.
        CIPHER_R_TOO_LARGE => SealError::PlaintextTooLong,
        CIPHER_R_TAG_TOO_LARGE => SealError::InvalidOverheadSize,
        CIPHER_R_BAD_KEY_LENGTH | CIPHER_R_INVALID_KEY_LENGTH => SealError::InvalidKeySize,
        _ => SealError::Other(err.reason_str()),
    }
}

/// Returns the most recent BoringSSL error as an [`EcdhError`].
fn ecdh_error() -> EcdhError {
    let err = BoringError::last();
    EcdhError::Other(err.reason_str())
}

/// Returns the most recent BoringSSL error as a [`SignerError`].
fn ecdsa_error() -> SignerError {
    let err = BoringError::last();
    match err.reason() {
        ECDSA_R_BAD_SIGNATURE => SignerError::Encoding(EncodingError::Other(err.reason_str())),
        _ => SignerError::Other(err.reason_str()),
    }
}

/// Returns the most recent BoringSSL error as an
/// [`ImportError`].
fn ec_import_error() -> ImportError {
    let err = BoringError::last();
    match err.reason() {
        EC_R_INVALID_PRIVATE_KEY | EC_R_INVALID_ENCODING => ImportError::InvalidSyntax,
        _ => ImportError::Other(err.reason_str()),
    }
}

macro_rules! indcca2_aead_impl {
    (
        $type:ident,
        $doc:expr,
        $aead:expr,
        $lifetime:expr,
        $max_pt_size:expr,
        $max_ad_size:expr,
        $id:expr $(,)?
    ) => {
        #[doc = concat!($doc, ".")]
        #[repr(align(16))]
        #[cfg_attr(feature = "clone-aead", derive(Clone))]
        pub struct $type(EVP_AEAD_CTX);

        // SAFETY: nothing precludes it from being sent across
        // threads.
        unsafe impl Send for $type {}

        // SAFETY: the BoringSSL docs state that
        // `EVP_AEAD_CTX_seal`, `EVP_AEAD_CTX_open`,
        // `EVP_AEAD_CTX_seal_scatter`, and
        // `EVP_AEAD_CTX_open_gather` may be used concurrently
        // concurrently.
        unsafe impl Sync for $type {}

        impl ZeroizeOnDrop for $type {}
        impl Drop for $type {
            fn drop(&mut self) {
                // SAFETY: FFI, no invariants.
                unsafe { EVP_AEAD_CTX_cleanup(ptr::addr_of_mut!(self.0)) }
            }
        }

        impl IndCca2 for $type {}

        impl Aead for $type {
            const ID: AeadId = $id;

            const LIFETIME: Lifetime = $lifetime;

            type KeySize = U32;
            type NonceSize = U12;
            type Overhead = U16;

            const MAX_PLAINTEXT_SIZE: u64 = $max_pt_size;
            const MAX_ADDITIONAL_DATA_SIZE: u64 = $max_ad_size;

            type Key = AeadKey<Self::KeySize>;

            #[inline]
            fn new(key: &Self::Key) -> Self {
                // Check that our provided constants are correct.
                assert_eq!(
                    Self::KEY_SIZE,
                    // SAFETY: FFI, no invariants.
                    unsafe { EVP_AEAD_key_length($aead()) }
                );
                assert_eq!(
                    Self::NONCE_SIZE,
                    // SAFETY: FFI, no invariants.
                    unsafe { EVP_AEAD_nonce_length($aead()) }
                );

                // Use Self so that the `EVP_AEAD_CTX` is dropped
                // if necessary.
                let mut ctx = Self(EVP_AEAD_CTX::default());

                // SAFETY: FFI, no invariants.
                let ret = unsafe {
                    // It should already be zero, but there isn't
                    // a downside to using the library correctly.
                    EVP_AEAD_CTX_zero(ptr::addr_of_mut!(ctx.0));

                    EVP_AEAD_CTX_init(
                        ptr::addr_of_mut!(ctx.0), // ctx
                        $aead(),                  // aead
                        key.as_slice().as_ptr(),  // key
                        Self::KEY_SIZE,           // key_len
                        Self::OVERHEAD,           // tag_len
                        ptr::null_mut(),          // impl
                    )
                };
                // `EVP_AEAD_CTX_init` only fails if they key
                // size is incorrect (which we've already
                // checked) or if the `EVP_AEAD` is misconfigured
                // (which, since we use the default `EVP_AEAD`
                // implementations, can only happen if it gets
                // corrupted).
                assert_eq!(ret, 1);
                ctx
            }

            #[inline]
            fn seal(
                &self,
                mut dst: &mut [u8],
                nonce: &[u8],
                plaintext: &[u8],
                additional_data: &[u8],
            ) -> Result<(), SealError> {
                check_seal_params::<Self>(&mut dst, nonce, plaintext, additional_data)?;

                // SAFETY: FFI, no invariants.
                let ret = unsafe {
                    let mut dst_len = dst.len();
                    EVP_AEAD_CTX_seal(
                        ptr::addr_of!(self.0),      // ctx
                        dst.as_mut_ptr(),           // out
                        ptr::addr_of_mut!(dst_len), // out_len
                        dst.len(),                  // max_out_len
                        nonce.as_ptr(),             // nonce
                        Self::NONCE_SIZE,           // nonce_len
                        plaintext.as_ptr(),         // in
                        plaintext.len(),            // in_len
                        additional_data.as_ptr(),   // ad
                        additional_data.len(),      // ad_len
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(seal_error())
                }
            }

            #[inline]
            fn seal_in_place(
                &self,
                nonce: &[u8],
                data: &mut [u8],
                tag: &mut [u8],
                additional_data: &[u8],
            ) -> Result<(), SealError> {
                check_seal_in_place_params::<Self>(nonce, data, tag, additional_data)?;

                // SAFETY: We create *mut u8 and *const u8 from
                // data, but:
                //
                // 1. We create them inside this block so they
                // can't be used outside and violate reference
                // aliasing rules.
                // 2. We pass the pointers directly to C.
                let ret = unsafe {
                    let mut tag_len = tag.len();
                    EVP_AEAD_CTX_seal_scatter(
                        ptr::addr_of!(self.0),      // ctx
                        data.as_mut_ptr(),          // out
                        tag.as_mut_ptr(),           // out_tag
                        ptr::addr_of_mut!(tag_len), // out_tag_len
                        tag_len,                    // max_out_len
                        nonce.as_ptr(),             // nonce
                        Self::NONCE_SIZE,           // nonce_len
                        data.as_ptr(),              // in
                        data.len(),                 // in_len
                        ptr::null(),                // extra_in
                        0,                          // extra_in_len
                        additional_data.as_ptr(),   // ad
                        additional_data.len(),      // ad_len
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(seal_error())
                }
            }

            #[inline]
            fn open(
                &self,
                dst: &mut [u8],
                nonce: &[u8],
                ciphertext: &[u8],
                additional_data: &[u8],
            ) -> Result<(), OpenError> {
                check_open_params::<Self>(dst, nonce, ciphertext, additional_data)?;

                // SAFETY: FFI, no invariants.
                let ret = unsafe {
                    let mut dst_len = dst.len();
                    EVP_AEAD_CTX_open(
                        ptr::addr_of!(self.0),      // ctx
                        dst.as_mut_ptr(),           // out
                        ptr::addr_of_mut!(dst_len), // out_len
                        dst.len(),                  // max_out_len
                        nonce.as_ptr(),             // nonce
                        Self::NONCE_SIZE,           // nonce_len
                        ciphertext.as_ptr(),        // in
                        ciphertext.len(),           // in_len
                        additional_data.as_ptr(),   // ad
                        additional_data.len(),      // ad_len
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(OpenError::Authentication)
                }
            }

            #[inline]
            fn open_in_place(
                &self,
                nonce: &[u8],
                data: &mut [u8],
                tag: &[u8],
                additional_data: &[u8],
            ) -> Result<(), OpenError> {
                check_open_in_place_params::<Self>(nonce, data, tag, additional_data)?;

                // SAFETY: We create *mut u8 and *const u8 from
                // data, but:
                //
                // 1. We create them inside this block so they
                // can't be used outside and violate reference
                // aliasing rules.
                // 2. We pass the pointers directly to C.
                let ret = unsafe {
                    EVP_AEAD_CTX_open_gather(
                        ptr::addr_of!(self.0),    // ctx
                        data.as_mut_ptr(),        // out
                        nonce.as_ptr(),           // nonce
                        Self::NONCE_SIZE,         // nonce_len
                        data.as_ptr(),            // in
                        data.len(),               // in_len
                        tag.as_ptr(),             // in_tag
                        tag.len(),                // in_tag_len
                        additional_data.as_ptr(), // ad
                        additional_data.len(),    // ad_len
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(OpenError::Authentication)
                }
            }
        }
    };
}
indcca2_aead_impl!(
    Aes256Gcm,
    "AES-256-GCM",
    EVP_aead_aes_256_gcm,
    Lifetime::Messages(u32::MAX as u64), // random nonce
    (1 << 36) - 32,                      // 2^36 - 32
    (1 << 61) - 1,                       // 2^61 - 1
    AeadId::Aes256Gcm,
);

#[cfg(feature = "committing-aead")]
mod committing {
    use core::ptr;

    use bssl_sys::{AES_encrypt, AES_set_encrypt_key, AES_BLOCK_SIZE, AES_KEY};
    use generic_array::GenericArray;
    use typenum::{Unsigned, U16, U32};

    use super::{Aes256Gcm, Sha256};
    use crate::aead::{AeadKey, BlockCipher};

    /// AES-256.
    #[doc(hidden)]
    pub struct Aes256(AES_KEY);

    impl BlockCipher for Aes256 {
        type BlockSize = U16;
        const BLOCK_SIZE: usize = Self::BlockSize::USIZE;
        type Key = AeadKey<U32>;

        fn new(key: &Self::Key) -> Self {
            let mut v = AES_KEY::default();
            // SAFETY: FFI call, no invariants.
            let ret =
                unsafe { AES_set_encrypt_key(key.as_slice().as_ptr(), 256, ptr::addr_of_mut!(v)) };
            // Unlike other parts of the BoringSSL API, it returns
            // 0 on success.
            assert_eq!(ret, 0);
            Self(v)
        }

        fn encrypt_block(&self, block: &mut GenericArray<u8, Self::BlockSize>) {
            const {
                assert!(Aes256::BLOCK_SIZE == AES_BLOCK_SIZE as usize);
            }

            // SAFETY: FFI call, no invariants.
            unsafe { AES_encrypt(block.as_ptr(), block.as_mut_ptr(), ptr::addr_of!(self.0)) };
        }
    }
    crate::aead::utc_aead!(Cmt1Aes256Gcm, Aes256Gcm, Aes256, "CMT-1 AES-256-GCM.");
    crate::aead::hte_aead!(Cmt4Aes256Gcm, Cmt1Aes256Gcm, Sha256, "CMT-4 AES-256-GCM.");
}
#[cfg(feature = "committing-aead")]
pub use committing::*;

/// An elliptic curve key.
struct EcKey(*mut EC_KEY);

impl EcKey {
    /// Initializes an `EC_KEY` with `f`.
    ///
    /// This allows us to (1) abstract creation of the `EC_KEY`,
    /// which needs to be freed if `f` fails, and (2) always
    /// ensure that the `EC_KEY` is initialized. (BoringSSL
    /// should return an error if it's uninitialized, but why
    /// risk it?)
    fn new<F>(nid: i32, f: F) -> Option<Self>
    where
        F: FnOnce(*mut EC_KEY) -> c_int,
    {
        // EC_KEY_new_by_curve_name can return null if the NID is
        // invalid or if it is unable to allocate memory. We only
        // use constants for the NID, so `key` should only ever
        // be null if we failed to allocate memory.
        let key = Self(
            // SAFETY: FFI call, no invariants
            unsafe { EC_KEY_new_by_curve_name(nid) },
        );
        match f(key.0) {
            1 => Some(key),
            _ => None,
        }
    }

    /// Reports whether the `EC_KEY` is opaque.
    fn is_opaque(&self) -> bool {
        // SAFETY: FFI call, no invariants
        let ret = unsafe { EC_KEY_is_opaque(self.as_ptr()) };
        ret == 1
    }

    /// Returns the public key.
    fn public(&self, nid: i32) -> Self {
        // We could check to see if `self.0` already has a public
        // key, but given BoringSSL's current implementation the
        // check will always be false. Plus, we can only get
        // a ref to the public key which makes this method way
        // more complicated (since we'd have to have two paths:
        // one where we free the point and one where we don't).

        // SAFETY: FFI calls, no invariants
        let point = unsafe {
            let g = EC_KEY_get0_group(self.0);
            let k = EC_KEY_get0_private_key(self.0);
            let q = EC_POINT_new(g);
            // q=g*K
            let ret = EC_POINT_mul(g, q, k, ptr::null(), ptr::null(), ptr::null_mut());
            // Point multiplication should only fail if (a) it
            // cannot allocate memory, or (b) the inputs are
            // misconfigured. We use our own allocator, so (a)
            // won't happen. And (b) will only happen if
            // something gets corrupted.
            assert_eq!(ret, 1);
            q
        };

        // SAFETY: FFI call, no invariants
        Self::new(nid, |key| unsafe { EC_KEY_set_public_key(key, point) })
            .ok_or_else(ec_import_error)
            // SAFETY: FFI call, no invariants
            .inspect_err(|_| unsafe { EC_POINT_free(point) })
            // `EC_KEY_set_public_key` can only fail if the
            // groups are different (including null), and that
            // should only happen if there is a programmer error.
            .expect("should not have failed")
    }

    fn as_ptr(&self) -> *const EC_KEY {
        self.0
    }
}

impl ZeroizeOnDrop for EcKey {}
impl Drop for EcKey {
    fn drop(&mut self) {
        // SAFETY: FFI call, no invariants
        unsafe { EC_KEY_free(self.0) };
    }
}

impl Clone for EcKey {
    fn clone(&self) -> Self {
        Self(
            // SAFETY: FFI call, no invariants
            unsafe { EC_KEY_dup(self.0) },
        )
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
            #[allow(dead_code)] // compiler bug!
            const ID: i32 = $id;
        }
    };
}
curve_impl!(P256, "NIST Curve P-256", NID_secp256r1, Secp256r1);
curve_impl!(P384, "NIST Curve P-384", NID_secp384r1, Secp384r1);
curve_impl!(P521, "NIST Curve P-521", NID_secp521r1, Secp521r1);
curve_impl!(Ed25519, "EdDSA using Ed25519", NID_ED25519, Curve25519);

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
        pub struct $sk(EcKey);

        impl DecapKey for $sk {
            type EncapKey = $pk;

            #[inline]
            fn public(&self) -> $pk {
                let pk = self.0.public($curve::ID);
                $pk(pk)
            }
        }

        impl SecretKey for $sk {
            type Size = <$curve as Curve>::ScalarSize;

            #[inline]
            fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
                if self.0.is_opaque() {
                    Err(ExportError::Opaque)
                } else {
                    let mut out = Scalar::<$curve>::default();
                    // SAFETY: FFI call, no invariants
                    let n =
                        unsafe { EC_KEY_priv2oct(self.0.as_ptr(), out.as_mut_ptr(), out.len()) };
                    // The zero-padded integer will always be
                    // exactly this many bytes.
                    assert_eq!(n, out.len());
                    Ok(SecretKeyBytes::new(out.0))
                }
            }

            #[inline]
            fn new<R: Csprng>(_rng: &mut R) -> Self {
                // SAFETY: FFI call, no invariants
                let key = EcKey::new($curve::ID, |key| unsafe {
                    // No need to perform FIPS compliance
                    // checks unless we're running in FIPS
                    // mode.
                    if cfg!(any(fips, test_fips)) {
                        EC_KEY_generate_key_fips(key)
                    } else {
                        EC_KEY_generate_key(key)
                    }
                })
                .ok_or(ecdh_error())
                .expect("should not have failed");
                Self(key)
            }
        }

        impl ConstantTimeEq for $sk {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    let x = EC_KEY_get0_private_key(self.0.as_ptr());
                    let y = EC_KEY_get0_private_key(other.0.as_ptr());
                    BN_equal_consttime(x, y)
                };
                // BN_equal_consttime states that it only returns
                // 0 or 1, and `Choice` requires exactly that.
                assert!(ret == 1 || ret == 0);

                #[allow(clippy::cast_sign_loss)]
                Choice::from(ret as u8)
            }
        }

        #[cfg(test)]
        impl Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.try_export_secret() {
                    Ok(key) => write!(f, "{}", key.into_bytes().to_hex()),
                    Err(_) => write!(f, "<opaque>"),
                }
            }
        }

        impl Import<SecretKeyBytes<<Self as SecretKey>::Size>> for $sk {
            #[inline]
            fn import(
                data: SecretKeyBytes<<Self as SecretKey>::Size>,
            ) -> Result<Self, ImportError> {
                Self::import(data.as_bytes())
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            #[inline]
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                // SAFETY: FFI call, no invariants
                let key = EcKey::new($curve::ID, |key| unsafe {
                    EC_KEY_oct2priv(key, data.as_ptr(), data.len())
                })
                .ok_or_else(ec_import_error)?;
                Ok(Self(key))
            }
        }

        #[doc = concat!($doc, " ECDH public key.")]
        #[derive(Clone)]
        pub struct $pk(EcKey);

        impl EncapKey for $pk {}

        impl PublicKey for $pk {
            type Data = Uncompressed<$curve>;

            #[inline]
            fn export(&self) -> Self::Data {
                const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t =
                    point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;
                let mut out = Self::Data::default();
                // SAFETY: FFI call, no invariants
                let n = unsafe {
                    EC_POINT_point2oct(
                        EC_KEY_get0_group(self.0.as_ptr()),      // group
                        EC_KEY_get0_public_key(self.0.as_ptr()), // point
                        POINT_CONVERSION_UNCOMPRESSED,           // form
                        out.as_mut_ptr(),                        // buf
                        out.len(),                               // max_out
                        ptr::null_mut(),                         // ctx
                    )
                };
                assert_eq!(n, out.len());
                out
            }
        }

        impl Eq for $pk {}
        impl PartialEq for $pk {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    let g = EC_KEY_get0_group(self.0.as_ptr());
                    let x = EC_KEY_get0_public_key(self.0.as_ptr());
                    let y = EC_KEY_get0_public_key(other.0.as_ptr());
                    EC_POINT_cmp(g, x, y, ptr::null_mut())
                };
                // Only returns -1 on error, which only occurs if
                // the groups don't match, which should not
                // happen as we never construct invalid
                // `EC_KEY`s.
                assert_ge!(ret, 0);

                ret == 0
            }
        }

        impl Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.export().to_hex())
            }
        }

        impl Import<Uncompressed<$curve>> for $pk {
            #[inline]
            fn import(data: Uncompressed<$curve>) -> Result<Self, ImportError> {
                Self::import(data.borrow())
            }
        }

        impl Import<&[u8]> for $pk {
            #[inline]
            fn import(data: &[u8]) -> Result<Self, ImportError> {
                // SAFETY: FFI call, no invariants
                let key = EcKey::new($curve::ID, |key| unsafe {
                    EC_KEY_oct2key(
                        key,             // key
                        data.as_ptr(),   // in
                        data.len(),      // len
                        ptr::null_mut(), // ctx
                    )
                })
                .ok_or_else(ec_import_error)?;
                Ok(Self(key))
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
                let mut dh = SharedSecret::default();
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    ECDH_compute_key(
                        dh.as_mut_ptr() as *mut c_void,            // out
                        dh.len(),                                  // out_len
                        EC_KEY_get0_public_key(remote.0.as_ptr()), // pub_key
                        local.0.as_ptr(),                          // priv_key
                        None,                                      // kdf
                    )
                };
                if ret < 0 {
                    Err(ecdh_error())
                } else {
                    Ok(dh)
                }
            }
        }
    };
}
ecdh_impl!(P256, "NIST Curve P-256", P256PrivateKey, P256PublicKey);
ecdh_impl!(P384, "NIST Curve P-384", P384PrivateKey, P384PublicKey);
ecdh_impl!(P521, "NIST Curve P-521", P521PrivateKey, P521PublicKey);

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
        pub struct $sk(EcKey);

        impl SigningKey<$curve> for $sk {
            #[inline]
            fn sign(&self, msg: &[u8]) -> Result<$sig, SignerError> {
                let digest = $hash::hash(msg);
                let mut sig = [0u8; max_sig_len::<{ $curve::SCALAR_SIZE * 8 }>()];
                let mut sig_len = sig.len() as u32;
                // SAFETY: FFI call, no invariants.
                let ret = unsafe {
                    ECDSA_sign(
                        0,                          // type
                        digest.as_ptr(),            // digest
                        digest.len(),               // digest_len
                        sig.as_mut_ptr(),           // sig
                        ptr::addr_of_mut!(sig_len), // sig_len
                        self.0.as_ptr(),            // key
                    )
                };
                if ret == 1 {
                    Ok(Sig::new(&sig[..sig_len as usize])?)
                } else {
                    Err(ecdsa_error())
                }
            }

            #[inline]
            fn public(&self) -> $pk {
                let pk = self.0.public($curve::ID);
                $pk(pk)
            }
        }

        impl SecretKey for $sk {
            #[inline]
            fn new<R: Csprng>(_rng: &mut R) -> Self {
                // SAFETY: FFI call, no invariants
                let sk = EcKey::new($curve::ID, |key| unsafe {
                    // No need to perform FIPS compliance
                    // checks unless we're running in FIPS
                    // mode.
                    if cfg!(any(fips, test_fips)) {
                        EC_KEY_generate_key_fips(key)
                    } else {
                        EC_KEY_generate_key(key)
                    }
                })
                .ok_or(ecdsa_error())
                .expect("should not have failed");
                Self(sk)
            }

            type Size = <$curve as Curve>::ScalarSize;

            #[inline]
            fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
                if self.0.is_opaque() {
                    Err(ExportError::Opaque)
                } else {
                    let mut out = Scalar::<$curve>::default();
                    // SAFETY: FFI call, no invariants
                    let n =
                        unsafe { EC_KEY_priv2oct(self.0.as_ptr(), out.as_mut_ptr(), out.len()) };
                    // Scalars are fixed size, so anything else
                    // is some sort of programmer error or bug in
                    // BoringSSL.
                    assert_eq!(n, out.len());
                    Ok(SecretKeyBytes::new(out.0))
                }
            }
        }

        #[cfg(test)]
        impl Debug for $sk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.try_export_secret() {
                    Ok(key) => write!(f, "{}", key.into_bytes().to_hex()),
                    Err(_) => write!(f, "<opaque>"),
                }
            }
        }

        impl ConstantTimeEq for $sk {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    let x = EC_KEY_get0_private_key(self.0.as_ptr());
                    let y = EC_KEY_get0_private_key(other.0.as_ptr());
                    BN_equal_consttime(x, y)
                };
                assert!(ret == 1 || ret == 0);

                #[allow(clippy::cast_sign_loss)]
                Choice::from(ret as u8)
            }
        }

        impl Import<SecretKeyBytes<<Self as SecretKey>::Size>> for $sk {
            #[inline]
            fn import(
                data: SecretKeyBytes<<Self as SecretKey>::Size>,
            ) -> Result<Self, ImportError> {
                Self::import(data.as_bytes())
            }
        }

        impl<'a> Import<&'a [u8]> for $sk {
            #[inline]
            fn import(data: &'a [u8]) -> Result<Self, ImportError> {
                // SAFETY: FFI call, no invariants
                let key = EcKey::new($curve::ID, |key| unsafe {
                    EC_KEY_oct2priv(key, data.as_ptr(), data.len())
                })
                .ok_or_else(ec_import_error)?;
                Ok(Self(key))
            }
        }

        #[doc = concat!($doc, " ECDSA public key.")]
        #[derive(Clone)]
        pub struct $pk(EcKey);

        impl VerifyingKey<$curve> for $pk {
            #[inline]
            fn verify(&self, msg: &[u8], sig: &$sig) -> Result<(), SignerError> {
                let digest = $hash::hash(msg);
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    ECDSA_verify(
                        0,                                    // type
                        digest.as_ref().as_ptr(),             // digest
                        digest.as_ref().len(),                // digest_len
                        Borrow::<[u8]>::borrow(sig).as_ptr(), // sig
                        Borrow::<[u8]>::borrow(sig).len(),    // len
                        self.0.as_ptr(),                      // key
                    )
                };
                if ret == 1 {
                    Ok(())
                } else {
                    Err(SignerError::Verification)
                }
            }
        }

        impl PublicKey for $pk {
            type Data = Uncompressed<$curve>;

            #[inline]
            fn export(&self) -> Self::Data {
                const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t =
                    point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;
                let mut out = Self::Data::default();
                // SAFETY: FFI call, no invariants
                let n = unsafe {
                    EC_POINT_point2oct(
                        EC_KEY_get0_group(self.0.as_ptr()),      // group
                        EC_KEY_get0_public_key(self.0.as_ptr()), // point
                        POINT_CONVERSION_UNCOMPRESSED,           // form
                        out.as_mut_ptr(),                        // buf
                        out.len(),                               // max_out
                        ptr::null_mut(),                         // ctx
                    )
                };
                assert_eq!(n, out.len());
                out
            }
        }

        impl Eq for $pk {}
        impl PartialEq for $pk {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                // SAFETY: FFI call, no invariants
                let ret = unsafe {
                    let g = EC_KEY_get0_group(self.0.as_ptr());
                    let x = EC_KEY_get0_public_key(self.0.as_ptr());
                    let y = EC_KEY_get0_public_key(other.0.as_ptr());
                    EC_POINT_cmp(g, x, y, ptr::null_mut())
                };
                // Only returns -1 on error, which only
                // occurs if the groups don't match, which
                // should not happen as we never construct
                // invalid `EC_KEY`s.
                assert_ge!(ret, 0);

                ret == 0
            }
        }

        impl Debug for $pk {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.export().0.to_hex())
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
                // SAFETY: FFI call, no invariants
                let key = EcKey::new($curve::ID, |key| unsafe {
                    EC_KEY_oct2key(
                        key,             // key
                        data.as_ptr(),   // in
                        data.len(),      // len
                        ptr::null_mut(), // ctx
                    )
                })
                .ok_or_else(ec_import_error)?;
                Ok(Self(key))
            }
        }

        #[doc = concat!($doc, " ECDSA signature.")]
        pub type $sig = Sig<$curve, { max_sig_len::<{ $curve::SCALAR_SIZE * 8 }>() }>;

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

impl Signer for Ed25519 {
    const ID: SignerId = SignerId::Ed25519;

    type SigningKey = Ed25519SigningKey;
    type VerifyingKey = Ed25519VerifyingKey;
    type Signature = Ed25519Signature;
}

/// An Ed25519 private key.
#[derive(Clone, ZeroizeOnDrop)]
pub struct Ed25519SigningKey {
    sk: [u8; 64], // seed || public key
}

impl Ed25519SigningKey {
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut sk = [0u8; 64];
        let mut pk = [0u8; 32];
        // SAFETY: FFI call, no invariants
        unsafe {
            ED25519_keypair_from_seed(
                ptr::addr_of_mut!(pk),
                ptr::addr_of_mut!(sk),
                ptr::addr_of!(seed),
            );
        }
        Self { sk }
    }
}

impl SigningKey<Ed25519> for Ed25519SigningKey {
    #[inline]
    fn sign(&self, msg: &[u8]) -> Result<Ed25519Signature, SignerError> {
        let mut out = [0u8; 64];

        // SAFETY: FFI call, no invariants
        let ret = unsafe {
            ED25519_sign(
                ptr::addr_of_mut!(out), // out_sig
                msg.as_ptr(),           // message
                msg.len(),              // message_len
                ptr::addr_of!(self.sk), // private_key
            )
        };
        // Should not fail.
        assert_eq!(ret, 1);

        Ok(Ed25519Signature(out))
    }

    #[inline]
    fn public(&self) -> Ed25519VerifyingKey {
        // sk is seed || public key
        Ed25519VerifyingKey(self.sk[32..].try_into().expect("unreachable"))
    }
}

impl SecretKey for Ed25519SigningKey {
    fn new<R: Csprng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    type Size = U32;

    #[inline]
    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        // sk is seed || public key
        let seed: [u8; 32] = self.sk[..32].try_into().expect("unreachable");
        Ok(SecretKeyBytes::new(seed.into()))
    }
}

#[cfg(test)]
impl Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.sk.to_hex())
    }
}

impl ConstantTimeEq for Ed25519SigningKey {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.sk.ct_eq(&other.sk)
    }
}

impl Import<[u8; 32]> for Ed25519SigningKey {
    #[inline]
    fn import(seed: [u8; 32]) -> Result<Self, ImportError> {
        Ok(Self::from_seed(seed))
    }
}

impl Import<SecretKeyBytes<<Self as SecretKey>::Size>> for Ed25519SigningKey {
    #[inline]
    fn import(seed: SecretKeyBytes<<Self as SecretKey>::Size>) -> Result<Self, ImportError> {
        Ok(Self::from_seed(seed.into_bytes().into_array()))
    }
}

impl<'a> Import<&'a [u8]> for Ed25519SigningKey {
    #[inline]
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

/// An Ed25519 public key.
#[derive(Clone, Eq, PartialEq)]
pub struct Ed25519VerifyingKey([u8; 32]);

impl VerifyingKey<Ed25519> for Ed25519VerifyingKey {
    fn verify(&self, msg: &[u8], sig: &Ed25519Signature) -> Result<(), SignerError> {
        // SAFETY: FFI call, no invariants
        let ret = unsafe {
            ED25519_verify(
                msg.as_ptr(),          // message
                msg.len(),             // message_len
                ptr::addr_of!(sig.0),  // signature
                ptr::addr_of!(self.0), // public_key
            )
        };
        if ret == 1 {
            Ok(())
        } else {
            Err(SignerError::Verification)
        }
    }
}

impl PublicKey for Ed25519VerifyingKey {
    type Data = [u8; 32];

    fn export(&self) -> Self::Data {
        self.0
    }
}

impl Import<[u8; 32]> for Ed25519VerifyingKey {
    fn import(data: [u8; 32]) -> Result<Self, ImportError> {
        Ok(Self(data))
    }
}

impl<'a> Import<&'a [u8]> for Ed25519VerifyingKey {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

impl Debug for Ed25519VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.export().to_hex())
    }
}

/// An Ed25519 signature.
#[derive(Clone, Debug)]
pub struct Ed25519Signature([u8; 64]);

impl Signature<Ed25519> for Ed25519Signature {
    type Data = [u8; 64];

    fn export(&self) -> Self::Data {
        self.0
    }
}

impl Borrow<[u8]> for Ed25519Signature {
    #[inline]
    fn borrow(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Import<[u8; 64]> for Ed25519Signature {
    #[inline]
    fn import(data: [u8; 64]) -> Result<Self, ImportError> {
        Ok(Self(data))
    }
}

impl<'a> Import<&'a [u8]> for Ed25519Signature {
    #[inline]
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        try_import(data)
    }
}

/// A CSPRNG.
#[derive(Clone, Copy)]
pub struct Rand;

impl Csprng for Rand {
    #[inline]
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        // SAFETY: FFI call, no invariants
        let ret = unsafe { RAND_bytes(dst.as_mut_ptr(), dst.len()) };
        // RAND_bytes aborts on failure.
        assert_eq!(ret, 1);
    }
}

macro_rules! hash_impl {
    (
        $type:ident,
        $doc:expr,
        $ctx:ident,
        $hash:ident,
        $init:ident,
        $update:ident,
        $final:ident,
        $digest_size:expr,
        $block_size:expr $(,)?
    ) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone, Default)]
        pub struct $type($ctx);

        impl Hash for $type {
            const ID: HashId = HashId::$type;

            type DigestSize = U<{ $digest_size as usize }>;
            const DIGEST_SIZE: usize = $digest_size as usize;

            const BLOCK_SIZE: usize = $block_size as usize;
            type Block = Block<{ $block_size as usize }>;

            #[inline]
            fn new() -> Self {
                let mut h = Self::default();
                // SAFETY: FFI call, no invariants
                let ret = unsafe { $init(ptr::addr_of_mut!(h.0)) };
                assert_eq!(ret, 1); // always returns 1
                h
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                if data.is_empty() {
                    return;
                }
                // SAFETY: FFI call, no invariants
                let ret =
                    unsafe { $update(&mut self.0, data.as_ptr() as *const c_void, data.len()) };
                assert_eq!(ret, 1); // always returns 1
            }

            #[inline]
            fn digest(mut self) -> Digest<Self::DigestSize> {
                let mut out = [0u8; $digest_size as usize];

                // SAFETY: FFI call, no invariants
                let ret = unsafe { $final(ptr::addr_of_mut!(out), ptr::addr_of_mut!(self.0)) };
                // Per the BoringSSL docs, the SHA*_Final
                // routines do not always return 1 like the other
                // routines do. However, the only time they will
                // return anything other than 1 is if `out` is
                // null or `ctx` is corrupted, both of which
                // cannot happen without some other catastrophic
                // failure.
                assert_eq!(ret, 1);

                Digest::new(out.into())
            }

            #[inline]
            fn hash(data: &[u8]) -> Digest<Self::DigestSize> {
                let mut out = [0u8; $digest_size as usize];
                // SAFETY: FFI call, no invariants
                unsafe {
                    $hash(data.as_ptr(), data.len(), ptr::addr_of_mut!(out));
                }
                Digest::new(out.into())
            }
        }
    };
}
hash_impl!(
    Sha256,
    "SHA-256",
    SHA256_CTX,
    SHA256,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final,
    SHA256_DIGEST_LENGTH,
    SHA256_CBLOCK,
);
hash_impl!(
    Sha384,
    "SHA-384",
    SHA512_CTX, // this is correct
    SHA384,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final,
    SHA384_DIGEST_LENGTH,
    SHA384_CBLOCK,
);
hash_impl!(
    Sha512_256,
    "SHA-512/256",
    SHA512_CTX, // this is correct
    SHA512_256,
    SHA512_256_Init,
    SHA512_256_Update,
    SHA512_256_Final,
    SHA512_256_DIGEST_LENGTH,
    SHA512_CBLOCK,
);
hash_impl!(
    Sha512,
    "SHA-512",
    SHA512_CTX,
    SHA512,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final,
    SHA512_DIGEST_LENGTH,
    SHA512_CBLOCK,
);

// FIPS compliant cryptography.
//
// There is still FIPS compliant crypto outside of this module.
// However, this module contains stuff that we *only* want to use
// in FIPS mode. For example, we have our own implementations of
// stuff (like HKDF) that perform better.
#[cfg_attr(docsrs, doc(cfg(any(fips, test_fips))))]
#[cfg(any(fips, test_fips))]
mod lame_crypto {
    #[allow(clippy::wildcard_imports)]
    use {
        super::*,
        bssl_sys::{
            CRYPTO_memcmp, EVP_MD_size, EVP_sha256, EVP_sha384, EVP_sha512, HKDF_expand,
            HKDF_extract, HMAC_CTX_cleanse, HMAC_CTX_copy_ex, HMAC_CTX_init, HMAC_Final,
            HMAC_Init_ex, HMAC_Update, HKDF, HMAC, HMAC_CTX,
        },
        core::ptr,
    };

    macro_rules! hkdf_impl {
        ($name:ident, $doc_name:expr, $hash_len:expr, $digest:ident) => {
            #[doc = concat!($doc_name, ".")]
            pub struct $name;

            impl $name {
                fn hash_len() -> usize {
                    // SAFETY: FFI call, no invariants.
                    unsafe { EVP_MD_size($digest()) }
                }
            }

            impl Kdf for $name {
                const ID: KdfId = KdfId::$name;

                const MAX_OUTPUT: usize = 255 * $hash_len;

                type Prk = Prk<$hash_len>;

                #[inline]
                fn extract_multi(ikm: &[&[u8]], salt: &[u8]) -> Self::Prk {
                    Self::extract(&ikm.concat(), salt)
                }

                #[inline]
                fn extract(ikm: &[u8], salt: &[u8]) -> Self::Prk {
                    let mut out = [0u8; $hash_len];
                    let mut out_len = out.len();
                    // SAFETY: FFI call, no invariants
                    let ret = unsafe {
                        HKDF_extract(
                            out.as_mut_ptr(),           // out_key
                            ptr::addr_of_mut!(out_len), // out_len
                            $digest(),                  // digest
                            ikm.as_ptr(),               // secret
                            ikm.len(),                  // secret_len
                            salt.as_ptr(),              // salt
                            salt.len(),                 // salt_len
                        )
                    };
                    // HKDF_extract only fails if HMAC fails, and
                    // HMAC only fails if the underlying hash does.
                    // We use SHA-512, which cannot fail. So,
                    // HKDF_extract returning anything other than
                    // 1 is a catastrophic bug.
                    assert_eq!(ret, 1);
                    // We should always get exactly the number of
                    // bytes we ask for. If we don't, it's a bug in
                    // BoringSSL.
                    assert_eq!(out_len, out.len());
                    out.into()
                }

                #[inline]
                fn expand_multi(
                    out: &mut [u8],
                    prk: &Self::Prk,
                    info: &[&[u8]],
                ) -> Result<(), KdfError> {
                    Self::expand(out, prk, &info.concat())
                }

                #[inline]
                fn expand(out: &mut [u8], prk: &Self::Prk, info: &[u8]) -> Result<(), KdfError> {
                    // SAFETY: FFI call, no invariants
                    let ret = unsafe {
                        HKDF_expand(
                            out.as_mut_ptr(),      // out_key
                            out.len(),             // out_len
                            $digest(),             // digest
                            prk.as_ref().as_ptr(), // prk
                            prk.as_ref().len(),    // prk_len
                            info.as_ptr(),         // info
                            info.len(),            // info_len
                        )
                    };
                    if ret == 1 {
                        Ok(())
                    } else {
                        // HKDF_expand only fails if (1) HMAC,
                        // does, or (2) the requested output is
                        // too long.  HMAC-SHA-512 should never
                        // fail, so this means the user requested
                        // too much data.
                        assert!(out.len() > 255 * 64);
                        Err(KdfError::OutputTooLong)
                    }
                }

                #[inline]
                fn extract_and_expand_multi(
                    out: &mut [u8],
                    ikm: &[&[u8]],
                    salt: &[u8],
                    info: &[&[u8]],
                ) -> Result<(), KdfError> {
                    Self::extract_and_expand(out, &ikm.concat(), salt, &info.concat())
                }

                #[inline]
                fn extract_and_expand(
                    out: &mut [u8],
                    ikm: &[u8],
                    salt: &[u8],
                    info: &[u8],
                ) -> Result<(), KdfError> {
                    // SAFETY: FFI call, no invariants
                    let ret = unsafe {
                        HKDF(
                            out.as_mut_ptr(), // out_key
                            out.len(),        // out_len
                            $digest(),        // digest
                            ikm.as_ptr(),     // secret
                            ikm.len(),        // secret_len
                            salt.as_ptr(),    // salt
                            salt.len(),       // salt_len
                            info.as_ptr(),    // info
                            info.len(),       // info_len
                        )
                    };
                    if ret == 1 {
                        Ok(())
                    } else {
                        // HKDF only fails if (1) HMAC, does, or
                        // (2) the requested output is too long.
                        // HMAC-SHA-512 should never fail, so
                        // this means the user requested too much
                        // data.
                        assert_eq!(Self::MAX_OUTPUT, 255 * Self::hash_len());
                        assert!(out.len() > 255 * Self::hash_len());
                        Err(KdfError::OutputTooLong)
                    }
                }
            }
        };
    }
    hkdf_impl!(HkdfSha256, "HKDF-SHA256", 32, EVP_sha256);
    hkdf_impl!(HkdfSha384, "HKDF-SHA384", 48, EVP_sha384);
    hkdf_impl!(HkdfSha512, "HKDF-SHA512", 64, EVP_sha512);

    fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut out_len = out.len() as u32;

        // SAFETY: FFI call, no invariants
        let ret = unsafe {
            HMAC(
                EVP_sha512(),
                key.as_ptr() as *const c_void,
                key.len(),
                data.as_ptr(),
                data.len(),
                out.as_mut_ptr(),
                ptr::addr_of_mut!(out_len),
            )
        };
        assert!(!ret.is_null());
        assert_eq!(out_len as usize, out.len());
        out
    }

    /// HMAC-SHA-512.
    pub struct HmacSha512(HMAC_CTX);

    impl HmacSha512 {
        const DIGEST_SIZE: usize = 64;
        const BLOCK_SIZE: usize = 128;

        fn check_key(key: &[u8]) -> Result<(), MacError> {
            // Reject len(K) < L.
            if key.len() < Self::DIGEST_SIZE {
                return Err(MacError::InsecureKey);
            }
            // Reject len(K) > B.
            if key.len() > Self::BLOCK_SIZE {
                return Err(MacError::InsecureKey);
            }
            Ok(())
        }
    }

    impl ZeroizeOnDrop for HmacSha512 {}
    impl Drop for HmacSha512 {
        fn drop(&mut self) {
            // SAFETY: FFI call, no invariants
            unsafe { HMAC_CTX_cleanse(ptr::addr_of_mut!(self.0)) }
        }
    }

    impl Clone for HmacSha512 {
        fn clone(&self) -> Self {
            let mut v = Self(HMAC_CTX::default());
            v.clone_from(self);
            v
        }

        fn clone_from(&mut self, src: &Self) {
            // SAFETY: FFI call, no invariants
            let ret = unsafe {
                HMAC_CTX_init(ptr::addr_of_mut!(self.0));
                HMAC_CTX_copy_ex(ptr::addr_of_mut!(self.0), ptr::addr_of!(src.0))
            };
            assert_eq!(ret, 1);
        }
    }

    impl Mac for HmacSha512 {
        type Tag = Tag<64>;

        #[inline]
        fn new(key: &Self::Key) -> Self {
            Self::check_key(key)?;

            let mut ctx = HMAC_CTX::default();
            // SAFETY: FFI call, no invariants
            let ret = unsafe {
                HMAC_CTX_init(ptr::addr_of_mut!(ctx));
                HMAC_Init_ex(
                    ptr::addr_of_mut!(ctx),
                    key.as_ptr() as *const c_void,
                    key.len(),
                    EVP_sha512(),
                    ptr::null_mut(),
                )
            };
            // HMAC_Init_ex returns 0 on allocation failure,
            // which our allocator should catch.
            assert_eq!(ret, 1);

            Ok(Self(ctx))
        }

        #[inline]
        fn update(&mut self, data: &[u8]) {
            if data.is_empty() {
                return;
            }
            // SAFETY: FFI call, no invariants
            let ret = unsafe { HMAC_Update(&mut self.0, data.as_ptr(), data.len()) };
            assert_eq!(ret, 1); // always returns 1
        }

        #[inline]
        fn tag(mut self) -> Tag<64> {
            let mut out = [0u8; 64];
            let mut out_len = out.len() as u32;

            // SAFETY: FFI call, no invariants
            let ret = unsafe {
                HMAC_Final(
                    ptr::addr_of_mut!(self.0),
                    out.as_mut_ptr(),
                    ptr::addr_of_mut!(out_len),
                )
            };

            // Per the BoringSSL docs, HMAC_final does not always
            // return 1 like the other HMAC_* routines do. However,
            // the only time they will return anything other than 1
            // is if `out` is null, too small, or `ctx` is corrupted,
            // both of which cannot happen without some other
            // catastophic failure.
            assert_eq!(ret, 1);
            assert_eq!(out_len as usize, out.len());

            out.into()
        }

        #[inline]
        fn verify(self, expect: &Tag<64>) -> Result<(), MacError> {
            let got = self.tag();
            // SAFETY: FFI call, no invariants
            let ret = unsafe {
                CRYPTO_memcmp(
                    got.as_ref().as_ptr() as *const c_void,
                    expect.as_ref().as_ptr() as *const c_void,
                    expect.as_ref().len(),
                )
            };
            if ret == 0 {
                Ok(())
            } else {
                Err(MacError::Verification)
            }
        }

        #[inline]
        fn mac(key: &[u8], data: &[u8]) -> Result<Tag<64>, MacError> {
            Self::check_key(key)?;
            Ok(hmac_sha512(key, data).into())
        }
    }
}

// Non-FIPS compliant cryptography.
//
// This module contains stuff that we can only use while *not* in
// FIPS mode.
#[cfg_attr(docsrs, doc(cfg(not(fips))))]
#[cfg(not(fips))]
mod fun_crypto {
    #[allow(clippy::wildcard_imports)]
    use {
        super::*,
        crate::{hkdf::hkdf_impl, hmac::hmac_impl},
        bssl_sys::{
            EVP_AEAD_CTX_open, EVP_aead_chacha20_poly1305, X25519_keypair,
            X25519_public_from_private, NID_X25519, X25519 as X25519_ecdh,
        },
        core::{
            fmt::{self, Debug},
            ptr,
            result::Result,
        },
        subtle::{Choice, ConstantTimeEq},
    };

    // AES-256-GCM-SIV is disabled for x86-64 because it doesn't
    // currently support EVP_AEAD_CTX_open_gather.

    #[cfg(any(docsrs, not(target_arch = "x86_64")))]
    indcca2_aead_impl!(
        Aes256GcmSiv,
        "AES-256-GCM-SIV",
        bssl_sys::EVP_aead_aes_256_gcm_siv,
        // Assumes a random nonce.
        //
        // We can technically go higher than this, but it's not
        // worth it.
        Lifetime::Messages(u32::MAX as u64),
        (1 << 36) - 32, // 2^36 - 32
        (1 << 61) - 1,  // 2^61 - 1
        // SAFETY: obviously non-zero
        AeadId::Other(unsafe { core::num::NonZeroU16::new_unchecked(0xfffe) }),
    );

    indcca2_aead_impl!(
        ChaCha20Poly1305,
        "ChaCha20-Poly1305",
        EVP_aead_chacha20_poly1305,
        Lifetime::Messages(u64::MAX),
        // 64*(2^32)-64 = 2^38-64
        (1 << 38) - 64,
        // 2^64-1 from RFC 7539.
        u64::MAX,
        AeadId::ChaCha20Poly1305,
    );

    curve_impl!(X25519, "ECDH using Curve25519", NID_X25519, Curve25519);

    dhkem_impl!(
        DhKemX25519HkdfSha256,
        "DHKEM(X25519, HKDF-SHA256)",
        X25519,
        HkdfSha256,
        X25519PrivateKey,
        X25519PublicKey,
    );

    hkdf_impl!(HkdfSha256, "HKDF-SHA256", Sha256);
    hkdf_impl!(HkdfSha384, "HKDF-SHA384", Sha384);
    hkdf_impl!(HkdfSha512, "HKDF-SHA512", Sha512);

    hmac_impl!(HmacSha256, "HMAC-SHA256", Sha256);
    hmac_impl!(HmacSha384, "HMAC-SHA384", Sha384);
    hmac_impl!(HmacSha512, "HMAC-SHA512", Sha512);

    impl Ecdh for X25519 {
        const SCALAR_SIZE: usize = 32;

        type PrivateKey = X25519PrivateKey;
        type PublicKey = X25519PublicKey;
        type SharedSecret = X25519SharedSecret;

        fn ecdh(
            local: &Self::PrivateKey,
            remote: &Self::PublicKey,
        ) -> Result<Self::SharedSecret, EcdhError> {
            let mut dh = [0u8; 32];
            // SAFETY: FFI call, no invariants
            let ret = unsafe {
                X25519_ecdh(
                    ptr::addr_of_mut!(dh),
                    ptr::addr_of!(local.0),
                    ptr::addr_of!(remote.0),
                )
            };
            if ret == 1 {
                Ok(X25519SharedSecret(dh))
            } else {
                Err(EcdhError::Other("small order point"))
            }
        }
    }

    /// An X25519 private key.
    #[derive(Clone, ZeroizeOnDrop)]
    pub struct X25519PrivateKey([u8; 32]);

    impl DecapKey for X25519PrivateKey {
        type EncapKey = X25519PublicKey;

        #[inline]
        fn public(&self) -> Self::EncapKey {
            let mut pk = [0u8; 32];
            // SAFETY: FFI call, no invariants
            unsafe { X25519_public_from_private(ptr::addr_of_mut!(pk), ptr::addr_of!(self.0)) }
            X25519PublicKey(pk)
        }
    }

    impl SecretKey for X25519PrivateKey {
        type Size = <Curve25519 as Curve>::ScalarSize;

        #[inline]
        fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
            Ok(SecretKeyBytes::new(self.0.into()))
        }

        fn new<R: Csprng>(_rng: &mut R) -> Self {
            let mut sk = [0u8; 32];
            let mut pk = [0u8; 32];
            // SAFETY: FFI call, no invariants
            unsafe { X25519_keypair(ptr::addr_of_mut!(pk), ptr::addr_of_mut!(sk)) }
            Self(sk)
        }
    }

    impl Import<Scalar<Curve25519>> for X25519PrivateKey {
        #[inline]
        fn import(data: Scalar<Curve25519>) -> Result<Self, ImportError> {
            Self::import(data.borrow())
        }
    }

    impl<'a> Import<&'a [u8]> for X25519PrivateKey {
        #[inline]
        fn import(data: &[u8]) -> Result<Self, ImportError> {
            Ok(Self(Scalar::<Curve25519>::import(data)?.into()))
        }
    }

    impl ConstantTimeEq for X25519PrivateKey {
        #[inline]
        fn ct_eq(&self, other: &Self) -> Choice {
            self.0.ct_eq(&other.0)
        }
    }

    #[cfg(test)]
    impl Debug for X25519PrivateKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", &self.0.to_hex())
        }
    }

    /// An X25519 public key.
    #[derive(Clone, Eq, PartialEq)]
    pub struct X25519PublicKey([u8; 32]);

    impl EncapKey for X25519PublicKey {}

    impl PublicKey for X25519PublicKey {
        type Data = [u8; 32];

        #[inline]
        fn export(&self) -> Self::Data {
            self.0
        }
    }

    impl Import<[u8; 32]> for X25519PublicKey {
        #[inline]
        fn import(data: [u8; 32]) -> Result<Self, ImportError> {
            Ok(Self(data))
        }
    }

    impl<'a> Import<&'a [u8]> for X25519PublicKey {
        #[inline]
        fn import(data: &[u8]) -> Result<Self, ImportError> {
            try_import(data)
        }
    }

    impl Debug for X25519PublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.export().fmt(f)
        }
    }

    /// An X25519 shared secret.
    #[derive(ZeroizeOnDrop, Default)]
    pub struct X25519SharedSecret([u8; 32]);

    impl Borrow<[u8]> for X25519SharedSecret {
        #[inline]
        fn borrow(&self) -> &[u8] {
            self.0.as_ref()
        }
    }

    impl BorrowMut<[u8]> for X25519SharedSecret {
        #[inline]
        fn borrow_mut(&mut self) -> &mut [u8] {
            self.0.as_mut()
        }
    }

    #[cfg(test)]
    #[allow(clippy::wildcard_imports)]
    mod tests {
        use super::*;

        // Test some [`CipherSuite`] configurations.
        mod ciphersuite_tests {
            use super::*;
            use crate::test_util::{test_ciphersuite, TestCs};

            test_ciphersuite!(chacha20poly1305, TestCs<
                ChaCha20Poly1305,
                Sha512,
                HkdfSha256,
                DhKemX25519HkdfSha256,
                HmacSha512,
                Ed25519,
            >);

            #[cfg(not(target_arch = "x86_64"))]
            test_ciphersuite!(aes256gcmsiv, TestCs<
                Aes256GcmSiv,
                Sha512,
                HkdfSha384,
                DhKemX25519HkdfSha256,
                HmacSha512,
                Ed25519,
            >);

            test_ciphersuite!(aes256gcm, TestCs<
                Aes256Gcm,
                Sha512,
                HkdfSha512,
                DhKemX25519HkdfSha256,
                HmacSha512,
                Ed25519,
            >);
        }

        mod aead_tests {
            use super::*;
            use crate::test_util::test_aead;

            #[cfg(not(target_arch = "x86_64"))]
            test_aead!(aes256gcmsiv, Aes256GcmSiv, AeadTest::AesGcmSiv);

            test_aead!(
                chacha20poly1305,
                ChaCha20Poly1305,
                AeadTest::ChaCha20Poly1305
            );
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
            use crate::{
                hpke::{Hpke, Mode},
                kdf::Kdf,
                test_util::test_hpke,
            };

            test_hpke!(
                p256_hkdfsha256_chacha20poly1305,
                DhKemP256HkdfSha256,
                HkdfSha256,
                ChaCha20Poly1305,
                HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha256ChaCha20Poly1305,
            );

            test_hpke!(
                p256_hkdfsha512_chacha20poly1305,
                DhKemP256HkdfSha256,
                HkdfSha512,
                ChaCha20Poly1305,
                HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha512ChaCha20Poly1305,
            );

            test_hpke!(
                x25519_hkdfsha256_aes256gcm,
                DhKemX25519HkdfSha256,
                HkdfSha256,
                Aes256Gcm,
                HpkeTest::HpkeDhKemX25519HkdfSha256HkdfSha256Aes256Gcm,
            );

            test_hpke!(
                x25519_hkdfsha512_aes256gcm,
                DhKemX25519HkdfSha256,
                HkdfSha512,
                Aes256Gcm,
                HpkeTest::HpkeDhKemX25519HkdfSha256HkdfSha512Aes256Gcm,
            );

            test_hpke!(
                x25519_hkdfsha256_chacha20poly1305,
                DhKemX25519HkdfSha256,
                HkdfSha256,
                ChaCha20Poly1305,
                HpkeTest::HpkeDhKemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
            );

            test_hpke!(
                x25519_hkdfsha512_chacha20poly1305,
                DhKemX25519HkdfSha256,
                HkdfSha512,
                ChaCha20Poly1305,
                HpkeTest::HpkeDhKemX25519HkdfSha256HkdfSha512ChaCha20Poly1305,
            );

            // Test borrowed from BoringSSL.
            fn test_x25519_small_order_point<K, F, A>()
            where
                K: Kem<Encap = [u8; 32], DecapKey = X25519PrivateKey, EncapKey = X25519PublicKey>,
                F: Kdf,
                A: Aead + IndCca2,
            {
                let small_order = K::EncapKey::import([
                    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1,
                    0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62,
                    0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
                ])
                .expect("unable to import public key");

                let valid = K::EncapKey::import([
                    0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24,
                    0xb1, 0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9,
                    0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
                ])
                .expect("unable to import public key");

                // pkR = small_order
                Hpke::<K, F, A>::setup_send(&mut Rand, Mode::Base, &small_order, &[])
                    .err()
                    .expect("should not succeed");
                let key = Mode::Auth(K::DecapKey::new(&mut Rand));
                // Also in auth mode.
                Hpke::<K, F, A>::setup_send(&mut Rand, key.as_ref(), &small_order, &[])
                    .err()
                    .expect("should not succeed");

                // enc = small_order
                Hpke::<K, F, A>::setup_recv(
                    Mode::Base,
                    &small_order.export(),
                    &K::DecapKey::new(&mut Rand),
                    &[],
                )
                .err()
                .expect("should not succeed");

                // pkSm = small_order
                Hpke::<K, F, A>::setup_recv(
                    Mode::Auth(small_order.clone()).as_ref(),
                    &valid.export(),
                    &K::DecapKey::new(&mut Rand),
                    &[],
                )
                .err()
                .expect("should not succeed");
                // skR = small_order
                Hpke::<K, F, A>::setup_recv(
                    Mode::Auth(valid).as_ref(),
                    &small_order.export(),
                    &K::DecapKey::new(&mut Rand),
                    &[],
                )
                .err()
                .expect("should not succeed");
            }

            #[test]
            fn test_hpke_dhkem_x25519_hkdfsha256_hkdfsha256_chacha20poly1305_small_order_point() {
                test_x25519_small_order_point::<DhKemX25519HkdfSha256, HkdfSha256, ChaCha20Poly1305>(
                )
            }

            #[test]
            fn test_hpke_dhkem_x25519_hkdfsha256_hkdfsha512_chacha20poly1305_small_order_point() {
                test_x25519_small_order_point::<DhKemX25519HkdfSha256, HkdfSha512, ChaCha20Poly1305>(
                )
            }

            #[test]
            fn test_hpke_dhkem_x25519_hkdfsha256_hkdfsha256_aes256gcm_small_order_point() {
                test_x25519_small_order_point::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>()
            }

            #[test]
            fn test_hpke_dhkem_x25519_hkdfsha256_hkdfsha512_aes256gcm_small_order_point() {
                test_x25519_small_order_point::<DhKemX25519HkdfSha256, HkdfSha512, Aes256Gcm>()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test some [`CipherSuite`] configurations.
    mod ciphersuite_tests {
        use super::*;
        use crate::test_util::{test_ciphersuite, TestCs};

        test_ciphersuite!(ed25519, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha256,
            DhKemP256HkdfSha256,
            HmacSha512,
            Ed25519,
        >);
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
        test_ciphersuite!(p521, TestCs<
            Aes256Gcm,
            Sha512,
            HkdfSha512,
            DhKemP521HkdfSha512,
            HmacSha512,
            P521,
        >);
    }

    mod alloc_tests {
        use core::sync::atomic::Ordering;

        use bssl_sys::{OPENSSL_free, OPENSSL_malloc};
        use rust_alloc::mem_size;

        use super::*;

        /// Test that [`mem_size`] reports accurate sizes.
        #[test]
        fn test_allocator_size() {
            for i in 0..4097 {
                // SAFETY: FFI call, no invariants
                let ptr = unsafe { OPENSSL_malloc(i) };
                // SAFETY: FFI call, no invariants
                let size = unsafe { mem_size(ptr) };
                assert_eq!(size, i);
                // SAFETY: FFI call, no invariants
                unsafe { OPENSSL_free(ptr) };
            }
        }

        /// Test that that BoringSSL uses our custom allocator by
        /// invoking [`OPENSSL_malloc`] and [`OPENSSL_free`]
        /// directly.
        #[test]
        fn test_allocator_direct() {
            let before = rust_alloc::ALLOC_CTR.load(Ordering::Relaxed);
            // SAFETY: FFI call, no invariants
            let ptr = unsafe { OPENSSL_malloc(42) };
            let after = rust_alloc::ALLOC_CTR.load(Ordering::Relaxed);
            assert!(before < after);

            let before = rust_alloc::FREE_CTR.load(Ordering::Relaxed);
            // SAFETY: FFI call, no invariants
            unsafe { OPENSSL_free(ptr) };
            let after = rust_alloc::FREE_CTR.load(Ordering::Relaxed);
            assert!(before < after);
        }

        /// Test that BoringSSL uses our custom allocator by
        /// performing an action that allocates memory.
        #[test]
        fn test_allocator_indirect() {
            let before = rust_alloc::ALLOC_CTR.load(Ordering::Relaxed);
            P256SigningKey::new(&mut Rand);
            let after = rust_alloc::ALLOC_CTR.load(Ordering::Relaxed);
            assert!(before < after);
        }
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

        #[test]
        fn test_ecdh_p521() {
            test_ecdh::<P521>(EcdhTest::EcdhSecp521r1Ecpoint);
        }
    }

    mod ecdsa_tests {
        use super::*;
        use crate::test_util::test_signer;

        test_signer!(p256, P256, EcdsaTest::EcdsaSecp256r1Sha256);
        test_signer!(p384, P384, EcdsaTest::EcdsaSecp384r1Sha384);
        test_signer!(p521, P521, EcdsaTest::EcdsaSecp521r1Sha512);
    }

    mod eddsa_tests {
        use super::*;
        use crate::test_util::test_signer;

        test_signer!(ed25519, Ed25519, EddsaTest::Ed25519);
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

        test_mac!(test_hmac_sha512, HmacSha512, MacTest::HmacSha512);
    }

    mod hpke_tests {
        use super::*;
        use crate::test_util::test_hpke;

        test_hpke!(
            p256_hkdf_sha256,
            DhKemP256HkdfSha256,
            HkdfSha256,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
        );
        test_hpke!(
            p256_hkdf_sha512,
            DhKemP256HkdfSha256,
            HkdfSha512,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
        );
        test_hpke!(
            p521_hkdf_sha256,
            DhKemP521HkdfSha512,
            HkdfSha256,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP521HkdfSha512HkdfSha256Aes256Gcm,
        );
        test_hpke!(
            p521_hkdf_sha512,
            DhKemP521HkdfSha512,
            HkdfSha512,
            Aes256Gcm,
            HpkeTest::HpkeDhKemP521HkdfSha512HkdfSha512Aes256Gcm,
        );
    }
}
