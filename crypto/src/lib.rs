#![feature(error_in_core)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;

pub use aead::Aead;
use alloc::string::String;
use alloc::vec::Vec;
use core::error::Error;
pub use digest::{DynDigest, Mac};

/// Engine is a set of cryptographic primitives used by
/// a particular protocol version.
pub trait Engine<P, U>
where
    P: PrivateKey<U>,
    U: PublicKey,
{
    /// Error is an engine error.
    type Error: Error;
    /// aead creates a symmetric cipher implementing a particular
    /// Authenticated Encryption with Associated Data (AEAD)
    /// algorithm.
    ///
    /// Briefly, AEAD encryption is a construction with four
    /// inputs:
    ///
    ///  1. uniformly random key K
    ///  2. nonce N that is unique for each unique (K, P) tuple
    ///  3. plaintext P which will be encrypted
    ///  4. associated data A that will be authenticated, but not
    ///     encrypted
    ///
    /// It outputs a ciphertext C, which is at least as long as P.
    /// AEAD decryption works in the inverse manner. For formal
    /// and more comprehensive documentation, see RFC 5116.
    ///
    /// This API is more restrictive than RFC 5116. Specifically,
    /// the cipher must:
    ///
    ///  * Only use 256-bit keys
    ///  * Have at minimum a 256-bit security level for
    ///    confidentiality
    ///  * Have at minimum a 128-bit security level for
    ///    authentication
    ///  * Accept plaintexts up to 2³⁹-256 bits long
    ///  * Accept associated data up to 2⁶⁴-1 bits long
    ///
    /// Examples of AEAD algorithms that fulfill these
    /// requirements include AES-256-GCM and ChaCha20Poly1305.
    type Aead: Aead;

    /// kdf creates an extract-then-expand Key Derivation Function (KDF).
    ///
    /// It is not suitable for deriving keys from passwords.
    type Kdf: Kdf;

    /// mac creates a keyed Message Authentication Function (MAC).
    ///
    /// The MAC must:
    ///
    ///  * Accept 512-bit keys
    ///  * Produce 512-bit tags
    ///  * Have at minimum a 256-bit security level
    ///  * Reject insecure keys
    ///  * Be at least strongly EUF-CMA secure
    ///  * Be a PRF
    ///
    /// Examples of keyed MAC algorithms that fulfill these
    /// requirements include HMAC-SHA-512 (for |K| in [L, B]) and
    /// KMAC256 (for |K| >= 256).
    type Mac: Mac;

    /// kem creates a Key Encapsulation Mechanism (KEM).
    type Kem: Kem<P, U>;

    /// signer creates a digital signature mechanism
    type Signer: Signer<P, U>;

    /// hash creates a cryptographic hash function.
    ///
    /// The function must:
    ///
    ///  * Produce 512-bit digests
    ///  * Have pre-image resistance
    ///  * Be collision resistant (and thus second pre-image
    ///    resistance)
    ///
    /// The function does not need to be resistant to
    /// length-extension attacks.
    ///
    /// Examples of cryptographic hash functions that fulfill
    /// these requirements include SHA-512 and SHA3-512.
    type Hash: DynDigest;

    /// tuple_hash returns the cryptographic hash over the strings
    /// in s such that each input is unambiguously encoded.
    ///
    /// In short, this means that H("abc", "d") creates
    /// a different hash value from H("abcd") and H("a", "bcd").
    ///
    /// Examples of algorithms that fulfill these requirements
    /// include [NIST]'s SHA-3 TupleHash function.
    ///
    /// The choice of hash function must have the same security
    /// properties as [Engine.Hash].
    ///
    /// Each call to tuple_hash must use the same primitive.
    ///
    /// [NIST]: https://www.nist.gov/publications/sha-3-derived-functions-cshake-kmac-tuplehash-and-parallelhash
    fn tuple_hash(s: &[u8]) -> [u8; 64];

    /// suite_ids returns identifiers describing this Engine.
    ///
    /// See its documentation for more information.
    fn suite_ids() -> SuiteIDs;
}

/// Kdf is an extract-then-expand Key Derivation Function (KDF) as
/// formally defined in section 3 of [HKDF].
///
/// It is not suitable for deriving keys from passwords.
///
/// [HKDF]: https://eprint.iacr.org/2010/264
pub trait Kdf {
    /// extract is a randomness extractor that extracts
    /// a fixed-length pseudorandom key (PRK) from the Input
    /// Keying Material (IKM) and an optional salt.
    ///
    /// extract must handle IKM and salts of an arbitrary length.
    fn extract(&self, ikm: &[u8], salt: &[u8]) -> Vec<u8>;
    /// expand is a PRF that expands the PRK with an optional info
    /// parameter into an L-byte key.
    ///
    /// expand must handle info parameters of an arbitrary length,
    /// output lengths up to 255*Size bytes, but need only handle
    /// PRKs Size bytes long.
    fn expand(&self, prk: &[u8], info: &[u8], l: usize) -> Vec<u8>;
    /// size returns the size in bytes of the output of Extract.
    ///
    /// It must be at least 32 bytes.
    fn size(&self) -> usize;
}

pub trait Kem<P, U>
where
    P: PrivateKey<U>,
    U: PublicKey,
{
    /// Error is a Kem error
    type Error: Error;
    /// generate_key generates a private key
    fn generate_key(&self) -> Result<P, Self::Error>;
    /// new_private_key validates the input and constructs
    /// a PrivateKey.
    fn new_private_key(&self, key: &[u8]) -> Result<P, Self::Error>;
    /// new_public_key validates the input and constructs
    /// a PublicKey.
    fn new_public_key(&self, key: &[u8]) -> Result<U, Self::Error>;
    /// key_sizes returns the maximum size in bytes for private and
    /// public keys.
    fn key_sizes(&self) -> KeySizes;
}

pub struct KeySizes {
    pub public_key: usize,
    pub private_key: usize,
}

pub trait PrivateKey<P>
where
    P: PublicKey,
{
    /// bytes returns the encoding of the private key.
    fn bytes(&self) -> Vec<u8>;
    /// equal reports, in constant time, whether the two private
    /// keys are equal.
    fn equal(&self, key: Self) -> bool;
    /// public returns the corresponding public key.
    fn public(&self) -> P;
}

pub trait PublicKey {
    /// Bytes returns the encoding of the public key.
    fn bytes(&self) -> Vec<u8>;
    /// equal reports, in constant time, whether the two public
    /// keys are equal.
    fn equal(&self, key: Self) -> bool;
}

/// SuiteIDs is a set of identifiers for the primitives used by an
/// Engine.
///
/// The identifiers are used for domain separation and contextual
/// binding.
///
/// It is up to the protocol to define the set of identifiers.
pub struct SuiteIDs {
    pub aead: u16,
    pub kdf: u16,
    pub mac: u16,
    pub kem: u16,
    pub signer: u16,
    pub hash: u16,
    pub tuple_hash: u16,
}

/// Signer is a digital signature algorithm.
///
/// The algorithm must must:
///
///   - Have at minimum a 256-bit security level
///   - Generate canonical signatures
///   - Reject non-canonical signatures
///   - Be EUF-CMA secure
///
/// Note that rejecting non-canonical signatures implies strong
/// EUF-CMA security. However, this API's definition is
/// intentionally weaker.
///
/// Examples of algorithms that fulfill these requirements include
/// ECDSA with the three NIST prime-order curves (P-256, P-384,
/// and P521), albeit with minor modifications (like rejecting
/// s >= N/2).
pub trait Signer<P, U>
where
    P: PrivateKey<U>,
    U: PublicKey,
{
    /// Error is a Signer error
    type Error: Error;
    /// sign signs a hash using the PrivateKey and returns the
    /// ASN.1 DER signature.
    fn sign(&self, sk: P, msg: &[u8]) -> Result<Vec<u8>, Self::Error>;
    /// verify reports whether the ASN.1 DER signature is valid
    /// for the provided PublicKey and hash.
    fn verify(&self, pk: U, sign: &[u8]) -> bool;
    /// generate_key generates a private key
    fn generate_key(&self, rand: String) -> Result<P, Self::Error>;
    /// new_private_key validates the input and constructs
    /// a PrivateKey.
    fn new_private_key(&self, key: &[u8]) -> Result<P, Self::Error>;
    /// new_public_key validates the input and constructs
    /// a PublicKey.
    fn new_public_key(&self, key: &[u8]) -> Result<U, Self::Error>;
    /// key_sizes returns the maximum size in bytes for private and
    /// public keys.
    fn key_sizes(&self) -> KeySizes;
}

#[cfg(test)]
mod tests;
