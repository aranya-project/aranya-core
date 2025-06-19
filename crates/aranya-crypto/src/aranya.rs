//! This file contains the various device keys.

#![forbid(unsafe_code)]

use core::{borrow::Borrow, fmt, marker::PhantomData, result::Result};

use derive_where::derive_where;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use spideroak_crypto::{
    aead::Tag,
    csprng::Csprng,
    import::{Import, ImportError},
    kem::{DecapKey, Kem},
    keys::PublicKey,
    signer::{self, Signer, SigningKey as SigningKey_, VerifyingKey as VerifyingKey_},
};
use zerocopy::{ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    ciphersuite::{CipherSuite, CipherSuiteExt},
    error::Error,
    groupkey::{EncryptedGroupKey, GroupKey},
    hpke::{self, Mode},
    id::Id,
    misc::{kem_key, signing_key, SigData},
    policy::{self, Cmd, CmdId},
};

/// A signature created by a signing key.
#[derive_where(Clone, Debug)]
pub struct Signature<CS: CipherSuite>(pub(crate) <CS::Signer as Signer>::Signature);

impl<CS: CipherSuite> Signature<CS> {
    /// Returns the raw signature.
    ///
    /// Should only be used in situations where contextual data
    /// is being merged in. Otherwise, use [`Serialize`].
    pub(crate) fn raw_sig(&self) -> SigData<CS> {
        signer::Signature::export(&self.0)
    }

    /// Encodes itself as bytes.
    pub fn to_bytes(&self) -> impl Borrow<[u8]> + use<CS> {
        self.raw_sig()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let sig = <CS::Signer as Signer>::Signature::import(data)?;
        Ok(Self(sig))
    }
}

impl<CS: CipherSuite> Serialize for Signature<CS> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.to_bytes().borrow())
    }
}

impl<'de, CS: CipherSuite> Deserialize<'de> for Signature<CS> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor<CS>(PhantomData<CS>);
        impl<'de, G: CipherSuite> de::Visitor<'de> for SigVisitor<G> {
            type Value = Signature<G>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a signature")
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Signature::<G>::from_bytes(v).map_err(de::Error::custom)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Signature::<G>::from_bytes(v).map_err(de::Error::custom)
            }
        }
        let sig = deserializer.deserialize_bytes(SigVisitor::<CS>(PhantomData))?;
        Ok(sig)
    }
}

signing_key! {
    /// The Device Identity Key.
    sk = IdentityKey,
    pk = IdentityVerifyingKey,
    id = DeviceId,
}

impl<CS: CipherSuite> IdentityKey<CS> {
    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     IdentityKey,
    ///     Rng,
    /// };
    ///
    /// let sk = IdentityKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &[u8] = b"doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, b"wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", b"signature")
    ///     .expect("should not fail");
    /// sk.public().expect("identity key should be valid").verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &[u8]) -> Result<Signature<CS>, Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = CS::tuple_hash(b"IdentityKey", [self.id()?.as_bytes(), context, msg]);
        let sig = self.sk.sign(&sum)?;
        Ok(Signature(sig))
    }
}

impl<CS: CipherSuite> IdentityVerifyingKey<CS> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(&self, msg: &[u8], context: &[u8], sig: &Signature<CS>) -> Result<(), Error> {
        // digest = H(
        //     "IdentityKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = CS::tuple_hash(b"IdentityKey", [self.id()?.as_bytes(), context, msg]);
        Ok(self.pk.verify(&sum, &sig.0)?)
    }
}

signing_key! {
    /// The Device Signing Key.
    sk = SigningKey,
    pk = VerifyingKey,
    id = SigningKeyId,
}

impl<CS: CipherSuite> SigningKey<CS> {
    /// Creates a signature over `msg` bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// let sk = SigningKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// const MESSAGE: &[u8] = b"hello, world!";
    /// const CONTEXT: &[u8] = b"doc test";
    /// let sig = sk.sign(MESSAGE, CONTEXT)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, CONTEXT, &sig)
    ///     .expect("should not fail");
    ///
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, b"wrong context", &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig = sk.sign(b"different", b"signature")
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify(MESSAGE, CONTEXT, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign(&self, msg: &[u8], context: &[u8]) -> Result<Signature<CS>, Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = CS::tuple_hash(b"SigningKey", [self.id()?.as_bytes(), context, msg]);
        let sig = self.sk.sign(&sum)?;
        Ok(Signature(sig))
    }

    /// Creates a signature over a named policy command.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(all(feature = "alloc", not(feature = "trng")))]
    /// # {
    /// use aranya_crypto::{
    ///     default::{
    ///         DefaultCipherSuite,
    ///         DefaultEngine,
    ///     },
    ///     Cmd,
    ///     Id,
    ///     Rng,
    ///     SigningKey,
    /// };
    ///
    /// let sk = SigningKey::<DefaultCipherSuite>::new(&mut Rng);
    ///
    /// let data = b"... some command data ...";
    /// let name = "AddDevice";
    /// let parent_id = &Id::random(&mut Rng);
    ///
    /// let good_cmd = Cmd { data, name, parent_id };
    /// let (sig, _) = sk.sign_cmd(good_cmd)
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify_cmd(good_cmd, &sig)
    ///     .expect("should not fail");
    ///
    /// let wrong_name_cmd = Cmd {
    ///     data,
    ///     name: "wrong name",
    ///     parent_id,
    /// };
    /// sk.public().expect("signing key should be valid").verify_cmd(wrong_name_cmd, &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_id_cmd = Cmd {
    ///     data,
    ///     name,
    ///     parent_id: &Id::random(&mut Rng),
    /// };
    /// sk.public().expect("signing key should be valid").verify_cmd(wrong_id_cmd, &sig)
    ///     .expect_err("should fail");
    ///
    /// let wrong_sig_cmd = Cmd {
    ///     data: b"different",
    ///     name: "signature",
    ///     parent_id: &Id::random(&mut Rng),
    /// };
    /// let (wrong_sig, _) = sk.sign_cmd(wrong_sig_cmd)
    ///     .expect("should not fail");
    /// sk.public().expect("signing key should be valid").verify_cmd(good_cmd, &wrong_sig)
    ///     .expect_err("should fail");
    /// # }
    /// ```
    pub fn sign_cmd(&self, cmd: Cmd<'_>) -> Result<(Signature<CS>, CmdId), Error> {
        let digest = cmd.digest::<CS>(self.id()?);
        let sig = Signature(self.sk.sign(&digest)?);
        let id = policy::cmd_id(&digest, &sig);
        Ok((sig, id))
    }
}

impl<CS: CipherSuite> VerifyingKey<CS> {
    /// Verifies the signature allegedly created over `msg` and
    /// bound to some `context`.
    ///
    /// `msg` must NOT be pre-hashed.
    pub fn verify(&self, msg: &[u8], context: &[u8], sig: &Signature<CS>) -> Result<(), Error> {
        // digest = H(
        //     "SigningKey",
        //     suites,
        //     pk,
        //     context,
        //     msg,
        // )
        let sum = CS::tuple_hash(b"SigningKey", [self.id()?.as_bytes(), context, msg]);
        Ok(self.pk.verify(&sum, &sig.0)?)
    }

    /// Verifies the signature allegedly created over a policy
    /// command and returns its ID.
    pub fn verify_cmd(&self, cmd: Cmd<'_>, sig: &Signature<CS>) -> Result<CmdId, Error> {
        let digest = cmd.digest::<CS>(self.id()?);
        self.pk.verify(&digest, &sig.0)?;
        let id = policy::cmd_id(&digest, sig);
        Ok(id)
    }
}

kem_key! {
    /// The Device Encryption Key.
    sk = EncryptionKey,
    pk = EncryptionPublicKey,
    id = EncryptionKeyId,
}

impl<CS: CipherSuite> EncryptionKey<CS> {
    /// Decrypts and authenticates a [`GroupKey`] received from
    /// a peer.
    pub fn open_group_key(
        &self,
        enc: &Encap<CS>,
        ciphertext: EncryptedGroupKey<CS>,
        group: Id,
    ) -> Result<GroupKey<CS>, Error> {
        let EncryptedGroupKey {
            mut ciphertext,
            tag,
        } = ciphertext;

        // info = concat(
        //     "GroupKey-v1",
        //     group,
        // )
        let info = GroupKeyInfo {
            domain: *b"GroupKey-v1",
            group,
        };
        let mut ctx = hpke::setup_recv::<CS>(Mode::Base, &enc.0, &self.sk, [info.as_bytes()])?;
        ctx.open_in_place(&mut ciphertext, &tag, info.as_bytes())?;
        Ok(GroupKey::from_seed(ciphertext.into()))
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, ByteEq, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct GroupKeyInfo {
    /// Always "GroupKey-v1".
    domain: [u8; 11],
    group: Id,
}

impl<CS: CipherSuite> EncryptionPublicKey<CS> {
    /// Encrypts and authenticates the [`GroupKey`] such that it
    /// can only be decrypted by the holder of the private half
    /// of the [`EncryptionPublicKey`].
    pub fn seal_group_key<R: Csprng>(
        &self,
        rng: &mut R,
        key: &GroupKey<CS>,
        group: Id,
    ) -> Result<(Encap<CS>, EncryptedGroupKey<CS>), Error> {
        // info = concat(
        //     "GroupKey-v1",
        //     group,
        // )
        let info = GroupKeyInfo {
            domain: *b"GroupKey-v1",
            group,
        };
        let (enc, mut ctx) =
            hpke::setup_send::<CS, _>(rng, Mode::Base, &self.pk, [info.as_bytes()])?;
        let mut ciphertext = (*key.raw_seed()).into();
        let mut tag = Tag::<CS::Aead>::default();
        ctx.seal_in_place(&mut ciphertext, &mut tag, info.as_bytes())?;
        Ok((Encap(enc), EncryptedGroupKey { ciphertext, tag }))
    }
}

/// An encapsulated symmetric key.
pub struct Encap<CS: CipherSuite>(pub(crate) <CS::Kem as Kem>::Encap);

impl<CS: CipherSuite> Encap<CS> {
    /// Encodes itself as bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.borrow()
    }

    /// Returns itself from its byte encoding.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ImportError> {
        let enc = <CS::Kem as Kem>::Encap::import(data)?;
        Ok(Self(enc))
    }

    #[cfg(any(feature = "afc", feature = "aqc"))]
    pub(crate) fn as_inner(&self) -> &<CS::Kem as Kem>::Encap {
        &self.0
    }
}

impl<CS: CipherSuite> fmt::Debug for Encap<CS> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Encap").field(&self.as_bytes()).finish()
    }
}

impl<CS> Serialize for Encap<CS>
where
    CS: CipherSuite,
{
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_bytes(self.as_bytes())
    }
}

impl<'de, CS> Deserialize<'de> for Encap<CS>
where
    CS: CipherSuite,
{
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EncapVisitor<G: ?Sized>(PhantomData<G>);
        impl<'de, G> de::Visitor<'de> for EncapVisitor<G>
        where
            G: CipherSuite,
        {
            type Value = Encap<G>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a valid encapsulation")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Encap::<G>::from_bytes(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E>(self, v: &'de [u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Encap::<G>::from_bytes(v).map_err(E::custom)
            }
        }
        d.deserialize_bytes(EncapVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use spideroak_crypto::rust;

    use super::*;
    use crate::{default::DhKemP256HkdfSha256, test_util::TestCs};

    #[allow(dead_code)]
    type CS = TestCs<
        rust::Aes256Gcm,
        rust::Sha256,
        rust::HkdfSha512,
        DhKemP256HkdfSha256,
        rust::HmacSha512,
        spideroak_crypto::ed25519::Ed25519,
    >;

    /// Golden test for [`IdentityKey::id`] (DeviceId) with deterministic keys.
    #[test]
    fn test_device_id() {
        use spideroak_crypto::import::Import;

        let tests = [
            ([0u8; 32], "4WvDDSvXv8Cqj85xHAkesJo3uVLy3LRczojr98KBNG8e"),
            ([1u8; 32], "7czZtx4VW5V6K3eu59rSBJKiqeVZjDX2gyJ4tkJqvqEM"),
            ([0xFF; 32], "DqAAPgZfS8KCo1W4M7C9A36SRXwoMKeLox5qzS1L7Bki"),
        ];

        for (i, (key_bytes, expected)) in tests.iter().enumerate() {
            let sk = IdentityKey::<CS>::from_inner(Import::import(&key_bytes[..]).unwrap());
            let got = sk.id().unwrap();
            let want = DeviceId::decode(expected).unwrap();
            assert_eq!(got, want, "test case #{i}");
        }
    }

    /// Golden test for [`SigningKey::id`] (SigningKeyId) with deterministic keys.
    #[test]
    fn test_signing_key_id() {
        use spideroak_crypto::import::Import;

        let tests = [
            ([0u8; 32], "DTSYenur9akPjgwULDLDhPdaZ9pmEKq7pYJ6vvST2kWs"),
            ([1u8; 32], "6fuCv2oLzQzK2sBDyKh5eHcTZ2b6uJXC5txoNwqyWuQ5"),
            ([0xFF; 32], "EgLiA9CxqVLKgdgLen9N5JJzh96vxDDrPXTGdBnpFzYe"),
        ];

        for (i, (key_bytes, expected)) in tests.iter().enumerate() {
            let sk = SigningKey::<CS>::from_inner(Import::import(&key_bytes[..]).unwrap());
            let got = sk.id().unwrap();
            let want = SigningKeyId::decode(expected).unwrap();
            assert_eq!(got, want, "test case #{i}");
        }
    }

    /// Golden test for [`EncryptionKey::id`] (EncryptionKeyId) with deterministic keys.
    #[test]
    fn test_encryption_key_id() {
        use spideroak_crypto::import::Import;

        // Use well-known P256 private keys that are valid scalars
        let tests = [
            (
                // A simple valid P256 private key (1)
                {
                    let mut key_bytes = [0u8; 32];
                    key_bytes[31] = 1;
                    key_bytes
                },
                "BHJHCs6ozYTwWRnZs86N1tYoqriNs8a2BLcVNTGmzXyh",
            ),
            (
                // Another valid P256 private key (2)
                {
                    let mut key_bytes = [0u8; 32];
                    key_bytes[31] = 2;
                    key_bytes
                },
                "AuXu55LDVk9qbBZ4LmqGA5EoQyPSwLSTYnX4KHTtx29y",
            ),
            (
                // A third valid P256 private key (0x42...)
                {
                    let mut key_bytes = [0u8; 32];
                    key_bytes[0] = 0x42;
                    key_bytes[31] = 0x42;
                    key_bytes
                },
                "2BsoFVd3YVsTj5wrfgXPQ3GUUYwh45F2xmi1K2iGH485",
            ),
        ];

        for (i, (key_bytes, expected)) in tests.iter().enumerate() {
            let sk = EncryptionKey::<CS>::from_inner(Import::import(&key_bytes[..]).unwrap());
            let got = sk.id().unwrap();
            let want = EncryptionKeyId::decode(expected).unwrap();
            assert_eq!(got, want, "test case #{i}");
        }
    }
}
