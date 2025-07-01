use core::{
    fmt,
    hash::{Hash, Hasher},
    iter,
    marker::PhantomData,
    slice,
};

use derive_where::derive_where;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha3_utils::{encode_string, EncodedString};
use spideroak_crypto::{
    hash,
    kdf::{self, Expand, Kdf as _, KdfError},
    oid::{Identified, Oid},
    typenum::Unsigned,
};

use crate::ciphersuite::CipherSuite;

/// Extension trait for [`CipherSuite`].
///
/// Its primary purpose is to provide convenience methods that
/// include the OIDs of the cipher suite's algorithms.
pub(crate) trait CipherSuiteExt: CipherSuite {
    /// Computes the following hash:
    ///
    /// ```text
    /// digest = TupleHash(
    ///     tag,
    ///     oids[0],
    ///     oids[1],
    ///     ..,
    ///     oids[n],
    ///     context,
    /// )
    /// ```
    fn tuple_hash<const N: usize>(tag: &[u8], context: [&[u8]; N]) -> Digest<Self>;

    /// Performs `LabeledExtract` per [RFC 9180].
    ///
    /// - `domain` provides domain separation. See [RFC 9180]
    ///    section 9.6.
    /// - `salt`, `label`, and `ikm` are regular KDF parameters.
    ///
    /// ```text
    /// def LabeledExtract(salt, label, ikm):
    ///     labeled_ikm = concat(domain, suite_id, label, ikm)
    ///     return Extract(salt, labeled_ikm)
    /// ```
    ///
    /// Note that in [RFC 9180] `suite_id` contains 16-bit HPKE
    /// algorithm identifiers, but in this function it contains
    /// OIDs. Since an OID does not have a fixed length, each OID
    /// is unambiguously encoded with [`encode_string`].
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies
    fn labeled_extract<'a>(
        domain: &'static [u8],
        salt: &[u8],
        label: &'static [u8],
        ikm: impl IntoIterator<Item = &'a [u8]>,
    ) -> Prk<Self>;

    /// Performs `LabeledExpand` per [RFC 9180].
    ///
    /// - `domain` provides domain separation. See [RFC 9180]
    ///    section 9.6.
    /// - `prk`, `label`, and `info` are regular KDF parameters.
    ///
    /// ```text
    /// def LabeledExpand(prk, label, info):
    ///     labeled_info = concat(I2OSP(L, 2), domain, suite_id,
    ///                   label, info)
    ///     return Expand(prk, labeled_info)
    /// ```
    ///
    /// Note that in [RFC 9180] `suite_id` contains 16-bit HPKE
    /// algorithm identifiers, but in this function it contains
    /// OIDs. Since an OID does not have a fixed length, each OID
    /// is unambiguously encoded with [`encode_string`].
    ///
    /// [RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html#name-cryptographic-dependencies
    fn labeled_expand<T, const N: usize>(
        domain: &'static [u8],
        prk: &Prk<Self>,
        label: &'static [u8],
        info: [&[u8]; N],
    ) -> Result<T, KdfError>
    where
        T: Expand;
}

impl<CS: CipherSuite> CipherSuiteExt for CS {
    fn tuple_hash<const N: usize>(tag: &[u8], context: [&[u8]; N]) -> Digest<Self> {
        let iter = iter::once(tag)
            .chain(CS::OIDS.into_iter().map(|oid| oid.as_bytes()))
            .chain(context.iter().copied());
        hash::tuple_hash::<Self::Hash, _>(iter)
    }

    fn labeled_extract<'a>(
        domain: &'static [u8],
        salt: &[u8],
        label: &'static [u8],
        ikm: impl IntoIterator<Item = &'a [u8]>,
    ) -> Prk<Self> {
        let labeled_ikm = iter::once(domain)
            .chain(CS::OIDS.encode())
            .chain(iter::once(label))
            .chain(ikm);
        Self::Kdf::extract_multi(labeled_ikm, salt)
    }

    fn labeled_expand<T, const N: usize>(
        domain: &'static [u8],
        prk: &Prk<Self>,
        label: &'static [u8],
        info: [&[u8]; N],
    ) -> Result<T, KdfError>
    where
        T: Expand,
    {
        let size = T::Size::U16.to_be_bytes();
        let labeled_info = iter::once(&size)
            .map(|v| v.as_ref())
            .chain(iter::once(domain))
            .chain(
                #[allow(clippy::useless_conversion, reason = "It helps with type inference")]
                CS::OIDS.encode().into_iter(),
            )
            .chain(iter::once(label))
            .chain(info.iter().copied());
        T::expand_multi::<Self::Kdf, _>(prk, labeled_info)
    }
}

pub(crate) type Digest<CS> = hash::Digest<<<CS as CipherSuite>::Hash as hash::Hash>::DigestSize>;
pub(crate) type Prk<CS> = kdf::Prk<<<CS as CipherSuite>::Kdf as kdf::Kdf>::PrkSize>;

/// The OIDs used by a [`CipherSuite`].
#[derive_where(Copy, Clone, Debug, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct Oids<CS: CipherSuite + ?Sized> {
    aead: AeadOid<CS>,
    hash: HashOid<CS>,
    kdf: KdfOid<CS>,
    kem: KemOid<CS>,
    mac: MacOid<CS>,
    signer: SignerOid<CS>,
}

impl<CS: CipherSuite + ?Sized> Oids<CS> {
    pub(super) const fn new() -> Self {
        Self {
            aead: AeadOid::<CS>(PhantomData),
            hash: HashOid::<CS>(PhantomData),
            kdf: KdfOid::<CS>(PhantomData),
            kem: KemOid::<CS>(PhantomData),
            mac: MacOid::<CS>(PhantomData),
            signer: SignerOid::<CS>(PhantomData),
        }
    }

    /// Returns the OIDs as an array.
    const fn all() -> [&'static Oid; 6] {
        const {
            [
                AeadOid::<CS>::OID,
                HashOid::<CS>::OID,
                KdfOid::<CS>::OID,
                KemOid::<CS>::OID,
                MacOid::<CS>::OID,
                SignerOid::<CS>::OID,
            ]
        }
    }

    /// Encods the OIDs with [`encode_string`].
    pub(crate) const fn encode(self) -> EncodedOids<CS> {
        EncodedOids::<CS>(PhantomData)
    }
}

impl<CS> IntoIterator for Oids<CS>
where
    CS: CipherSuite,
{
    type Item = &'static Oid;
    type IntoIter = iter::Copied<slice::Iter<'static, &'static Oid>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        const { Oids::<CS>::all() }.iter().copied()
    }
}

/// Encodes the OIDs with [`encode_string`], then flattens the
/// [`EncodedString`]s into their parts.
///
/// [TupleHash]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
#[derive_where(Copy, Clone, Debug)]
pub(crate) struct EncodedOids<CS: ?Sized>(PhantomData<CS>);

impl<CS: CipherSuite + ?Sized> EncodedOids<CS> {
    const ITEMS: [&'static [u8]; 12] = {
        // ([0], [1]) = AEAD.into_parts()
        // ([2], [3]) = HASH.into_parts()
        // ...
        // ([10], [11]) = SIGNER.into_parts()
        let mut buf: [&[u8]; 12] = [&[]; 12];
        let mut i = 0;
        let mut j = 0;
        while i < Self::ENCODED.len() {
            let (p, s) = Self::ENCODED[i].as_parts();
            buf[j] = p.as_bytes();
            buf[j + 1] = s;
            i += 1;
            j += 2;
        }
        buf
    };

    /// All OIDs encoded with [`encode_string`].
    const ENCODED: [EncodedString<'static>; 6] = {
        let mut buf = [encode_string(b""); 6];
        let mut i = 0;
        while i < buf.len() {
            buf[i] = encode_string(Oids::<CS>::all()[i].as_bytes());
            i += 1;
        }
        buf
    };
}

impl<CS> IntoIterator for EncodedOids<CS>
where
    CS: CipherSuite + ?Sized,
{
    type Item = &'static [u8];
    type IntoIter = iter::Copied<slice::Iter<'static, &'static [u8]>>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        Self::ITEMS.iter().copied()
    }
}

/// Creates a ZST that serializes and deserializes as a specific
/// OID.
macro_rules! oid_repr {
    ($($name:ident => $ty:ident),* $(,)?) => {$(
        #[derive_where(Copy, Clone, Debug, Eq, PartialEq)]
        struct $name<CS: ?Sized>(PhantomData<CS>);

        impl<CS: CipherSuite + ?Sized> Identified for $name<CS> {
            const OID: &Oid = <<CS as CipherSuite>::$ty as Identified>::OID;
        }

        impl<CS: CipherSuite + ?Sized> Hash for $name<CS> {
            fn hash<H: Hasher>(&self, state: &mut H) {
                Self::OID.hash(state);
            }
        }

        #[automatically_derived]
        impl<CS> Serialize for $name<CS>
        where
            CS: CipherSuite + ?Sized,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Self::OID.serialize(serializer)
            }
        }

        #[automatically_derived]
        impl<'de, CS> Deserialize<'de> for $name<CS>
        where
            CS: CipherSuite + ?Sized,
        {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct OidVisitor<CS: ?Sized>(PhantomData<CS>);

                impl<'de, CS> de::Visitor<'de> for OidVisitor<CS>
                where
                    CS: CipherSuite + ?Sized,
                {
                    type Value = $name<CS>;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("an OID")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        if $name::<CS>::OID != v {
                            Err(de::Error::custom("unexpected OID"))
                        } else {
                            Ok($name(PhantomData))
                        }
                    }

                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        if $name::<CS>::OID != v {
                            Err(de::Error::custom("unexpected OID"))
                        } else {
                            Ok($name(PhantomData))
                        }
                    }
                }
                deserializer.deserialize_bytes(OidVisitor(PhantomData))
            }
        }
    )*};
}
oid_repr! {
    AeadOid => Aead,
    HashOid => Hash,
    KdfOid => Kdf,
    KemOid => Kem,
    MacOid => Mac,
    SignerOid => Signer,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        default::DefaultCipherSuite as CS,
        test_util::{assert_ct_eq, assert_ct_ne},
    };

    mod labeled_extract {
        use super::*;

        #[test]
        fn test_smoke() {
            let lhs =
                CS::labeled_extract(b"domain", b"salt", b"label", iter::once::<&[u8]>(b"ikm"));
            let rhs =
                CS::labeled_extract(b"domain", b"salt", b"label", iter::once::<&[u8]>(b"ikm"));
            assert_ct_eq!(lhs, rhs);
        }

        #[test]
        fn test_different_inputs() {
            let tests = [
                (
                    "domain",
                    (b"domain", b"salt", b"label", b"ikm"),
                    (b"DOMAIN", b"salt", b"label", b"ikm"),
                ),
                (
                    "salt",
                    (b"domain", b"salt", b"label", b"ikm"),
                    (b"domain", b"SALT", b"label", b"ikm"),
                ),
                (
                    "label",
                    (b"domain", b"salt", b"label", b"ikm"),
                    (b"domain", b"salt", b"LABEL", b"ikm"),
                ),
                (
                    "ikm",
                    (b"domain", b"salt", b"label", b"ikm"),
                    (b"domain", b"salt", b"label", b"IKM"),
                ),
            ];
            for (i, (name, lhs, rhs)) in tests.iter().enumerate() {
                let lhs = CS::labeled_extract(lhs.0, lhs.1, lhs.2, iter::once::<&[u8]>(lhs.3));
                let rhs = CS::labeled_extract(rhs.0, rhs.1, rhs.2, iter::once::<&[u8]>(rhs.3));
                assert_ct_ne!(lhs, rhs, "#{i}: `{name}`:");
            }
        }
    }

    mod labeled_expand {
        use super::*;

        #[test]
        fn test_smoke() {
            let prk =
                CS::labeled_extract(b"domain", b"salt", b"label", iter::once::<&[u8]>(b"ikm"));
            let lhs: [u8; 16] =
                CS::labeled_expand(b"domain", &prk, b"label", [b"ikm", b"info"]).unwrap();
            let rhs: [u8; 16] =
                CS::labeled_expand(b"domain", &prk, b"label", [b"ikm", b"info"]).unwrap();
            assert_ct_eq!(lhs[..], rhs[..]);
        }

        #[test]
        fn test_different_inputs() {
            let prk1 =
                CS::labeled_extract(b"domain", b"salt", b"label", iter::once::<&[u8]>(b"ikm"));
            let prk2 =
                CS::labeled_extract(b"DOMAIN", b"SALT", b"LABEL", iter::once::<&[u8]>(b"IKM"));
            #[allow(
                clippy::type_complexity,
                reason = "I wouldn't need this if Rust's type inference were better"
            )]
            let tests: [(_, (_, _, _, [&[u8]; 1]), (_, _, _, [&[u8]; 1])); 4] = [
                (
                    "domain",
                    (b"domain", &prk1, b"label", [b"info"]),
                    (b"DOMAIN", &prk1, b"label", [b"info"]),
                ),
                (
                    "prk",
                    (b"domain", &prk1, b"label", [b"info"]),
                    (b"domain", &prk2, b"label", [b"info"]),
                ),
                (
                    "label",
                    (b"domain", &prk1, b"label", [b"info"]),
                    (b"domain", &prk1, b"LABEL", [b"info"]),
                ),
                (
                    "info",
                    (b"domain", &prk1, b"label", [b"info"]),
                    (b"domain", &prk1, b"label", [b"INFO"]),
                ),
            ];
            for (i, (name, lhs, rhs)) in tests.iter().enumerate() {
                let lhs: [u8; 16] = CS::labeled_expand(lhs.0, lhs.1, lhs.2, lhs.3).unwrap();
                let rhs: [u8; 16] = CS::labeled_expand(rhs.0, rhs.1, rhs.2, rhs.3).unwrap();
                assert_ct_ne!(lhs[..], rhs[..], "#{i}: `{name}`:");
            }
        }

        #[test]
        fn test_info_concat() {
            let prk =
                CS::labeled_extract(b"domain", b"salt", b"label", iter::once::<&[u8]>(b"ikm"));

            macro_rules! tests {
                ($(($lhs:expr, $rhs:expr),)*) => {$({
                    let lhs: [u8; 16] =
                        CS::labeled_expand(b"domain", &prk, b"label", $lhs).unwrap();
                    let rhs: [u8; 16] =
                        CS::labeled_expand(b"domain", &prk, b"label", $rhs).unwrap();
                    assert_ct_eq!(lhs[..], rhs[..], "{} != {}",
                        stringify!($lhs), stringify!($rhs));
                })*};
            }
            tests! {
                ([], []),
                ([], [&[], &[]]),
                ([], [b"", b""]),
                ([&[]], [&[], &[]]),
                ([b"info"], [b"info"]),
                ([b"info", b""], [b"info", b""]),
                ([b"", b"info"], [b"", b"info"]),
                ([b"info", b"in", b"fo"], [b"info", b"in", b"fo"]),
                ([b"in", b"fo", b"info"], [b"in", b"fo", b"info"]),
            }
        }
    }
}
