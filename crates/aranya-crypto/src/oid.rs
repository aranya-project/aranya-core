/// Wraps a KDF with a specific OID.
#[macro_export]
macro_rules! kdf_with_oid {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner:ty) => $oid:expr
    ) => {
        $(#[$meta])*
        $vis struct $name($inner);

        impl $crate::spideroak_crypto::kdf::Kdf for $name {
            type MaxOutput = <$inner as $crate::spideroak_crypto::kdf::Kdf>::MaxOutput;

            type PrkSize = <$inner as $crate::spideroak_crypto::kdf::Kdf>::PrkSize;

            fn extract(ikm: &[u8], salt: &[u8]) -> $crate::spideroak_crypto::kdf::Prk<Self::PrkSize> {
                <$inner as $crate::spideroak_crypto::kdf::Kdf>::extract(ikm, salt)
            }

            fn extract_multi<I>(ikm: I, salt: &[u8]) -> $crate::spideroak_crypto::kdf::Prk<Self::PrkSize>
            where
                I: ::core::iter::IntoIterator,
                I::Item: ::core::convert::AsRef<[u8]>,
            {
                <$inner as $crate::spideroak_crypto::kdf::Kdf>::extract_multi(ikm, salt)
            }

            fn expand(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: &[u8]) -> ::core::result::Result<(), $crate::spideroak_crypto::kdf::KdfError> {
                <$inner as $crate::spideroak_crypto::kdf::Kdf>::expand(out, prk, info)
            }

            fn expand_multi<I>(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: I) -> ::core::result::Result<(), $crate::spideroak_crypto::kdf::KdfError>
            where
                I: ::core::iter::IntoIterator,
                I::Item: ::core::convert::AsRef<[u8]>,
                I::IntoIter: ::core::clone::Clone,
            {
                <$inner as $crate::spideroak_crypto::kdf::Kdf>::expand_multi(out, prk, info)
            }
        }

        impl $crate::spideroak_crypto::hpke::HpkeKdf for $name {
            const ID: $crate::spideroak_crypto::hpke::KdfId = <$inner as $crate::spideroak_crypto::hpke::HpkeKdf>::ID;
        }

        impl $crate::spideroak_crypto::oid::Identified for $name {
            const OID: &'static $crate::spideroak_crypto::oid::Oid = $oid;
        }
    };
}

/// Wraps a KEM with a specific OID.
#[macro_export]
macro_rules! kem_with_oid {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner:ty) => $oid:expr
    ) => {
        $(#[$meta])*
        $vis struct $name($inner);

        #[allow(non_snake_case)]
        impl $crate::spideroak_crypto::kem::Kem for $name {
            type DecapKey = <$inner as $crate::spideroak_crypto::kem::Kem>::DecapKey;
            type EncapKey = <$inner as $crate::spideroak_crypto::kem::Kem>::EncapKey;
            type Secret = <$inner as $crate::spideroak_crypto::kem::Kem>::Secret;
            type Encap = <$inner as $crate::spideroak_crypto::kem::Kem>::Encap;

            fn encap<R: $crate::spideroak_crypto::csprng::Csprng>(
                rng: &mut R,
                pkR: &Self::EncapKey,
            ) -> Result<(Self::Secret, Self::Encap), $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::encap(rng, pkR)
            }

            fn encap_deterministically(
                pkR: &Self::EncapKey,
                skE: Self::DecapKey,
            ) -> Result<(Self::Secret, Self::Encap), $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::encap_deterministically(pkR, skE)
            }

            fn decap(
                enc: &Self::Encap,
                skR: &Self::DecapKey,
            ) -> Result<Self::Secret, $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::decap(enc, skR)
            }

            fn auth_encap<R: $crate::spideroak_crypto::csprng::Csprng>(
                rng: &mut R,
                pkR: &Self::EncapKey,
                skS: &Self::DecapKey,
            ) -> Result<(Self::Secret, Self::Encap), $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::auth_encap(rng, pkR, skS)
            }

            fn auth_encap_deterministically(
                pkR: &Self::EncapKey,
                skS: &Self::DecapKey,
                skE: Self::DecapKey,
            ) -> Result<(Self::Secret, Self::Encap), $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::auth_encap_deterministically(pkR, skS, skE)
            }

            fn auth_decap(
                enc: &Self::Encap,
                skR: &Self::DecapKey,
                pkS: &Self::EncapKey,
            ) -> Result<Self::Secret, $crate::spideroak_crypto::kem::KemError> {
                <$inner as $crate::spideroak_crypto::kem::Kem>::auth_decap(enc, skR, pkS)
            }
        }

        impl $crate::spideroak_crypto::hpke::HpkeKem for $name {
            const ID: $crate::spideroak_crypto::hpke::KemId = <$inner as $crate::spideroak_crypto::hpke::HpkeKem>::ID;
        }

        impl $crate::spideroak_crypto::oid::Identified for $name {
            const OID: &'static $crate::spideroak_crypto::oid::Oid = $oid;
        }
    };
}
