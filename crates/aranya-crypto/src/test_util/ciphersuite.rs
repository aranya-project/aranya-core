//! [`CipherSuite`][crate::CipherSuite] tests.

/// Tests a [`CipherSuite`][crate::CipherSuite].
///
/// It also performs all of the tests inside the `aead`, `hash`,
/// `hpke`, `kdf`, `mac`, and `signer` modules.
///
/// # Example
///
/// ```
/// use aranya_crypto::{default::DefaultCipherSuite, test_ciphersuite};
///
/// test_ciphersuite!(default_ciphersuite, DefaultCipherSuite);
/// ```
#[macro_export]
macro_rules! test_ciphersuite {
    ($name:ident, $cs:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_ciphersuite!($cs);
        }
    };
    ($cs:ty) => {
        $crate::test_aead!(aead, <$cs as $crate::CipherSuite>::Aead);
        $crate::test_aead!(
            aead_with_defaults,
            $crate::test_util::AeadWithDefaults<
                <$cs as $crate::CipherSuite>::Aead,
            >
        );

        $crate::test_hash!(hash, <$cs as $crate::CipherSuite>::Hash);

        $crate::test_hpke!(hpke,
            <$cs as $crate::CipherSuite>::Kem,
            <$cs as $crate::CipherSuite>::Kdf,
            <$cs as $crate::CipherSuite>::Aead,
        );

        $crate::test_kdf!(kdf, <$cs as $crate::CipherSuite>::Kdf);
        $crate::test_kdf!(
            kdf_with_defaults,
            $crate::test_util::KdfWithDefaults<<$cs as $crate::CipherSuite>::Kdf>
        );

        $crate::test_mac!(mac, <$cs as $crate::CipherSuite>::Mac);
        $crate::test_mac!(
            mac_with_defaults,
            $crate::test_util::MacWithDefaults<<$cs as $crate::CipherSuite>::Mac>
        );

        $crate::test_signer!(signer, <$cs as $crate::CipherSuite>::Signer);
        $crate::test_signer!(
            signer_with_defaults,
            $crate::test_util::SignerWithDefaults<<$cs as $crate::CipherSuite>::Signer>
        );
    };
}
pub use test_ciphersuite;
