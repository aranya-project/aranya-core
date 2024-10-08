//! Test specific algorithms using test vectors.

extern crate alloc;

use alloc::{string::ToString, vec};
use core::borrow::Borrow;

pub use hpke::TestName as HpkeTest;
use subtle::ConstantTimeEq;
pub use wycheproof::{
    self, aead::TestName as AeadTest, ecdh::TestName as EcdhTest, ecdsa::TestName as EcdsaTest,
    eddsa::TestName as EddsaTest, hkdf::TestName as HkdfTest, mac::TestName as MacTest, TestResult,
};
use wycheproof::{aead, ecdh, ecdsa, eddsa, hkdf, mac};

use super::{AeadWithDefaults, KdfWithDefaults, MacWithDefaults, SignerWithDefaults};
use crate::{
    aead::{Aead, IndCca2, Nonce},
    hpke::{Hpke, SealCtx},
    import::Import,
    kdf::Kdf,
    kem::{Ecdh, Kem},
    mac::Mac,
    signer::{Signer, VerifyingKey},
};

macro_rules! msg {
    ($id:expr) => {
        &$id.to_string()
    };
    ($($arg:tt)*) => {
        &format!($($arg)*)
    };
}

/// HPKE tests.
#[allow(missing_docs)]
pub mod hpke {
    extern crate alloc;

    use alloc::{boxed::Box, vec::Vec};
    use core::{result::Result, str::FromStr};

    use serde::{self, Deserialize};
    use serde_json;
    use wycheproof::{ByteString, WycheproofError};

    use crate::{
        hpke::{Mode, Psk},
        import::Import,
    };

    macro_rules! test_names {
            ($($name:ident),* $(,)?) => {
                pub enum TestName {
                    $($name,)*
                }

                impl TestName {
                    fn json_data(&self) -> &'static str {
                        match self {
                            $(
                                Self::$name => include_str!(concat!("testdata/", stringify!($name), ".json")),
                            )*
                        }
                    }
                }

                impl FromStr for TestName {
                    type Err = WycheproofError;

                    fn from_str(s: &str) -> Result<Self, Self::Err> {
                        match s {
                            $(
                                stringify!($name) => Ok(Self::$name),
                            )*
                            _ => Err(WycheproofError::NoDataSet),
                        }
                    }
                }
            };
        }

    test_names! {
        HpkeDhKemP256HkdfSha256HkdfSha256Aes128Gcm,
        HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
        HpkeDhKemP256HkdfSha256HkdfSha256ChaCha20Poly1305,
        HpkeDhKemP256HkdfSha256HkdfSha256ExportOnly,
        HpkeDhKemP256HkdfSha256HkdfSha512Aes128Gcm,
        HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
        HpkeDhKemP256HkdfSha256HkdfSha512ChaCha20Poly1305,
        HpkeDhKemP256HkdfSha256HkdfSha512ExportOnly,
        HpkeDhKemP521HkdfSha512HkdfSha256Aes128Gcm,
        HpkeDhKemP521HkdfSha512HkdfSha256Aes256Gcm,
        HpkeDhKemP521HkdfSha512HkdfSha256ChaCha20Poly1305,
        HpkeDhKemP521HkdfSha512HkdfSha256ExportOnly,
        HpkeDhKemP521HkdfSha512HkdfSha512Aes128Gcm,
        HpkeDhKemP521HkdfSha512HkdfSha512Aes256Gcm,
        HpkeDhKemP521HkdfSha512HkdfSha512ChaCha20Poly1305,
        HpkeDhKemP521HkdfSha512HkdfSha512ExportOnly,
        HpkeDhKemX25519HkdfSha256HkdfSha256Aes128Gcm,
        HpkeDhKemX25519HkdfSha256HkdfSha256Aes256Gcm,
        HpkeDhKemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
        HpkeDhKemX25519HkdfSha256HkdfSha256ExportOnly,
        HpkeDhKemX25519HkdfSha256HkdfSha512Aes128Gcm,
        HpkeDhKemX25519HkdfSha256HkdfSha512Aes256Gcm,
        HpkeDhKemX25519HkdfSha256HkdfSha512ChaCha20Poly1305,
        HpkeDhKemX25519HkdfSha256HkdfSha512ExportOnly,
        HpkeDhKemX448HkdfSha512HkdfSha256Aes128Gcm,
        HpkeDhKemX448HkdfSha512HkdfSha256Aes256Gcm,
        HpkeDhKemX448HkdfSha512HkdfSha256ChaCha20Poly1305,
        HpkeDhKemX448HkdfSha512HkdfSha256ExportOnly,
        HpkeDhKemX448HkdfSha512HkdfSha512Aes128Gcm,
        HpkeDhKemX448HkdfSha512HkdfSha512Aes256Gcm,
        HpkeDhKemX448HkdfSha512HkdfSha512ChaCha20Poly1305,
        HpkeDhKemX448HkdfSha512HkdfSha512ExportOnly,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
    pub(crate) struct TestSet {
        pub test_groups: Vec<TestGroup>,
    }

    impl TestSet {
        pub fn load(test: TestName) -> Result<Self, WycheproofError> {
            match serde_json::from_str(test.json_data()) {
                Ok(set) => Ok(set),
                Err(e) => Err(WycheproofError::ParsingFailed(Box::new(e))),
            }
        }
    }

    /// An HPKE mode.
    #[repr(u8)]
    #[derive(serde_repr::Deserialize_repr, Copy, Clone, Debug, Eq, PartialEq)]
    pub enum HpkeMode {
        Base = 0x00,
        Psk = 0x01,
        Auth = 0x02,
        AuthPsk = 0x03,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(non_snake_case)]
    pub(crate) struct TestGroup {
        pub mode: HpkeMode,
        pub kem_id: u16,
        pub kdf_id: u16,
        pub aead_id: u16,
        pub info: ByteString,
        pub ikmR: ByteString,
        pub ikmS: ByteString,
        pub ikmE: ByteString,
        pub skRm: ByteString,
        pub skSm: ByteString,
        pub skEm: ByteString,
        pub psk: ByteString,
        pub psk_id: ByteString,
        pub pkRm: ByteString,
        pub pkSm: ByteString,
        pub pkEm: ByteString,
        pub enc: ByteString,
        pub shared_secret: ByteString,
        pub key_schedule_context: ByteString,
        pub secret: ByteString,
        pub key: ByteString,
        pub base_nonce: ByteString,
        pub exporter_secret: ByteString,
        #[serde(rename = "encryptions")]
        pub tests: Vec<Test>,
        pub exports: Vec<ExportTest>,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Test {
        pub aad: ByteString,
        pub ct: ByteString,
        pub nonce: ByteString,
        pub pt: ByteString,
    }

    #[derive(Debug, Clone, Eq, PartialEq, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct ExportTest {
        pub exporter_context: ByteString,
        #[serde(rename = "L")]
        pub len: usize,
        pub exported_value: ByteString,
    }

    impl TestGroup {
        #[allow(non_snake_case)]
        pub(super) fn get_mode<'a, T: Import<&'a [u8]>>(
            &'a self,
            id: usize,
            xkSm: &'a [u8],
        ) -> Mode<'_, T> {
            match self.mode {
                HpkeMode::Base => Mode::Base,
                HpkeMode::Psk => {
                    let psk = Psk::new(&self.psk[..], &self.psk_id[..])
                        .unwrap_or_else(|_| panic!("{id}"));
                    Mode::Psk(psk)
                }
                HpkeMode::Auth => {
                    let xkS = T::import(xkSm).unwrap_or_else(|_| panic!("{id}"));
                    Mode::Auth(xkS)
                }
                HpkeMode::AuthPsk => {
                    let xkS = T::import(xkSm).unwrap_or_else(|_| panic!("{id}"));
                    let psk = Psk::new(&self.psk[..], &self.psk_id[..])
                        .unwrap_or_else(|_| panic!("{id}"));
                    Mode::AuthPsk(xkS, psk)
                }
            }
        }
    }
}

/// Tests an [`Aead`] against Project Wycheproof test vectors.
///
/// It tests both `A` and [`AeadWithDefaults<T>`].
pub fn test_aead<A: Aead>(name: AeadTest) {
    test_aead_inner::<A>(name);
    test_aead_inner::<AeadWithDefaults<A>>(name);
}

fn test_aead_inner<A: Aead>(name: AeadTest) {
    let set = aead::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        if g.nonce_size / 8 != A::NONCE_SIZE
            || g.key_size / 8 != A::KEY_SIZE
            || g.tag_size / 8 != A::OVERHEAD
        {
            continue;
        }
        for tc in &g.tests {
            let id = tc.tc_id;

            let key = A::Key::import(&tc.key[..]).unwrap_or_else(|_| panic!("{id}"));
            let aead = A::new(&key);
            let nonce =
                Nonce::<A::NonceSize>::try_from(&tc.nonce[..]).unwrap_or_else(|_| panic!("{id}"));

            macro_rules! check {
                ($tc:ident, $res:ident) => {
                    match tc.result {
                        TestResult::Valid | TestResult::Acceptable => {
                            let plaintext = $res.unwrap_or_else(|_| panic!("{id}"));
                            assert_eq!(plaintext, *tc.pt, "{id}");
                        }
                        TestResult::Invalid => {
                            $res.err().unwrap_or_else(|| panic!("{id}"));
                        }
                    }
                };
            }

            let res = {
                let ciphertext = [&tc.ct[..], &tc.tag[..]].concat();
                let mut dst = vec![0u8; ciphertext.len() - A::OVERHEAD];
                aead.open(&mut dst[..], nonce.as_ref(), &ciphertext, &tc.aad[..])
                    .map(|_| dst)
            };
            check!(tc, res);

            let res = {
                let mut data = tc.ct.to_vec();
                aead.open_in_place(nonce.as_ref(), &mut data, &tc.tag[..], &tc.aad[..])
                    .map(|_| data)
            };
            check!(tc, res);

            if tc.result == TestResult::Invalid {
                // Can't test encryption if our data is for
                // a test failure.
                continue;
            }

            let (ct, tag) = {
                let mut dst = vec![0u8; tc.pt.len() + A::OVERHEAD];
                aead.seal(&mut dst[..], nonce.as_ref(), &tc.pt[..], &tc.aad[..])
                    .unwrap_or_else(|_| panic!("{id}"));
                let tag = dst.split_off(dst.len() - A::OVERHEAD);
                (dst, tag)
            };
            assert_eq!(ct, *tc.ct, "{id}");
            assert_eq!(tag, *tc.tag, "{id}");

            let (ct, tag) = {
                let mut data = tc.pt.clone().to_vec();
                let mut tag = vec![0u8; A::OVERHEAD];
                aead.seal_in_place(nonce.as_ref(), &mut data, &mut tag[..], &tc.aad[..])
                    .unwrap_or_else(|_| panic!("{id}"));
                (data, tag)
            };
            assert_eq!(ct, *tc.ct, "{id}");
            assert_eq!(tag, *tc.tag, "{id}");
        }
    }
}

/// Tests an [`Ecdh`] against Project Wycheproof test
/// vectors.
pub fn test_ecdh<T: Ecdh>(name: EcdhTest) {
    let set = ecdh::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let sk = match T::PrivateKey::import(&tc.private_key[..]) {
                Ok(sk) => sk,
                Err(_) => continue,
            };
            let pk = match T::PublicKey::import(&tc.public_key[..]) {
                Ok(pk) => pk,
                Err(_) => continue,
            };

            let res = T::ecdh(&sk, &pk);
            match tc.result {
                TestResult::Valid | TestResult::Acceptable => {
                    let got = res.unwrap_or_else(|_| panic!("{id}"));
                    assert_eq!(got.borrow(), &tc.shared_secret[..]);
                }
                TestResult::Invalid => {
                    res.err().unwrap_or_else(|| panic!("{id}"));
                }
            };
        }
    }
}

/// Tests a [`Signer`] that implements ECDSA against Project
/// Wycheproof test vectors.
///
/// It tests both `T` and [`SignerWithDefaults<T>`].
pub fn test_ecdsa<T: Signer>(name: EcdsaTest) {
    test_ecdsa_inner::<T>(name);
    test_ecdsa_inner::<SignerWithDefaults<T>>(name);
}

fn test_ecdsa_inner<T: Signer>(name: EcdsaTest) {
    let set = ecdsa::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let pk = T::VerifyingKey::import(&g.key.key[..]).unwrap_or_else(|_| panic!("{id}"));
            // TODO(eric): fail the test if we reject a valid
            // signature.
            let sig = match T::Signature::import(&tc.sig[..]) {
                Ok(sig) => sig,
                Err(_) => continue,
            };

            let res = pk.verify(&tc.msg[..], &sig);
            match tc.result {
                TestResult::Valid | TestResult::Acceptable => {
                    res.unwrap_or_else(|_| panic!("{id}"));
                }
                TestResult::Invalid => {
                    res.expect_err(msg!(id));
                }
            };
        }
    }
}

/// Tests a [`Signer`] that implements EdDSA against Project
/// Wycheproof test vectors.
///
/// It tests both `T` and [`SignerWithDefaults<T>`].
pub fn test_eddsa<T: Signer>(name: EddsaTest) {
    test_eddsa_inner::<T>(name);
    test_eddsa_inner::<SignerWithDefaults<T>>(name);
}

fn test_eddsa_inner<T: Signer>(name: EddsaTest) {
    fn sig_len(name: eddsa::TestName) -> usize {
        match name {
            eddsa::TestName::Ed25519 => 64,
            eddsa::TestName::Ed448 => 114,
        }
    }

    let set = eddsa::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let pk = T::VerifyingKey::import(&g.key.pk[..]).unwrap_or_else(|_| panic!("{id}"));

            let wrong_len = sig_len(name) != tc.sig.len();
            let sig = match T::Signature::import(&tc.sig[..]) {
                Err(_) => {
                    // Can't import the signature, so it's
                    // either an incorrect length or (r,s)
                    // are invalid.
                    assert!(wrong_len || tc.result == TestResult::Invalid, "#{id}");
                    // Since we can't import the signature,
                    // it's impossible to test.
                    continue;
                }
                Ok(sig) => {
                    // We could import the signature, so it
                    // must be the correct length.
                    assert!(!wrong_len);
                    sig
                }
            };

            // TODO(eric): EdDSA signatures are
            // deterministic, so also check the output of
            // sign.

            let res = pk.verify(&tc.msg[..], &sig);
            match tc.result {
                TestResult::Valid | TestResult::Acceptable => {
                    res.unwrap_or_else(|_| panic!("{id}"));
                }
                TestResult::Invalid => {
                    res.expect_err(msg!(id));
                }
            };
        }
    }
}

/// Tests a [`Kdf`] that implements HKDF against Project
/// Wycheproof test vectors.
///
/// It tests both `T` and [`KdfWithDefaults<T>`].
pub fn test_hkdf<T: Kdf>(name: HkdfTest) {
    test_hkdf_inner::<T>(name);
    test_hkdf_inner::<KdfWithDefaults<T>>(name);
}

fn test_hkdf_inner<T: Kdf>(name: HkdfTest) {
    let set = hkdf::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let mut out = vec![0u8; tc.okm.len()];
            T::extract_and_expand(&mut out[..], &tc.ikm[..], &tc.salt[..], &tc.info[..])
                .unwrap_or_else(|_| panic!("{id}"));
            assert_eq!(&out[..], &tc.okm[..], "{id}");
        }
    }
}

/// Tests an [`Hpke`] against test vectors.
#[allow(non_snake_case)]
pub fn test_hpke<K, F, A>(name: HpkeTest)
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    let set = hpke::TestSet::load(name).expect("should be able to load tests");
    for (i, g) in set.test_groups.iter().enumerate() {
        let (enc, mut send) = {
            let skE = K::DecapKey::import(&g.skEm[..]).unwrap_or_else(|_| panic!("group={i}"));
            let pkR = K::EncapKey::import(&g.pkRm[..]).unwrap_or_else(|_| panic!("group={i}"));
            let mode = g.get_mode(i, &g.skSm[..]);
            Hpke::<K, F, A>::setup_send_deterministically(mode.as_ref(), &pkR, &g.info, skE)
                .unwrap_or_else(|_| panic!("group={i}"))
        };
        let mut recv = {
            let skR = K::DecapKey::import(&g.skRm[..]).unwrap_or_else(|_| panic!("group={i}"));
            let mode = g.get_mode(i, &g.pkSm[..]);
            Hpke::<K, F, A>::setup_recv(mode.as_ref(), &enc, &skR, &g.info)
                .unwrap_or_else(|_| panic!("group={i}"))
        };

        for (id, tc) in g.tests.iter().enumerate() {
            let ct = {
                let mut dst = vec![0u8; tc.pt.len() + SealCtx::<A>::OVERHEAD];
                send.seal(&mut dst, &tc.pt, &tc.aad).unwrap_or_else(|_| {
                    panic!("encryption failure: {id}/{} (g={i})", g.tests.len())
                });
                dst
            };
            assert_eq!(
                ct,
                &tc.ct[..],
                "invalid ciphertext for enc {id}/{} (g={i})",
                g.tests.len()
            );

            let pt = {
                let mut dst = vec![0u8; tc.pt.len()];
                recv.open(&mut dst, &tc.ct, &tc.aad).unwrap_or_else(|_| {
                    panic!("decryption failure: {id}/{} (g={i})", g.tests.len())
                });
                dst
            };
            assert_eq!(
                pt,
                &tc.pt[..],
                "invalid plaintext for enc {id}/{} (g={i})",
                g.tests.len()
            );
        }

        for (id, tc) in g.exports.iter().enumerate() {
            let n = g.exports.len();

            let mut got = vec![0u8; tc.len];
            send.export_into(got.as_mut(), &tc.exporter_context)
                .expect("unable to export secret {id}/{n} (g={i})");
            assert_eq!(
                got,
                &tc.exported_value[..],
                "invalid exported secret {id}/{n} (g={i})",
            );

            let mut got = vec![0u8; tc.len];
            recv.export_into(got.as_mut(), &tc.exporter_context)
                .expect("unable to export secret {id}/{n} (g={i})");
            assert_eq!(
                got,
                &tc.exported_value[..],
                "invalid exported secret {id}/{n} (g={i})",
            );
        }
    }
}

/// Tests a [`Mac`] against Project Wycheproof test vectors.
///
/// It tests both `T` and [`MacWithDefaults<T>`].
pub fn test_mac<T: Mac>(name: MacTest)
where
    T::Key: ConstantTimeEq,
    T::Tag: for<'a> TryFrom<&'a [u8]>,
{
    test_mac_inner::<T>(name);
    test_mac_inner::<MacWithDefaults<T>>(name);
}

fn test_mac_inner<T: Mac>(name: MacTest)
where
    T::Key: ConstantTimeEq,
    T::Tag: for<'a> TryFrom<&'a [u8]>,
{
    let set = mac::TestSet::load(name).expect("should be able to load tests");
    for g in &set.test_groups {
        for tc in &g.tests {
            let id = tc.tc_id;

            let tc_tag: T::Tag = match tc.tag[..].try_into() {
                Ok(tag) => tag,
                // Skip truncated tags.
                Err(_) => continue,
            };

            let key = match T::Key::import(&tc.key[..]) {
                Ok(h) => h,
                // Skip insecure keys.
                Err(_) => continue,
            };
            let mut h = T::new(&key);

            // Update one character at a time.
            for c in tc.msg.iter() {
                h.update(&[*c]);
            }
            // An empty update.
            h.update(&[]);

            match tc.result {
                TestResult::Valid | TestResult::Acceptable => {
                    h.clone().verify(&tc_tag).unwrap_or_else(|_| panic!("{id}"));
                    assert_eq!(h.clone().tag().ct_eq(&tc_tag).unwrap_u8(), 1, "{id}");
                    assert_eq!(h.clone().tag().ct_eq(&h.tag()).unwrap_u8(), 1, "{id}");
                }
                TestResult::Invalid => {
                    h.verify(&tc_tag).expect_err(msg!(id));
                }
            };
        }
    }
}
