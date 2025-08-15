//! Utilities for testing [`Ffi`] with different [`Engine`]s and
//! [`KeyStore`]s.

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

use core::marker::PhantomData;

use aranya_crypto::{
    Csprng, DeviceId, Engine, Id, KeyStore, KeyStoreExt as _, Random, SignerError, SigningKey,
    policy::CmdId,
};
use aranya_policy_vm::{
    ActionContext, CommandContext, OpenContext, PolicyContext, SealContext, ident,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ErrorKind, WrongContext},
    ffi::{Ffi, Signed},
};

/// Performs all of the unit tests.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use aranya_crypto::{default::DefaultEngine, keystore::memstore::MemStore, Rng};
///
/// use aranya_crypto_ffi::run_tests;
///
/// run_tests!(default_engine, || -> (DefaultEngine<_, _>, MemStore) {
///     let (eng, _) = DefaultEngine::<_>::from_entropy(Rng);
///     let store = MemStore::new();
///     (eng, store)
/// });
/// ```
#[macro_export]
macro_rules! run_tests {
    ($name:ident, || -> ($engine:ty, $store:ty) { $($args:tt)+ }) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            macro_rules! test {
                ($test:ident) => {
                    #[test]
                    fn $test() {
                        let (eng, store) = { $($args)+ };
                        $crate::testing::Tests::$test(eng, store);
                    }
                };
            }

            test!(test_sign_verify);
            test!(test_verify_reject_modified_sig);
            test!(test_verify_reject_modified_command);
            test!(test_verify_reject_different_cmd_name);
            test!(test_verify_reject_different_parent_cmd_id);
            test!(test_verify_reject_different_signing_key);
            test!(test_seal_reject_wrong_context);
            test!(test_verify_reject_wrong_context);
        }
    };
}
#[cfg(test)]
pub(crate) use run_tests;

/// The unit tests.
pub struct Tests<E, S>(PhantomData<(E, S)>);

impl<E, S> Tests<E, S>
where
    E: Engine,
    S: KeyStore,
{
    const SEAL_CTX: CommandContext = CommandContext::Seal(SealContext {
        name: ident!("dummy"),
        head_id: Id::default(),
    });

    const OPEN_CTX: CommandContext = CommandContext::Open(OpenContext {
        name: ident!("dummy"),
    });

    /// Test that we can verify valid signatures.
    pub fn test_sign_verify(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &Self::SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");
        let got = ffi
            .verify(
                &Self::OPEN_CTX,
                &mut eng,
                pk,
                CmdId::default(),
                command.clone(),
                command_id.into(),
                signature,
            )
            .expect("`crypto::verify` should not fail");
        assert_eq!(got, command);
    }

    /// Test that we reject signatures that have been tampered
    /// with.
    pub fn test_verify_reject_modified_sig(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            mut signature,
            command_id,
        } = ffi
            .sign(
                &Self::SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");

        for v in &mut signature {
            *v = v.wrapping_add(1);
        }

        // We don't check the exact error or its kind here since
        // it could be either a normal verification failure or it
        // could be a failure because `sig` is malformed.
        ffi.verify(
            &Self::OPEN_CTX,
            &mut eng,
            pk,
            CmdId::default(),
            command,
            command_id.into(),
            signature,
        )
        .expect_err("`crypto::verify` should fail");
    }

    /// Test that we reject signatures that were not over the
    /// command (or where the command was modified).
    pub fn test_verify_reject_modified_command(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let mut command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &Self::SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");

        for v in &mut command {
            *v = v.wrapping_add(1);
        }

        let err = ffi
            .verify(
                &Self::OPEN_CTX,
                &mut eng,
                pk,
                CmdId::default(),
                command,
                command_id.into(),
                signature,
            )
            .expect_err("`crypto::verify` should fail");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Signer(SignerError::Verification)),
        );
    }

    /// Test that we reject signatures created with a different
    /// command name.
    pub fn test_verify_reject_different_cmd_name(mut eng: E, mut store: S) {
        const SEAL_CTX: CommandContext = CommandContext::Seal(SealContext {
            name: ident!("foo"),
            head_id: Id::default(),
        });

        const OPEN_CTX: CommandContext = CommandContext::Open(OpenContext {
            name: ident!("bar"),
        });

        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");

        let err = ffi
            .verify(
                &OPEN_CTX,
                &mut eng,
                pk,
                CmdId::default(),
                command,
                command_id.into(),
                signature,
            )
            .expect_err("`crypto::verify` should fail");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Signer(SignerError::Verification)),
        );
    }

    /// Test that we reject signatures created with a different
    /// parent command ID.
    pub fn test_verify_reject_different_parent_cmd_id(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");

        let seal_ctx = CommandContext::Seal(SealContext {
            name: ident!("dummy"),
            head_id: Id::random(&mut eng),
        });
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &seal_ctx,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");

        let open_ctx = CommandContext::Open(OpenContext {
            name: ident!("dummy"),
        });
        let err = ffi
            .verify(
                &open_ctx,
                &mut eng,
                pk,
                CmdId::default(),
                command,
                command_id.into(),
                signature,
            )
            .expect_err("`crypto::verify` should fail");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Signer(SignerError::Verification)),
        );
    }

    /// Test that we reject signatures created with a different
    /// [`SigningKey`].
    pub fn test_verify_reject_different_signing_key(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = {
                // NB: different `SigningKey`.
                let sk = SigningKey::<E::CS>::new(&mut eng);
                postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                    .expect("should be able to encode `VerifyingKey`")
            };
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &Self::SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");
        let err = ffi
            .verify(
                &Self::OPEN_CTX,
                &mut eng,
                pk,
                CmdId::default(),
                command,
                command_id.into(),
                signature,
            )
            .expect_err("`crypto::verify` should fail");
        assert_eq!(err.kind(), ErrorKind::Crypto);
        assert_eq!(
            err.downcast_ref::<aranya_crypto::Error>(),
            Some(&aranya_crypto::Error::Signer(SignerError::Verification)),
        );
    }

    /// Test that `seal` returns an error when called outside
    /// of a `seal` block.
    pub fn test_seal_reject_wrong_context(mut eng: E, mut store: S) {
        let sk = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            sk
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");

        for ctx in &[
            CommandContext::Action(ActionContext {
                name: ident!("dummy"),
                head_id: Id::default(),
            }),
            CommandContext::Open(OpenContext {
                name: ident!("dummy"),
            }),
            CommandContext::Policy(PolicyContext {
                name: ident!("dummy"),
                id: Id::default(),
                author: DeviceId::default(),
                version: Id::default(),
            }),
            CommandContext::Recall(PolicyContext {
                name: ident!("dummy"),
                id: Id::default(),
                author: DeviceId::default(),
                version: Id::default(),
            }),
        ] {
            let err = ffi
                .sign(
                    ctx,
                    &mut eng,
                    sk.id().expect("signing key ID should be valid"),
                    command.clone(),
                )
                .expect_err("`crypto::sign` should fail");
            assert_eq!(err.kind(), ErrorKind::WrongContext);
            assert!(err.downcast_ref::<WrongContext>().is_some());
        }
    }

    /// Test that `verify` returns an error when called outside
    /// of an `open` block.
    pub fn test_verify_reject_wrong_context(mut eng: E, mut store: S) {
        let (sk, pk) = {
            let sk = SigningKey::<E::CS>::new(&mut eng);
            let pk = postcard::to_allocvec(&sk.public().expect("verifying key should be valid"))
                .expect("should be able to encode `VerifyingKey`");
            store
                .insert_key(&mut eng, sk.clone())
                .expect("should be able to insert wrapped `SigningKey`");
            (sk, pk)
        };
        let ffi = Ffi::new(store);

        let command = postcard::to_allocvec(&Command::random(&mut eng))
            .expect("should be able to encode `Command`");
        let Signed {
            signature,
            command_id,
        } = ffi
            .sign(
                &Self::SEAL_CTX,
                &mut eng,
                sk.id().expect("signing key ID should be valid"),
                command.clone(),
            )
            .expect("should be able to create signature");

        for ctx in &[
            CommandContext::Action(ActionContext {
                name: ident!("dummy"),
                head_id: Id::default(),
            }),
            CommandContext::Seal(SealContext {
                name: ident!("dummy"),
                head_id: Id::default(),
            }),
            CommandContext::Policy(PolicyContext {
                name: ident!("dummy"),
                id: Id::default(),
                author: DeviceId::default(),
                version: Id::default(),
            }),
            CommandContext::Recall(PolicyContext {
                name: ident!("dummy"),
                id: Id::default(),
                author: DeviceId::default(),
                version: Id::default(),
            }),
        ] {
            let err = ffi
                .verify(
                    ctx,
                    &mut eng,
                    pk.clone(),
                    CmdId::default(),
                    command.clone(),
                    command_id.into(),
                    signature.clone(),
                )
                .expect_err("`crypto::verify` should fail");
            assert_eq!(err.kind(), ErrorKind::WrongContext);
            assert!(err.downcast_ref::<WrongContext>().is_some());
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
struct Command([u8; 32]);

impl Random for Command {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}
