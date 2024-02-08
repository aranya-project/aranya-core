extern crate alloc;

use alloc::vec::Vec;
use core::borrow::Borrow;

use crypto::{
    subtle::ConstantTimeEq, Cmd, Engine, Id, KeyStore, Signature, SigningKey, VerifyingKey,
};
use policy_vm::{ffi::ffi, CommandContext};

use crate::error::{Error, ErrorKind, InvalidCmdId, KeyNotFound, WrongContext};

/// Implements `crypto-ffi`.
///
/// ```text
/// use crypto
/// use device
/// use envelope
///
/// command Init {
///     seal {
///         let author_id = device::device_id()
///         let author_sign_sk_id = /* TODO */
///         let signed = crypto::sign(
///             author_sign_sk_id,
///             serialize(this),
///         )
///         return envelope::new(
///             author_id,
///             signed.command_id,
///             signed.signature,
///             payload,
///         )
///     }
///
///     open {
///         let author_id = envelope::author_id(envelope)
///         let author_sign_pk = /* TODO */
///         let command = crypto::verify(
///             author_sign_pk,
///             envelope::payload(envelope),
///             envelope::command_id(envelope),
///             envelope::signature(envelope),
///         )
///         return deserialize(command)
///     }
/// }
///
/// command Foo {
///     seal {
///         let author_id = device::device_id()
///         let author_sign_sk_id = unwrap query UserSignKey[user_id: author_id]=>{ ... }
///         let signed = crypto::sign(
///             author_sign_sk_id,
///             serialize(this),
///         )
///         return envelope::new(
///             author_id,
///             signed.command_id,
///             signed.signature,
///             payload,
///         )
///     }
///
///     open {
///         let author_id = envelope::author_id(envelope)
///         let author_sign_pk = unwrap query UserSignKey[user_id: author_id]=>{ ... }
///         let command = crypto::verify(
///             author_sign_pk,
///             envelope::payload(envelope),
///             envelope::command_id(envelope),
///             envelope::signature(envelope),
///         )
///         return deserialize(command)
///     }
/// }
/// ```
#[derive(Clone)]
pub struct Ffi<S> {
    store: S,
}

impl<S> Ffi<S> {
    /// Creates a new `Ffi`.
    #[inline]
    pub const fn new(store: S) -> Self {
        Self { store }
    }
}

#[ffi(
    module = "crypto",
    def = r#"
// TODO(eric): this name sucks
struct Signed {
    signature bytes,
    command_id id,
}
"#
)]
impl<S: KeyStore> Ffi<S> {
    /// Signs `command`.
    #[ffi_export(def = r#"
function sign(
    our_sign_sk_id id,
    command bytes,
) struct Seal
"#)]
    pub(crate) fn sign<E: Engine + ?Sized>(
        &self,
        ctx: &CommandContext<'_>,
        eng: &mut E,
        our_sign_sk_id: Id,
        command: Vec<u8>,
    ) -> Result<Signed, Error> {
        let CommandContext::Seal(ctx) = ctx else {
            return Err(WrongContext("`crypto::sign` used outside of a `seal` block").into());
        };

        let sk: SigningKey<E> = {
            let wrapped = self
                .store
                .get(&our_sign_sk_id)
                .map_err(|err| Error::new(ErrorKind::KeyStore, err))?
                .ok_or(KeyNotFound(our_sign_sk_id))?;
            eng.unwrap(&wrapped)?
        };
        debug_assert_eq!(sk.id().into_id(), our_sign_sk_id);

        let (sig, id) = sk.sign_cmd(Cmd {
            data: &command,
            name: ctx.name,
            parent_id: &ctx.parent_id,
        })?;
        Ok(Signed {
            signature: sig.to_bytes().borrow().to_vec(),
            command_id: id.into(),
        })
    }

    /// Verifies the signature created over `command` by
    /// `author_sign_pk`.
    #[ffi_export(def = r#"
function verify(
    author_sign_pk bytes,
    command bytes,
    command_id id,
    signature bytes,
) id
"#)]
    pub(crate) fn verify<E: Engine + ?Sized>(
        &self,
        ctx: &CommandContext<'_>,
        _eng: &mut E,
        author_sign_pk: Vec<u8>,
        command: Vec<u8>,
        command_id: Id,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let CommandContext::Open(ctx) = ctx else {
            return Err(WrongContext("`crypto::verify` used outside of an `open` block").into());
        };

        let pk: VerifyingKey<E> = postcard::from_bytes(&author_sign_pk)?;
        let signature = Signature::<E>::from_bytes(&signature)?;

        let cmd = Cmd {
            data: &command,
            name: ctx.name,
            parent_id: &ctx.parent_id,
        };
        let id = pk.verify_cmd(cmd, &signature)?;
        if bool::from(id.ct_eq(&command_id.into())) {
            Ok(command)
        } else {
            Err(InvalidCmdId(()).into())
        }
    }
}
