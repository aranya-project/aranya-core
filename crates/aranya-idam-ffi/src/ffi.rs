extern crate alloc;

use alloc::{vec, vec::Vec};
use core::convert::Infallible;

use aranya_crypto::{
    custom_id, engine::Engine, policy, zeroize::Zeroizing, Context, Encap, EncryptedGroupKey,
    EncryptionKey, EncryptionPublicKey, GroupKey, Id, IdentityVerifyingKey, KeyStore, KeyStoreExt,
    PolicyId, SigningKey, VerifyingKey,
};
use aranya_policy_vm::{
    ffi::{ffi, Type},
    CommandContext, Text, Typed, Value, ValueConversionError,
};

use crate::error::{AllocError, Error, ErrorKind, KeyNotFound, WrongContext};

/// An [`FfiModule`][aranya_policy_vm::ffi::FfiModule] for IDAM.
///
/// - `K` should be an implementation of [`KeyStore`]
pub struct Ffi<K> {
    store: K,
}

impl<K> Ffi<K> {
    /// Creates a new `Ffi`
    #[inline]
    pub const fn new(store: K) -> Self {
        Self { store }
    }
}

#[ffi(
    module = "idam",
    def = r#"
// A GroupKey as stored in the fact database.
struct StoredGroupKey {
    // Uniquely identifies the GroupKey.
    key_id id,
    // The wrapped GroupKey.
    wrapped bytes,
}

// An encrypted GroupKey.
struct SealedGroupKey {
    // The encapsulated secret key needed to decrypt
    // `ciphertext`.
    encap bytes,
    // The encrypted GroupKey.
    ciphertext bytes,
}
"#
)]
#[allow(clippy::too_many_arguments)]
impl<K: KeyStore> Ffi<K> {
    /// Returns the ID of an encoded [`EncryptionPublicKey`].
    #[ffi_export(def = r#"
function derive_enc_key_id(
    // The encoded `EncryptionPublicKey`.
    enc_pk bytes,
) id
"#)]
    pub(crate) fn derive_enc_key_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        enc_pk: Vec<u8>,
    ) -> Result<Id, Error> {
        let pk: EncryptionPublicKey<E::CS> = postcard::from_bytes(&enc_pk)?;
        Ok(pk.id()?.into())
    }

    /// Returns the ID of an encoded [`VerifyingKey`].
    #[ffi_export(def = r#"
function derive_sign_key_id(
    // The encoded `VerifyingKey`.
    sign_pk bytes,
) id
"#)]
    pub(crate) fn derive_sign_key_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        sign_pk: Vec<u8>,
    ) -> Result<Id, Error> {
        let pk: VerifyingKey<E::CS> = postcard::from_bytes(&sign_pk)?;
        Ok(pk.id().map_err(aranya_crypto::Error::from)?.into())
    }

    /// Returns the ID of an encoded [`IdentityVerifyingKey`].
    #[ffi_export(def = r#"
function derive_device_id(
    // The encoded `IdentityVerifyingKey`.
    ident_pk bytes,
) id
"#)]
    pub(crate) fn derive_device_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        ident_pk: Vec<u8>,
    ) -> Result<Id, Error> {
        let pk: IdentityVerifyingKey<E::CS> = postcard::from_bytes(&ident_pk)?;
        Ok(pk.id().map_err(aranya_crypto::Error::from)?.into())
    }

    /// Generates a random [`GroupKey`].
    #[ffi_export(def = r#"
function generate_group_key() struct StoredGroupKey
"#)]
    pub(crate) fn generate_group_key<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
    ) -> Result<StoredGroupKey, Error> {
        let group_key = GroupKey::new(eng);
        let key_id = group_key.id()?.into();
        let wrapped = {
            let wrapped = eng.wrap(group_key)?;
            postcard::to_allocvec(&wrapped)?
        };
        Ok(StoredGroupKey { key_id, wrapped })
    }

    /// Encrypts the [`GroupKey`] for another device.
    #[ffi_export(def = r#"
function seal_group_key(
    wrapped_group_key bytes,
    peer_enc_pk bytes,
    group_id id,
) struct SealedGroupKey
"#)]
    pub(crate) fn seal_group_key<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
        wrapped_group_key: Vec<u8>,
        peer_enc_pk: Vec<u8>,
        group_id: Id,
    ) -> Result<SealedGroupKey, Error> {
        let group_key: GroupKey<E::CS> = {
            let wrapped = postcard::from_bytes(&wrapped_group_key)?;
            eng.unwrap(&wrapped)?
        };
        let pk: EncryptionPublicKey<E::CS> = postcard::from_bytes(&peer_enc_pk)?;
        let (encap, ciphertext) = pk.seal_group_key(eng, &group_key, group_id)?;
        Ok(SealedGroupKey {
            encap: encap.as_bytes().to_vec(),
            ciphertext: postcard::to_allocvec(&ciphertext)?,
        })
    }

    /// Decrypts a [`GroupKey`] received from another device.
    #[ffi_export(def = r#"
function open_group_key(
    sealed_group_key struct SealedGroupKey,
    our_enc_sk_id id,
    group_id id,
) struct StoredGroupKey
"#)]
    pub(crate) fn open_group_key<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
        sealed_group_key: SealedGroupKey,
        our_enc_sk_id: Id,
        group_id: Id,
    ) -> Result<StoredGroupKey, Error> {
        let sk: EncryptionKey<E::CS> = self
            .store
            .get_key(eng, our_enc_sk_id)
            .map_err(|err| Error::new(ErrorKind::KeyStore, err))?
            .ok_or_else(|| Error::new(ErrorKind::KeyNotFound, KeyNotFound(our_enc_sk_id)))?;
        debug_assert_eq!(
            sk.id().map_err(aranya_crypto::Error::from)?.into_id(),
            our_enc_sk_id
        );

        let group_key = {
            let enc = Encap::<E::CS>::from_bytes(&sealed_group_key.encap)?;
            let ciphertext: EncryptedGroupKey<E::CS> =
                postcard::from_bytes(&sealed_group_key.ciphertext)?;
            sk.open_group_key(&enc, ciphertext, group_id)?
        };

        let key_id = group_key.id()?.into();
        let wrapped = {
            let wrapped = eng.wrap(group_key)?;
            postcard::to_allocvec(&wrapped)?
        };
        Ok(StoredGroupKey { key_id, wrapped })
    }

    /// Encrypt a message using the [`GroupKey`].
    #[ffi_export(def = r#"
function encrypt_message(
    plaintext bytes,
    wrapped_group_key bytes,
    our_sign_sk_id id,
    // Name of the command that will carry the
    // encrypted message.
    label string,
) bytes
"#)]
    pub(crate) fn encrypt_message<E: Engine>(
        &self,
        ctx: &CommandContext,
        eng: &mut E,
        plaintext: Vec<u8>,
        wrapped_group_key: Vec<u8>,
        our_sign_sk_id: Id,
        label: Text,
    ) -> Result<Vec<u8>, Error> {
        let plaintext = Zeroizing::new(plaintext);

        let CommandContext::Action(ctx) = ctx else {
            return Err(WrongContext("`idam::encrypt_message` called outside of an action").into());
        };

        let group_key: GroupKey<E::CS> = {
            let wrapped = postcard::from_bytes(&wrapped_group_key)?;
            eng.unwrap(&wrapped)?
        };

        let sk: SigningKey<E::CS> = self
            .store
            .get_key(eng, our_sign_sk_id)
            .map_err(|err| Error::new(ErrorKind::KeyStore, err))?
            .ok_or_else(|| Error::new(ErrorKind::KeyNotFound, KeyNotFound(our_sign_sk_id)))?;
        let our_sign_pk = sk.public().expect("signing key should be valid");

        let ctx = Context {
            label: label.as_str(),
            parent: ctx.head_id,
            author_sign_pk: &our_sign_pk,
        };
        let mut ciphertext = {
            let len = plaintext
                .len()
                .checked_add(GroupKey::<E::CS>::OVERHEAD)
                .ok_or_else(|| Error::new(ErrorKind::Alloc, AllocError::new()))?;
            vec![0u8; len]
        };
        group_key.seal(eng, &mut ciphertext, &plaintext, ctx)?;
        Ok(ciphertext)
    }

    /// Encrypt a message using the [`GroupKey`].
    #[ffi_export(def = r#"
function decrypt_message(
    parent_id id,
    ciphertext bytes,
    wrapped_group_key bytes,
    author_sign_pk bytes,
) bytes
"#)]
    pub(crate) fn decrypt_message<E: Engine>(
        &self,
        ctx: &CommandContext,
        eng: &mut E,
        parent_id: Id,
        ciphertext: Vec<u8>,
        wrapped_group_key: Vec<u8>,
        author_sign_pk: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let CommandContext::Policy(ctx) = ctx else {
            return Err(
                WrongContext("`idam::decrypt_message` called outside of a `policy` block").into(),
            );
        };
        let group_key: GroupKey<E::CS> = {
            let wrapped = postcard::from_bytes(&wrapped_group_key)?;
            eng.unwrap(&wrapped)?
        };
        let author_pk: &VerifyingKey<E::CS> = &postcard::from_bytes(&author_sign_pk)?;

        let ctx = Context {
            label: ctx.name.as_str(),
            parent: parent_id,
            author_sign_pk: author_pk,
        };
        let mut plaintext = {
            let len = ciphertext.len().saturating_sub(GroupKey::<E::CS>::OVERHEAD);
            vec![0u8; len]
        };
        group_key.open(&mut plaintext, &ciphertext, ctx)?;
        Ok(plaintext)
    }

    /// Calculates the next change ID.
    #[ffi_export(def = r#"
function compute_change_id(
    new_cmd_id id,
    current_change_id id,
) id
"#)]
    pub(crate) fn compute_change_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        new_cmd_id: Id,
        current_change_id: Id,
    ) -> Result<Id, Error> {
        // ChangeID = H("ID-v1" || suites || data || tag)
        Ok(Id::new::<E::CS>(
            current_change_id.as_bytes(),
            new_cmd_id.as_bytes(),
        ))
    }

    /// Computes the ID of a role.
    #[ffi_export(def = r#"
function label_id(
    cmd_id id,
    name string,
) id
"#)]
    pub(crate) fn label_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &mut E,
        cmd_id: Id,
        name: Text,
    ) -> Result<RoleId, Infallible> {
        // TODO(eric): Use the real policy ID once it's
        // available.
        let policy_id = PolicyId::default();
        let id = policy::role_id::<E::CS>(cmd_id.into(), &name, policy_id)
            .into_id()
            .into();
        Ok(id)
    }
}

custom_id! {
    /// Uniquely identifies a role.
    pub struct RoleId;
}

impl Typed for RoleId {
    const TYPE: Type<'static> = Type::Id;
}

impl TryFrom<Value> for RoleId {
    type Error = ValueConversionError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let id: Id = value.try_into()?;
        Ok(RoleId::from(id))
    }
}

impl From<RoleId> for Value {
    fn from(id: RoleId) -> Value {
        Value::Id(id.into())
    }
}
