extern crate alloc;

use alloc::vec::Vec;
use core::convert::Infallible;

use aranya_crypto::{
    custom_id, engine::Engine, policy, EncryptionPublicKey, Id, IdentityVerifyingKey, KeyStore,
    PolicyId, VerifyingKey,
};
use aranya_policy_vm::{
    ffi::{ffi, Type},
    CommandContext, Text, Typed, Value, ValueConversionError,
};

use crate::error::Error;

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
