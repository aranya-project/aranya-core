//! Testing FFI
//!
//! An FFI for `preamble:` sections that provides utility functions for
//! creating specific or random values.
//!
//! ## `function random_bytes(n int) bytes`
//!
//! Generate `n` random bytes.
//!
//! ## `function random_id() id`
//!
//! Generate a random ID.
//!
//! ## `function random_key() bytes`
//!
//! Generate a random key. The secret portion of the key is stored
//! in the keystore.
//!
//! ## `function bytes_from_hex(hex_str string) bytes`
//!
//! Convert a hex string into bytes. The number of hex digits must
//! be a multiple of 2.
//!
//! ## `function id_from_hex(hex_str string) id`
//!
//! Convert a hex string into an ID. The hex string must have
//! exactly 64 hex digits.
use std::{cell::RefCell, ops::DerefMut as _};

use aranya_crypto::{BaseId, Engine, KeyStore, KeyStoreExt as _, SigningKey};
use aranya_policy_vm::{
    CommandContext, MachineError, MachineErrorType, MachineIOError, Text, ffi::ffi,
};

/// TestingFFI contains utility functions for generating bytes and ids
/// for various testing needs.
///
/// It is not expected that you will instantiate this yourself, as it is
/// not useful outside of the policy runner framework.
#[doc(hidden)]
pub struct TestingFfi<'o, KS> {
    // RefCell is needed here because the FFI traits only allow
    // functions to be called with `&self` but we need to be able to
    // mutate the keystore when generating keys. And it takes a `&mut`
    // because we do not own the keystore but it doesn't need to be
    // accessed concurrently while the preamble is being executed (which
    // would necessitate something like Arc<Mutex<KS>>).
    keystore: RefCell<&'o mut KS>,
}

impl<'o, KS> TestingFfi<'o, KS> {
    #[doc(hidden)]
    pub fn new(keystore: &'o mut KS) -> Self {
        Self {
            keystore: RefCell::new(keystore),
        }
    }
}

#[ffi(module = "testing")]
impl<'o, KS: KeyStore> TestingFfi<'o, KS> {
    #[ffi_export(def = "function random_bytes(n int) bytes")]
    pub fn random_bytes<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &E,
        n: i64,
    ) -> Result<Vec<u8>, MachineError> {
        if n <= 0 {
            return Err(MachineError::new(MachineErrorType::Unknown(
                "Must generate one or more bytes in testing::random_bytes()".to_string(),
            )));
        }
        // checked by above if statement
        #[allow(clippy::cast_sign_loss)]
        let n = n as usize;
        // really wish there was a way to generate random values without zeroing the buffer first
        let mut v = vec![0; n];
        eng.fill_bytes(&mut v);
        Ok(v)
    }

    #[ffi_export(def = "function random_id() id")]
    pub fn random_id<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &E,
    ) -> Result<BaseId, MachineError> {
        let bytes = self.random_bytes(_ctx, eng, 32)?;
        let array_bytes = bytes.try_into().expect("we asked for 32 bytes");
        Ok(BaseId::from_bytes(array_bytes))
    }

    #[ffi_export(def = "function random_key() bytes")]
    pub fn random_key<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &E,
    ) -> Result<Vec<u8>, MachineError> {
        let sk: SigningKey<E::CS> = SigningKey::new(eng);
        let mut refmut = self.keystore.try_borrow_mut().map_err(|e| {
            tracing::error!("{e}");
            MachineError::new(MachineErrorType::IO(MachineIOError::Internal))
        })?;
        let keystore = refmut.deref_mut();
        keystore.insert_key(eng, sk.clone()).map_err(|e| {
            tracing::error!("{e}");
            MachineError::new(MachineErrorType::IO(MachineIOError::Internal))
        })?;
        let pk = sk.public().expect("what");
        postcard::to_allocvec(&pk).map_err(|e| {
            tracing::error!("{e}");
            MachineError::new(MachineErrorType::Unknown(
                "Could not serialize pubkey".to_string(),
            ))
        })
    }

    #[ffi_export(def = "function bytes_from_hex(hex_str string) bytes")]
    pub fn bytes_from_hex<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E,
        hex_str: Text,
    ) -> Result<Vec<u8>, MachineError> {
        let s = hex_str.as_str();
        let hex_str: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        if !hex_str.len().is_multiple_of(2) {
            return Err(MachineError::new(MachineErrorType::Unknown(
                "hex string must be an even number of hex digits".to_string(),
            )));
        }
        let bytes: Vec<u8> = hex_str
            .char_indices()
            .step_by(2)
            .map(|(i, _)| {
                let i_plus_two = i.wrapping_add(2);
                u8::from_str_radix(&hex_str[i..i_plus_two], 16)
                    .expect("cannot fail as we already filtered the allowed characters")
            })
            .collect();
        Ok(bytes)
    }

    #[ffi_export(def = "function id_from_hex(hex_str string) id")]
    pub fn id_from_hex<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E,
        hex_str: Text,
    ) -> Result<BaseId, MachineError> {
        let bytes = self.bytes_from_hex(_ctx, _eng, hex_str)?;
        let array_bytes = bytes.try_into().map_err(|_| {
            MachineError::new(MachineErrorType::Unknown(
                "Not exactly 32 bytes".to_string(),
            ))
        })?;
        Ok(BaseId::from_bytes(array_bytes))
    }

    /// This exists purely to unit test the `PolicyVm` error variant in
    /// [`RunFile`](crate::RunFile).
    #[doc(hidden)]
    #[ffi_export(def = "function cause_machine_error() bool")]
    pub fn cause_machine_error<E: Engine>(
        &self,
        _ctx: &CommandContext,
        _eng: &E,
    ) -> Result<bool, MachineError> {
        Err(MachineError::new(MachineErrorType::Unknown(
            "BOO!".to_string(),
        )))
    }
}
