use std::sync::Mutex;

use aranya_crypto::{BaseId, Engine, KeyStore, KeyStoreExt as _, SigningKey, buggy::BugExt as _};
use aranya_policy_vm::{
    CommandContext, MachineError, MachineErrorType, MachineIOError, Text, ffi::ffi,
};

pub struct TestingFfi<KS> {
    keystore: Mutex<KS>,
}

impl<KS> TestingFfi<KS> {
    pub fn new(keystore: KS) -> Self {
        Self {
            keystore: Mutex::new(keystore),
        }
    }
}

#[ffi(module = "testing")]
impl<KS: KeyStore> TestingFfi<KS> {
    #[ffi_export(def = "function random_bytes(n int) bytes")]
    pub fn random_bytes<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
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
        eng: &mut E,
    ) -> Result<BaseId, MachineError> {
        let bytes = self.random_bytes(_ctx, eng, 32)?;
        let array_bytes = bytes.try_into().expect("we asked for 32 bytes");
        Ok(BaseId::from_bytes(array_bytes))
    }

    #[ffi_export(def = "function random_key() bytes")]
    pub fn random_key<E: Engine>(
        &self,
        _ctx: &CommandContext,
        eng: &mut E,
    ) -> Result<Vec<u8>, MachineError> {
        let sk: SigningKey<E::CS> = SigningKey::new(eng);
        self.keystore
            .lock()
            .assume("lock poisoned")?
            .insert_key(eng, sk.clone())
            .map_err(|e| {
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
        _eng: &mut E,
        hex_str: Text,
    ) -> Result<Vec<u8>, MachineError> {
        let s = hex_str.as_str();
        let hex_str: String = s.chars().filter(char::is_ascii_hexdigit).collect();
        if hex_str.len() % 2 != 0 {
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
        _eng: &mut E,
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
}
