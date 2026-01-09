use anyhow::{Context as _, Result};
use aranya_crypto::{
    CipherSuite, DeviceId, Engine, IdentityKey, IdentityVerifyingKey, KeyStore, KeyStoreExt as _,
    SigningKey, SigningKeyId, VerifyingKey,
};
use derive_where::derive_where;
use serde::{Deserialize, Serialize};

/// A key bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyBundle {
    /// See [`IdentityKey`].
    pub device_id: DeviceId,
    /// See [`SigningKey`].
    pub sign_id: SigningKeyId,
}

/// A minimum key bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MinKeyBundle {
    /// See [`IdentityKey`].
    pub device_id: DeviceId,
}

/// Public keys from key bundle.
#[derive_where(Debug)]
pub struct PublicKeys<CS: CipherSuite> {
    /// Public identity key.
    pub ident_pk: IdentityVerifyingKey<CS>,
    /// Public signing key.
    pub sign_pk: VerifyingKey<CS>,
}

impl KeyBundle {
    /// Generates a key bundle.
    ///
    /// The wrapped keys are stored inside of `store`.
    pub fn generate<CE, S>(eng: &mut CE, store: &mut S) -> Result<Self>
    where
        CE: Engine,
        S: KeyStore,
    {
        macro_rules! gen_key {
            ($key:ident) => {{
                let sk = $key::<CE::CS>::new(eng);
                store.insert_key(eng, sk).context(concat!(
                    "unable to insert wrapped `",
                    stringify!($key),
                    "`"
                ))?
            }};
        }
        Ok(Self {
            device_id: gen_key!(IdentityKey),
            sign_id: gen_key!(SigningKey),
        })
    }

    /// Loads the public keys from `store`.
    pub fn public_keys<CE, S>(&self, eng: &mut CE, store: &S) -> Result<PublicKeys<CE::CS>>
    where
        CE: Engine,
        S: KeyStore,
    {
        Ok(PublicKeys {
            ident_pk: store
                .get_key::<_, IdentityKey<CE::CS>>(eng, self.device_id)
                .context("unable to load `IdentityKey`")?
                .context("unable to find `IdentityKey`")?
                .public()?,
            sign_pk: store
                .get_key::<_, SigningKey<CE::CS>>(eng, self.sign_id)
                .context("unable to load `SigningKey`")?
                .context("unable to find `SigningKey`")?
                .public()?,
        })
    }
}

impl MinKeyBundle {
    /// Generates a minimum key bundle.
    ///
    /// The wrapped keys are stored inside of `store`.
    pub fn generate<CE, S>(eng: &mut CE, store: &mut S) -> Result<Self>
    where
        CE: Engine,
        S: KeyStore,
    {
        macro_rules! gen_key {
            ($key:ident) => {{
                let sk = $key::<CE::CS>::new(eng);
                store.insert_key(eng, sk).context(concat!(
                    "unable to insert wrapped `",
                    stringify!($key),
                    "`"
                ))?
            }};
        }
        Ok(Self {
            device_id: gen_key!(IdentityKey),
        })
    }
}
