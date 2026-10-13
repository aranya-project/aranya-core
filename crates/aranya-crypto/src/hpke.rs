//! HPKE augmented with OIDs.

// Use the same names as in `spideroak-crypto`.
#![allow(non_snake_case)]

pub(crate) use spideroak_crypto::hpke::Mode;
use spideroak_crypto::{
    hpke::{self, HpkeError},
    kem::Kem,
};

use crate::{Csprng, ciphersuite::CipherSuite};

type Hpke<CS> =
    hpke::Hpke<<CS as CipherSuite>::Kem, <CS as CipherSuite>::Kdf, <CS as CipherSuite>::Aead>;
type DecapKey<CS> = <<CS as CipherSuite>::Kem as Kem>::DecapKey;
type EncapKey<CS> = <<CS as CipherSuite>::Kem as Kem>::EncapKey;
type Encap<CS> = <<CS as CipherSuite>::Kem as Kem>::Encap;
type SendCtx<CS> =
    hpke::SendCtx<<CS as CipherSuite>::Kem, <CS as CipherSuite>::Kdf, <CS as CipherSuite>::Aead>;
type RecvCtx<CS> =
    hpke::RecvCtx<<CS as CipherSuite>::Kem, <CS as CipherSuite>::Kdf, <CS as CipherSuite>::Aead>;

/// Augments `info` with [`CipherSuite::OIDS`].
///
/// ```text
/// info = info || oids
/// ```
///
/// where `oids` each OID encoded with `encode_string`,
/// concatenated.
#[inline(always)]
fn wrap_info<'a, CS>(info: impl IntoIterator<Item = &'a [u8]>) -> impl IntoIterator<Item = &'a [u8]>
where
    CS: CipherSuite,
{
    info.into_iter().chain(
        // `map(|v| v)` converts the `'static` lifetime to `'a`.
        #[allow(clippy::map_identity)]
        CS::OIDS.encode().into_iter().map(|v| v),
    )
}

/// Same as [`setup_send`][hpe::Hpke::setup_send], but augments
/// `info` with [`CipherSuite::OIDS`].
#[allow(clippy::type_complexity)]
pub(crate) fn setup_send<'a, CS, R>(
    rng: R,
    mode: Mode<'_, &DecapKey<CS>>,
    pkR: &EncapKey<CS>,
    info: impl IntoIterator<Item = &'a [u8]>,
) -> Result<(Encap<CS>, SendCtx<CS>), HpkeError>
where
    CS: CipherSuite,
    R: Csprng,
{
    Hpke::<CS>::setup_send(rng, mode, pkR, wrap_info::<CS>(info))
}

/// Same as
/// [`setup_send_deterministically`][hpe::Hpke::setup_send_deterministically],
/// but augments `info` with [`CipherSuite::OIDS`].
#[cfg(feature = "afc")]
#[allow(clippy::type_complexity)]
pub(crate) fn setup_send_deterministically<'a, CS>(
    mode: Mode<'_, &DecapKey<CS>>,
    pkR: &EncapKey<CS>,
    info: impl IntoIterator<Item = &'a [u8]>,
    skE: DecapKey<CS>,
) -> Result<(Encap<CS>, SendCtx<CS>), HpkeError>
where
    CS: CipherSuite,
{
    Hpke::<CS>::setup_send_deterministically(mode, pkR, wrap_info::<CS>(info), skE)
}

/// Same as [`setup_recv`][hpe::Hpke::setup_recv], but augments
/// `info` with [`CipherSuite::OIDS`].
pub(crate) fn setup_recv<'a, CS>(
    mode: Mode<'_, &EncapKey<CS>>,
    enc: &Encap<CS>,
    skR: &DecapKey<CS>,
    info: impl IntoIterator<Item = &'a [u8]>,
) -> Result<RecvCtx<CS>, HpkeError>
where
    CS: CipherSuite,
{
    Hpke::<CS>::setup_recv(mode, enc, skR, wrap_info::<CS>(info))
}
