use anyhow::Context as _;
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::{DeviceId, keystore::fs_keystore};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_vm::{
    Machine,
    ffi::{FfiModule as _, ModuleSchema},
};
use aranya_runtime::{FfiCallable, VmPolicy};

type KS = fs_keystore::Store;

// NOTE(chip): It is important that these are the same FFIs in the same
// order as `create_vmpolicy()` below. Failure to uphold this invariant
// will cause VM execution to break in weird ways.
pub const FFI_MODULES: [ModuleSchema<'static>; 6] = [
    AfcFfi::<KS>::SCHEMA,
    CryptoFfi::<KS>::SCHEMA,
    DeviceFfi::SCHEMA,
    EnvelopeFfi::SCHEMA,
    IdamFfi::<KS>::SCHEMA,
    PerspectiveFfi::SCHEMA,
];

/// Takes an instantiated machine, crypto engine, keystore, and device
/// ID; and creates a [`VmPolicy`] instance.
pub fn create_vmpolicy<CE: aranya_crypto::Engine>(
    machine: Machine,
    crypto_engine: CE,
    keystore: KS,
    device_id: DeviceId,
) -> anyhow::Result<VmPolicy<CE>> {
    // NOTE(chip): It is important that these are the same FFIs in the same
    // order as `FFI_MODULES` above. Failure to uphold this invariant
    // will cause VM execution to break in weird ways.
    let ffis: Vec<Box<dyn FfiCallable<CE> + Send + 'static>> = vec![
        Box::from(AfcFfi::new(keystore.try_clone()?)),
        Box::from(CryptoFfi::new(keystore.try_clone()?)),
        Box::from(DeviceFfi::new(device_id)),
        Box::from(EnvelopeFfi),
        Box::from(IdamFfi::new(keystore)),
        Box::from(PerspectiveFfi),
    ];

    // create an instance of the policy VM.
    tracing::debug!("Creating Policy Runtime");
    VmPolicy::new(machine, crypto_engine, ffis).context("unable to create `VmPolicy`")
}
