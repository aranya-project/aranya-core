use std::{
    fs,
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::{DeviceId, default::DefaultEngine, keystore::fs_keystore};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::{Compiler, validate::validate};
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::{
    Identifier, Machine, Value,
    ffi::{FfiModule as _, ModuleSchema},
};
use aranya_runtime::{FfiCallable, VmPolicy};

use crate::{PolicyRunnable, RunFile, SwitchableRng};

pub type CE = DefaultEngine<SwitchableRng>;
pub type KS = fs_keystore::Store;

pub struct RunSchedule {
    pub file_path: PathBuf,
    pub thunk_range: Range<usize>,
}

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

pub fn load_and_compile_policy(
    policy_path: impl AsRef<Path>,
    globals: impl IntoIterator<Item = (Identifier, Value)>,
    run_files: Vec<RunFile>,
    validator: bool,
) -> anyhow::Result<(Machine, Vec<RunSchedule>)> {
    // Load the policy data from file
    let mut policy_doc = fs::read_to_string(policy_path.as_ref())?;

    // Append generated policy thunks to the policy doc
    policy_doc.push_str("\n```policy\n");
    let mut thunk_counter = 0usize;
    let thunk_schedule = run_files
        .into_iter()
        .map(|run_file| {
            let thunk_start = thunk_counter;
            for policy_runnable in &run_file.do_things {
                // Each thunk calls another action or publishes a command,
                let action_body = match policy_runnable {
                    PolicyRunnable::Action(call) => format!("action {call}"),
                    PolicyRunnable::Command(cmd) => format!("publish {cmd}"),
                };
                policy_doc.push_str(&format!(
                    r#"
    action policy_runner_thunk_{thunk_counter}() {{
        {action_body}
    }}"#
                ));
                // and they are sequentially numbered.
                thunk_counter = thunk_counter
                    .checked_add(1)
                    .expect("should not overflow thunk counter");
            }
            // Each "schedule" captures a range of thunks for a given run file.
            RunSchedule {
                file_path: run_file.file_path,
                thunk_range: thunk_start..thunk_counter,
            }
        })
        .collect();
    policy_doc.push_str("\n```\n");

    // compile the policy.
    let ast = parse_policy_document(&policy_doc)
        .inspect_err(|e| println!("{e}"))
        .context("unable to parse policy document")?;
    let module = Compiler::new(&ast)
        .ffi_modules(&FFI_MODULES)
        .with_globals(globals)
        .compile()
        .context("should be able to compile policy")?;
    if validator && validate(&module) {
        return Err(anyhow::anyhow!("Could not validate module"));
    }
    let machine = Machine::from_module(module).context("should be able to create machine")?;

    Ok((machine, thunk_schedule))
}

pub fn create_vmpolicy(
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
    VmPolicy::new(machine, crypto_engine, ffis).context("unable to create `VmPolicy`")
}
