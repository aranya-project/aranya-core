use std::{
    cell::RefCell,
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Mutex,
};

use anyhow::Context as _;
use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::{DeviceId, default::DefaultEngine, id::Id, keystore::fs_keystore};
use aranya_crypto_ffi::Ffi as CryptoFfi;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_compiler::Compiler;
use aranya_policy_lang::lang::{parse_policy_document, parse_policy_str};
use aranya_policy_vm::{
    CommandContext, ExitReason, Identifier, Label, LabelType, Machine, PolicyContext, Value,
    ffi::{FfiModule as _, ModuleSchema},
    ident,
};
use aranya_runtime::{FfiCallable, VmPolicy};
use tracing::error;

use crate::{
    PolicyRunnable, RunFile,
    io::{PreambleIO, testing_ffi::TestingFfi},
};

type CE = DefaultEngine;
type KS = fs_keystore::Store;

pub struct RunSchedule {
    pub file_path: PathBuf,
    pub thunk_ids: Vec<usize>,
}

pub const FFI_MODULES: [ModuleSchema<'static>; 6] = [
    AfcFfi::<KS>::SCHEMA,
    CryptoFfi::<KS>::SCHEMA,
    DeviceFfi::SCHEMA,
    EnvelopeFfi::SCHEMA,
    IdamFfi::<KS>::SCHEMA,
    PerspectiveFfi::SCHEMA,
];

pub fn load_policy(
    policy_path: impl AsRef<Path>,
    globals: impl IntoIterator<Item = (Identifier, Value)>,
    runnables: Vec<RunFile>,
) -> anyhow::Result<(Machine, Vec<RunSchedule>)> {
    // Load the policy data from file
    let policy_file = OpenOptions::new().read(true).open(policy_path.as_ref())?;
    let mut policy_doc = std::io::read_to_string(policy_file)?;

    policy_doc.push_str("\n```policy\n");
    let mut c = 0usize;
    let mut thunk_schedule = Vec::new();
    for f in runnables {
        let mut thunk_ids = Vec::new();
        for r in &f.do_things {
            let (verb, object) = match r {
                PolicyRunnable::Action(s) => ("action", s),
                PolicyRunnable::Command(s) => ("publish", s),
            };
            policy_doc.push_str(&format!(
                r#"
    action policy_runner_thunk_{c}() {{
        {verb} {object}
    }}
    "#
            ));
            thunk_ids.push(c);
            c = c.checked_add(1).expect("absurd number of runnables");
        }
        thunk_schedule.push(RunSchedule {
            file_path: f.file_path,
            thunk_ids,
        });
    }
    policy_doc.push_str("\n```\n");

    // compile the policy.
    let ast = parse_policy_document(&policy_doc).context("unable to parse policy document")?;
    let module = Compiler::new(&ast)
        .ffi_modules(&FFI_MODULES)
        .with_globals(globals)
        .compile()
        .context("should be able to compile policy")?;
    let machine = Machine::from_module(module).context("should be able to create machine")?;

    Ok((machine, thunk_schedule))
}

pub fn create_vmpolicy(
    machine: Machine,
    crypto_engine: CE,
    keystore: KS,
    device_id: DeviceId,
) -> anyhow::Result<VmPolicy<DefaultEngine>> {
    // select which FFI modules to use.
    let ffis: Vec<Box<dyn FfiCallable<DefaultEngine> + Send + 'static>> = vec![
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

pub fn get_runfile_preamble_values(
    rf: &RunFile,
    crypto_engine: &Mutex<CE>,
    keystore: KS,
) -> anyhow::Result<Vec<(Identifier, Value)>> {
    let func_str = format!(
        "use testing\nfunction preamble() bool {{\n{}\n  return false\n}}",
        rf.preamble
    );
    let ast = parse_policy_str(&func_str, aranya_policy_lang::ast::Version::V2)?;
    let module = Compiler::new(&ast)
        .ffi_modules(&[TestingFfi::<KS>::SCHEMA])
        .compile()?;

    let machine = Machine::from_module(module)?;
    let io = RefCell::new(PreambleIO::new(crypto_engine, keystore));
    let mut rs = machine.create_run_state(
        &io,
        CommandContext::Policy(PolicyContext {
            name: ident!("preamble"),
            id: Id::default(),
            author: Id::default(),
            version: Id::default(),
        }),
    );
    rs.set_pc_by_label(&Label::new(ident!("preamble"), LabelType::Function))?;
    match rs.run() {
        Ok(exit_reason) => assert_eq!(exit_reason, ExitReason::Normal),
        Err(err) => {
            error!("Errored {err}");
            return Err(anyhow::anyhow!("Errored {err}"));
        }
    }
    Ok(rs
        .scope()
        .locals()
        .map(|(n, v)| (n.clone(), v.clone()))
        .collect())
}
