//! Aranya's daemon policy, ported to the current syntax as a test
//! artifact. `data/daemon-policy.md` says what the port changed, and
//! `data/port-daemon-policy.py` regenerates it.
//!
//! The warnings on the policy are kept in a snapshot. None of them is a
//! real bug: the design doc's section on the daemon policy says why
//! each is raised. Injecting a bug that one of the policy's guards
//! prevents must add a warning.

use std::ops::Range;

use aranya_afc_util::Ffi as AfcFfi;
use aranya_crypto::keystore::memstore::MemStore;
use aranya_device_ffi::FfiDevice as DeviceFfi;
use aranya_envelope_ffi::Ffi as EnvelopeFfi;
use aranya_idam_ffi::Ffi as IdamFfi;
use aranya_perspective_ffi::FfiPerspective as PerspectiveFfi;
use aranya_policy_ast::Span;
use aranya_policy_lang::lang::parse_policy_document;
use aranya_policy_vm::ffi::{FfiModule as _, ModuleSchema};
use rstest::rstest;

use super::ObligationWarning;
use crate::Compiler;

const POLICY: &str = include_str!("data/daemon-policy.md");

/// The daemon's FFI modules, as the policy runner lists them.
const FFI_MODULES: [ModuleSchema<'static>; 5] = [
    AfcFfi::<MemStore>::SCHEMA,
    DeviceFfi::SCHEMA,
    EnvelopeFfi::SCHEMA,
    IdamFfi::<MemStore>::SCHEMA,
    PerspectiveFfi::SCHEMA,
];

/// Compile a policy document, in debug mode since the port's
/// `test_fail()` needs it, and return its source and warnings.
#[track_caller]
fn warnings_in(text: &str) -> (String, Vec<ObligationWarning>) {
    let ast = parse_policy_document(text).unwrap_or_else(|e| panic!("{e}"));
    let (_module, warnings) = Compiler::new(&ast)
        .ffi_modules(&FFI_MODULES)
        .debug(true)
        .analyze_obligations(true)
        .compile_with_diagnostics()
        .unwrap_or_else(|e| panic!("{e}"));
    (ast.text, warnings)
}

/// Each warning's line and message, then its notes', indented: enough
/// to see what changed and where to look.
fn summary(text: &str, warnings: &[ObligationWarning]) -> String {
    let line = |span: Span| {
        let range: Range<usize> = span.into();
        let before = text.get(..range.start).unwrap_or_default();
        before.matches('\n').count().saturating_add(1)
    };
    let mut lines = Vec::new();
    for w in warnings {
        lines.push(format!("{}: {}", line(w.span), w.message));
        for (span, note) in &w.notes {
            lines.push(format!("    {}: {note}", line(*span)));
        }
    }
    lines.join("\n")
}

#[test]
fn daemon_policy_warnings() {
    let (text, warnings) = warnings_in(POLICY);
    insta::with_settings!({ prepend_module_to_snapshot => false, snapshot_path => "data" }, {
        insta::assert_snapshot!("daemon-policy-warnings", summary(&text, &warnings));
    });
}

/// Each case injects a bug the policy's guards prevent, by dropping a
/// guard, pointing it at the wrong key, or inverting a branch, and the
/// analysis must then warn at the mutation that guard protected.
#[rstest]
#[case::perm_added_twice(
    "check !role_has_perm(this.role_id, this.perm) else test_fail()",
    "",
    "cannot prove `RoleHasPerm[role_id: this.role_id, perm: this.perm]` does not exist before `create`"
)]
#[case::perm_removed_unchecked(
    "check role_has_perm(this.role_id, this.perm) else test_fail()",
    "",
    "cannot prove `RoleHasPerm[role_id: this.role_id, perm: this.perm]` exists before `delete`"
)]
#[case::default_role_seeded_twice(
    "check !exists DefaultRoleSeeded[name: this.name] else test_fail()",
    "",
    "cannot prove `DefaultRoleSeeded[name: this.name]` does not exist before `create`"
)]
#[case::role_deleted_by_wrong_key(
    "delete Role[role_id: this.role_id]",
    "delete Role[role_id: author.device_id]",
    "cannot prove `Role[role_id: author.device_id]` exists before `delete`"
)]
#[case::role_assigned_twice(
    "check !exists AssignedRole[device_id: this.device_id] else test_fail()",
    "",
    "cannot prove `AssignedRole[device_id: device_id]` does not exist before `create`"
)]
#[case::role_index_not_clear(
    "check !exists RoleAssignmentIndex[
            role_id: this.role_id,
            device_id: this.device_id,
        ] else test_fail()",
    "",
    "cannot prove `RoleAssignmentIndex[role_id: role_id, device_id: device_id]` does not exist before `create`"
)]
#[case::revoked_role_index_unchecked(
    "check exists RoleAssignmentIndex[
            role_id: this.role_id,
            device_id: this.device_id,
        ] else test_fail()",
    "",
    "cannot prove `RoleAssignmentIndex[role_id: role_id, device_id: device_id]` exists before `delete`"
)]
#[case::revoked_role_read_by_wrong_key(
    "let assignment = query AssignedRole[device_id: this.device_id] or test_fail()",
    "let assignment = query AssignedRole[device_id: author.device_id] or test_fail()",
    "cannot prove `AssignedRole[device_id: device_id]` exists before `delete`"
)]
#[case::changed_role_index_unchecked(
    "check exists RoleAssignmentIndex[
            role_id: this.old_role_id,
            device_id: this.device_id,
        ] else test_fail()",
    "",
    "cannot prove `RoleAssignmentIndex[role_id: old_role_id, device_id: device_id]` exists before `delete`"
)]
#[case::team_started_twice(
    "create TeamStart[]=>{team_id: team_id}",
    "create TeamStart[]=>{team_id: team_id}
            create TeamStart[]=>{team_id: team_id}",
    "`TeamStart[]` is manipulated more than once in this finish block"
)]
#[case::device_added_twice(
    "check !exists Device[device_id: device_id] else test_fail()",
    "",
    "cannot prove `Device[device_id: device_id]` does not exist before `create`"
)]
#[case::device_generation_branch_inverted(
    "if existing_gen is None {",
    "if existing_gen is Some {",
    "cannot prove `DeviceGeneration[device_id: device_id]` does not exist before `create`"
)]
#[case::device_removed_unchecked(
    "check exists Device[device_id: this.device_id] else test_fail()

        // Author must have permission to remove a device",
    "// Author must have permission to remove a device",
    "cannot prove `Device[device_id: device_id]` exists before `delete`"
)]
#[case::device_generation_read_by_wrong_key(
    "let device_gen = query DeviceGeneration[device_id: this.device_id] or test_fail()",
    "let device_gen = query DeviceGeneration[device_id: author.device_id] or test_fail()",
    "cannot prove `DeviceGeneration[device_id: this.device_id]` exists before `update`"
)]
#[case::device_generation_stale_value(
    "{generation: device_gen.generation} to {
                    generation: next_gen
                }
                delete_role_assignment",
    "{generation: 0} to {
                    generation: next_gen
                }
                delete_role_assignment",
    "cannot prove the stated values of `DeviceGeneration[device_id: this.device_id]` match the stored fact before `update`"
)]
#[case::removed_device_role_index_unchecked(
    "check exists RoleAssignmentIndex[
                role_id: role_id,
                device_id: this.device_id,
            ] else test_fail()",
    "",
    "cannot prove `RoleAssignmentIndex[role_id: role_id, device_id: device_id]` exists before `delete`"
)]
#[case::label_assignment_branch_inverted(
    "if existing_assignment is Some {",
    "if existing_assignment is None {",
    "cannot prove `LabelAssignedToDevice[label_id: this.label_id, device_id: this.device_id]` does not exist before `create`"
)]
#[case::label_assignment_stale_value(
    "op: assignment.op,",
    "op: this.op,",
    "cannot prove the stated values of `LabelAssignedToDevice[label_id: this.label_id, device_id: this.device_id]` match the stored fact before `update`"
)]
#[case::revoked_label_read_by_wrong_key(
    "let assignment = query LabelAssignedToDevice[
            label_id: this.label_id,
            device_id: this.device_id,
        ] or test_fail()",
    "let assignment = query LabelAssignedToDevice[
            label_id: this.label_id,
            device_id: author.device_id,
        ] or test_fail()",
    "cannot prove `LabelAssignedToDevice[label_id: this.label_id, device_id: this.device_id]` exists before `delete`"
)]
fn injected_bug_warns(#[case] guard: &str, #[case] bug: &str, #[case] expected: &str) {
    assert_eq!(
        POLICY.matches(guard).count(),
        1,
        "the guard should appear once"
    );
    let count = |text: &str| {
        let (_, warnings) = warnings_in(text);
        warnings.iter().filter(|w| w.message == expected).count()
    };
    assert_eq!(count(POLICY), 0, "the policy as written should not warn");
    assert!(
        count(&POLICY.replacen(guard, bug, 1)) > 0,
        "the injected bug should warn"
    );
}
