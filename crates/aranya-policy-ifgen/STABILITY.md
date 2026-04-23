# Stability

`aranya-policy-ifgen`, `aranya-policy-ifgen-build`, and
`aranya-policy-ifgen-macro` are used together to create
a rust interface based on a policy. For stability,
these crates should be compatible if the major version
in the semver matches.

After updating the three crates, re-running the
generator against the same `policy.md` must produce a `policy.rs` that
compiles and that user code can still import from. 

## User-facing runtime surface

Items in `aranya_policy_ifgen` that user code (not just generated code)
is expected to read:

- Trait: `Actionable`.
- Re-exports: `VmAction`, `VmEffect`, `BaseId`, `Text`.
- Error types: `EffectsParseError`, `EffectVariantMismatch`.
- Macros: `text!`, `ident!`.

Changes to the names, signatures, or visibility of any of the above
are user-facing and require a matched major bump of all three crates.

## User-facing generator output shape

Names and shapes that the user's hand-written code imports from the
generated module:

- Per-action free functions and their argument types.
- Per-action request structs.
- Marker enums: `Persistent`, `Ephemeral`.
- Container enums: `PersistentAction`, `EphemeralAction`, `Effect`.
- `Actionable` impls on the action types.
- `TryFrom<VmEffect>` impls on the effect types.
- `.name()` on effects.
- Field names and visibility on generated structs.

Changes to any of the above are user-facing.

## Internal (allowed to change freely)

- Macro expansion details.
- Generator emission details that don't surface in generated names
  (e.g. attribute ordering, whitespace, import forms).
- Items reached only via a `__private` module.
- Transitive dep versions.

## Bump policy

User-facing changes require a matched major bump of all three crates.
Internal changes can be minor. 

