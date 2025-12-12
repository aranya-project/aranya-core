# Aranya Policy Tester

The Aranya Policy Tester is a tool to execute actions and commands in a
production-ish environment, and inspect/validate the emitted effects. It
should be able to load production policy and execute it in much the same
way it works in the [Aranya
daemon](https://github.com/aranya-project/aranya/).

## Architecture

The tool will use `aranya-runtime`'s `VmPolicy` with all production FFIs -
`envelope`, `perspective`, `device`, `crypto`, `idam`, and `afc`.
Custom FFIs are not supported, but may be offered later through
customizing the tester and recompiling.

The default RNG (`spideroak_crypto::default::Rng`) will be used.

### Test Library

This is probably a useful set of tools to have generally for integration
testing, so the non-CLI parts of this should be available as a library
for use in rust tests.

### Environment

Run state for the crypto engine, keystore, and graph storage will be
stored in a "working directory" configurable from the command-line. If
no working directory is specified, the current directory is used. All
data in the working directory will be reused if it is specified in a
later run. In the rest of this document, `<wd>` will be used to indicate
the working directory in paths.

### Crypto Engine

The "default" crypto engine (`aranya_crypto::default:DefaultEngine`)
will be used. The root key used by the engine will be randomly generated
and stored under `<wd>/crypto_root_key`.

### Key Store

The tool will use the `fs_keystore` implementation with data stored
in `<wd>/key_store`.

### Graph Storage

This will use a `LinearStorage` implementation with underlying file
manager using the `libc` implementation. Data will be stored in
`<wd>/graph`.

### FFI

`crypto`, `idam`, and `afc` FFIs depend on a key store, and they will
use the implementation specified above.

The `device` FFI needs a device ID specified. One will be randomly
generated and stored in `<wd>/device_id`.

## Input format

The input file will contain a sequence of items, which are either action
calls or raw command structs. The format of these are the same as in the
policy itself (or the `vm_action!()` macro). These calls and structs
will be compiled in the same way as the rest of the policy, which means
they can use policy-defined types and global values.

The input file will also have a section that defines values that will be
made available to policy execution as globals. This section will be able
to define `id` and `bytes` values that the policy cannot.

Optionally, there will be a validation section that contains a sequence
of effect structs that are expected to be produced.

## Operation

The tool will accept a policy file and a test file. First it will
compile the policy file into a VM. Then it will load the test file,
define any additional values specified in it, then execute its sequence
of actions and command structs.

If the validation section is present, the effects emitted by execution
will be checked against it. The tool will alert the user if there is a
deviation, and produce a diff between the expected and received effects.
If the validation section is absent, it will simply print out the
effects produced.