//! VmPolicy implements a [Policy] that evaluates actions and commands via the [Policy
//! VM](../../policy_vm/index.html).
//!
//! ## Creating a `VmPolicy` instance
//!
//! To use `VmPolicy` in your [`PolicyStore`](super::PolicyStore), you need to provide a Policy VM
//! [`Machine`], a [`aranya_crypto::Engine`], and a Vec of Boxed FFI implementations. The Machine
//! will be created by either compiling a policy document (see
//! [`parse_policy_document()`](../../policy_lang/lang/fn.parse_policy_document.html) and
//! [`Compiler`](../../policy_compiler/struct.Compiler.html)), or loading a compiled policy
//! module (see [`Machine::from_module()`]). The crypto engine comes from your favorite
//! implementation
//! ([`DefaultEngine::from_entropy()`](aranya_crypto::default::DefaultEngine::from_entropy) is a
//! good choice for testing). The list of FFIs is a list of things that implement
//! [`FfiModule`](aranya_policy_vm::ffi::FfiModule), most likely via the [ffi attribute
//! macro](../../policy_vm/ffi/attr.ffi.html). The list of FFI modules _must_ be in the same
//! order as the FFI schemas given during VM construction.
//!
//! ```ignore
//! // Create a `Machine` by compiling policy from source.
//! let ast = parse_policy_document(policy_doc).unwrap();
//! let machine = Compiler::new(&ast)
//!     .ffi_modules(&[TestFfiEnvelope::SCHEMA])
//!     .compile()
//!     .unwrap();
//! // Create a `aranya_crypto::Engine` implementation
//! let (eng, _) = DefaultEngine::from_entropy(Rng);
//! // Create a list of FFI module implementations
//! let ffi_modules = vec![Box::from(TestFfiEnvelope {
//!     device: DeviceId::random(Rng),
//! })];
//! // And finally, create the VmPolicy
//! let policy = VmPolicy::new(machine, eng, ffi_modules).unwrap();
//! ```
//!
//! ## Actions and Effects
//!
//! The VM represents actions as a kind of function, which has a name and a list of
//! parameters. [`VmPolicy`] represents those actions as [`VmAction`]. Calling an action
//! via [`call_action()`](VmPolicy::call_action) requires you to give it an action of
//! that type. You can use the [`vm_action!()`](crate::vm_action) macro to create this
//! more comfortably.
//!
//! The VM represents effects as a named struct containing a set of fields. `VmPolicy`
//! represents this as [`VmEffect`]. Effects captured via [`Sink`]s will have this type.
//! You can use the [`vm_effect!()`](crate::vm_effect) macro to create effects.
//!
//! ## The "init" command and action
//!
//! To create a graph, there must be a command that is the ancestor of all commands in that
//! graph - the "init" command. In `VmPolicy`, that command is created via a special action
//! given as the second argument to
//! [`ClientState::new_graph()`](crate::ClientState::new_graph). The first command produced
//! by that action becomes the "init" command. It has basically all the same properties as
//! any other command, except it has no parent.
//!
//! So for this example policy:
//!
//! ```policy
//! command Init with BaseInit {
//!     fields {
//!         nonce int,
//!     }
//!     policy {
//!         finish {}
//!     }
//! }
//!
//! action[init] init(nonce int) {
//!     publish Init { nonce }
//! }
//! ```
//!
//! This is an example of initializing a graph with `new_graph()`:
//!
//! ```ignore
//! let policy_store = MyPolicyStore::new();
//! let provider = MyStorageProvider::new();
//! let mut cs = ClientState::new(policy_store, provider);
//! let mut sink = MySink::new();
//!
//! let graph_id = cs
//!     .new_graph(&[0u8], vm_action!(init(0)), &mut sink)
//!     .expect("could not create graph");
//! ```
//!
//! Because the ID of this initial command is also the ID of the resulting graph,
//! some data within the command must be present to ensure that multiple initial commands
//! create distinct IDs for each graph. If no other suitable data exists, it is good
//! practice to add a nonce field that is distinct for each graph.
//!
//! ## Priorities
//!
//! `VmPolicy` uses the policy language's attributes system to report command priorities to
//! the runtime. You can specify the priority of a command by adding the `priority`
//! attribute. It should be an `int` literal.
//!
//! ```policy
//! command Foo with Base {
//!     attributes {
//!         priority: 3
//!     }
//!     // ... fields, policy, etc.
//! }
//! ```
//!
//! ## Policy Interface Generator
//!
//! A more comfortable way to use `VmPolicy` is via the [Policy Interface
//! Generator](../../policy_ifgen/index.html). It creates a Rust interface for actions and
//! effects from a policy document.

mod error;
mod imp;
mod interface;
mod io;
mod priority;
mod protocol;
mod seal_open;

#[cfg(any(test, feature = "testing"))]
pub(crate) use self::io::ser_keys;
pub use self::{
    error::{AttributeError, VmPolicyError},
    imp::{FLAVORS, VmPolicy},
    interface::{VmAction, VmEffect, VmEffectData},
    io::{FfiCallable, VmFactCursor},
    seal_open::SealCtx,
};
