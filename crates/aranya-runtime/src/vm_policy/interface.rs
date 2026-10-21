use alloc::{borrow::Cow, vec::Vec};
use core::fmt;

use aranya_crypto::CmdId;
use aranya_policy_vm::{Identifier, KVPair, Value};

/// Creates a [`VmAction`].
///
/// This must be used directly to avoid lifetime issues, not assigned to a variable.
///
/// # Example
///
/// ```ignore
/// let x = 42;
/// let y = text!("asdf");
/// client.action(graph_id, sink, vm_action!(foobar(x, y)))
/// ```
#[macro_export]
macro_rules! vm_action {
    ($name:ident($($arg:expr),* $(,)?)) => {
        $crate::VmAction {
            name: ::aranya_policy_vm::ident!(stringify!($name)),
            args: [$(::aranya_policy_vm::Value::from($arg)),*].as_slice().into(),
        }
    };
}

/// Creates a [`VmEffectData`].
///
/// This is mostly useful for testing expected effects, and is expected to be compared
/// against a [`VmEffect`].
///
/// # Example
///
/// ```ignore
/// let val = 3;
/// sink.add_expectation(vm_effect!(StuffHappened { x: 1, y: val }));
///
/// client.action(graph_id, sink, vm_action!(create(val)))
/// ```
#[macro_export]
macro_rules! vm_effect {
    ($name:ident { $($field:ident : $val:expr),* $(,)? }) => {
        $crate::VmEffectData {
            name: ::aranya_policy_vm::ident!(stringify!($name)),
            fields: vec![$(
                ::aranya_policy_vm::KVPair::new(::aranya_policy_vm::ident!(stringify!($field)), $val.into())
            ),*],
        }
    };
}

/// [`VmPolicy`]'s actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmAction<'a> {
    /// The name of the action.
    pub name: Identifier,
    /// The arguments of the action.
    pub args: Cow<'a, [Value]>,
}

/// A partial version of [`VmEffect`] containing only the data. Created by
/// [`vm_effect!`] and used to compare only the name and fields against the full
/// `VmEffect`.
#[derive(Debug)]
pub struct VmEffectData {
    /// The name of the effect.
    pub name: Identifier,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
}

impl PartialEq<VmEffect> for VmEffectData {
    fn eq(&self, other: &VmEffect) -> bool {
        self.name == other.name && self.fields == other.fields
    }
}

impl PartialEq<VmEffectData> for VmEffect {
    fn eq(&self, other: &VmEffectData) -> bool {
        self.name == other.name && self.fields == other.fields
    }
}

/// [`VmPolicy`]'s effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmEffect {
    /// The name of the effect.
    pub name: Identifier,
    /// The fields of the effect.
    pub fields: Vec<KVPair>,
    /// The command ID that produced this effect
    pub command: CmdId,
    /// Was this produced from a recall block?
    pub recalled: bool,
}

impl fmt::Display for VmAction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_tuple(self.name.as_str());
        for arg in self.args.as_ref() {
            d.field(&DebugViaDisplay(arg));
        }
        d.finish()
    }
}

impl fmt::Display for VmEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct(self.name.as_str());
        for field in &self.fields {
            d.field(field.key().as_str(), &DebugViaDisplay(field.value()));
        }
        d.finish()
    }
}

/// Implements `Debug` via `T`'s `Display` impl.
struct DebugViaDisplay<T>(T);

impl<T: fmt::Display> fmt::Debug for DebugViaDisplay<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
