//! The probe policy: minimal production plumbing that records evaluation order.
//!
//! The harness runs graphs through the real [`ClientState`]/sync machinery,
//! which needs a [`Policy`]. This one does the least possible: every command's
//! rule appends the command's short ID to a `"seq"` fact, so the committed fact
//! *is* production's evaluation order, and priorities are uniform so the braid
//! order is decided purely by graph shape and ID ties (exactly like
//! production). Merges are never evaluated. Nothing here is specific to a
//! shape; [`super::harness`] drives it.
//!
//! [`ClientState`]: crate::ClientState

use alloc::boxed::Box;

use buggy::{BugExt as _, bug};

use crate::{
    Address, CmdId, Command, Prior, Priority,
    policy::{
        ActionPlacement, CommandPlacement, MergeIds, Policy, PolicyError, PolicyId, PolicyStore,
        Sink,
    },
    storage::{FactPerspective, Keys, Perspective},
    testing::{hash_for_testing_only, short_b58},
};

pub struct ProbePolicyStore;
pub struct ProbePolicy;

/// The id of the merge of `left < right`: a hash of the two parent ids.
/// Production validates every merge it ingests by recomputing its id through
/// [`Policy::merge`], so the harness derives its authored merge ids here too.
pub(crate) fn merge_id(left: CmdId, right: CmdId) -> CmdId {
    hash_for_testing_only([*left.as_array(), *right.as_array()].as_flattened())
}

/// A command with uniform priority: its rule appends the command's short ID
/// to the `"seq"` fact, so the committed fact is production's evaluation
/// order. Equal-priority ties break on ID, exactly like production.
pub struct ProbeCommand {
    id: CmdId,
    prior: Prior<Address>,
    data: Box<str>,
}

impl ProbeCommand {
    pub(crate) fn new(id: CmdId, prior: Prior<Address>) -> Self {
        Self {
            id,
            prior,
            data: short_b58(id).into_boxed_str(),
        }
    }
}

impl Command for ProbeCommand {
    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.prior
    }

    fn policy(&self) -> Option<&[u8]> {
        // The storage layer requires policy bytes on init commands, and the
        // sync wire drops a zero-length policy (reconstructing it as None),
        // which would fail init on a receiving peer — so use non-empty
        // bytes. The content is ignored; ProbePolicyStore keys on nothing.
        match self.prior {
            Prior::None => Some(b"probe"),
            _ => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

impl PolicyStore for ProbePolicyStore {
    type Policy = ProbePolicy;
    type Effect = ();

    fn add_policy(&mut self, _policy: &[u8]) -> Result<PolicyId, PolicyError> {
        Ok(PolicyId::default())
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&ProbePolicy)
    }
}

impl Policy for ProbePolicy {
    type Action<'a> = &'a str;
    type Effect = ();
    type Command<'a> = ProbeCommand;

    fn serial(&self) -> u32 {
        0
    }

    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl FactPerspective,
        _sink: &mut impl Sink<Self::Effect>,
        _placement: CommandPlacement,
    ) -> Result<Priority, PolicyError> {
        // Uniform priority: init is `Init`, everything else is `Basic(0)`, so
        // the braid order is decided purely by graph shape and ID ties.
        let priority = match command.parent() {
            Prior::None => Priority::Init,
            Prior::Single(_) => Priority::Basic(0),
            Prior::Merge(..) => bug!("merges must never be evaluated"),
        };
        let data = command.bytes();
        if let Some(seq) = facts
            .query("seq", &Keys::default())
            .assume("can query")?
            .as_deref()
        {
            facts
                .insert(
                    "seq".into(),
                    Keys::default(),
                    [seq, b":", data].concat().into(),
                )
                .expect("can insert");
        } else {
            facts
                .insert("seq".into(), Keys::default(), data.into())
                .expect("can insert");
        }
        Ok(priority)
    }

    fn call_action(
        &self,
        _action: Self::Action<'_>,
        _facts: &mut impl Perspective,
        _sink: &mut impl Sink<Self::Effect>,
        _placement: ActionPlacement,
    ) -> Result<(), PolicyError> {
        unimplemented!("the harness never calls actions")
    }

    fn merge<'a>(
        &self,
        _target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, PolicyError> {
        // Reached only through `validate_merge`: every merge in a program is
        // authored explicitly, and commit braids a multi-head set without
        // writing a merge, so production never adds a merge the oracle does
        // not know about.
        let (left, right): (Address, Address) = ids.into();
        Ok(ProbeCommand::new(
            merge_id(left.id, right.id),
            Prior::Merge(left, right),
        ))
    }
}
