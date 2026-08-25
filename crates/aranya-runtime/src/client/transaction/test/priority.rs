//! Priority derivation tests.
//!
//! Priorities never travel between peers: [`Command`] has no priority
//! accessor, so a command reconstructed from sync metadata cannot even
//! claim one. At ingest the runtime assigns merge and init priorities
//! structurally, and takes evaluated commands' priorities from the policy
//! (which derives them from the id-covered command body). These tests
//! ingest wire-shaped commands and check the stored priorities against an
//! independent derivation, plus that two peers ingesting the same commands
//! converge.

use std::collections::HashSet;
use std::vec::Vec;

use test_log::test;

use super::*;
use crate::{Location, storage::LocatedAddress};

/// A wire-shaped command: identity, structure, and payload only — exactly
/// what `SyncCommand` gives a receiving peer. There is nowhere to smuggle a
/// priority.
#[derive(Clone)]
struct PCmd {
    id: CmdId,
    prior: Prior<Address>,
    data: Box<str>,
    is_init: bool,
}

impl Command for PCmd {
    fn id(&self) -> CmdId {
        self.id
    }
    fn parent(&self) -> Prior<Address> {
        self.prior
    }
    fn policy(&self) -> Option<&[u8]> {
        if self.is_init { Some(b"") } else { None }
    }
    fn bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
}

fn addr(id: CmdId, mc: u64) -> Address {
    Address {
        id,
        max_cut: MaxCut::new(mc),
    }
}

type Prov = MemStorageProvider;

fn add(
    trx: &mut Transaction<Prov, SeqPolicyStore>,
    client: &mut ClientState<SeqPolicyStore, Prov>,
    buffers: &mut RuntimeBuffers<<Prov as StorageProvider>::Segment>,
    cmd: PCmd,
) -> Result<(), ClientError> {
    trx.add_commands(
        &[cmd],
        &mut client.provider,
        &mut client.policy_store,
        &mut NullSink,
        buffers,
        &MemSpill::new,
    )
    .map(|_| ())
}

/// Ingest a branchy DAG through the wire-shaped path and commit:
///
/// ```text
///        A (init)
///      / | | \
///     b  c p  q        (basics)
///     \ /   \ /
///      m     r         (merges)
/// ```
fn run() -> (ClientState<SeqPolicyStore, Prov>, GraphId) {
    let a: CmdId = mkid("a");
    let b: CmdId = mkid("b");
    let c: CmdId = mkid("c");
    let p: CmdId = mkid("p");
    let q: CmdId = mkid("qq"); // avoid data starting with 'q' (SeqPolicy skips those)
    let m: CmdId = mkid("m");
    let r: CmdId = mkid("r");

    let mut client = ClientState::new(SeqPolicyStore, Prov::default());
    let mut trx = Transaction::new(GraphId::transmute(a));
    let mut buffers = RuntimeBuffers::new();

    let mk = |id: CmdId, prior, data: &str, is_init| PCmd {
        id,
        prior,
        data: data.to_string().into_boxed_str(),
        is_init,
    };

    for cmd in [
        mk(a, Prior::None, "A", true),
        mk(b, Prior::Single(addr(a, 0)), "B", false),
        mk(c, Prior::Single(addr(a, 0)), "C", false),
        mk(m, Prior::Merge(addr(b, 1), addr(c, 1)), "M", false),
        mk(p, Prior::Single(addr(a, 0)), "P", false),
        mk(q, Prior::Single(addr(a, 0)), "Z", false),
        mk(r, Prior::Merge(addr(p, 1), addr(q, 1)), "R", false),
    ] {
        add(&mut trx, &mut client, &mut buffers, cmd).unwrap();
    }

    assert!(
        trx.commit(
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        )
        .unwrap()
    );

    (client, GraphId::transmute(a))
}

/// Every stored command's priority must equal the locally-derived value:
/// `Init` for the init command, `Merge` for merges, and the policy's
/// body-derived priority (SeqPolicy: last byte of the id) for basics.
#[test]
fn test_stored_priorities_are_derived_locally() {
    let (mut client, graph_id) = run();
    let g = client.provider.get_storage(graph_id).unwrap();

    // Walk every command in every segment reachable from the heads.
    let mut queue: Vec<Location> = g
        .get_heads()
        .unwrap()
        .iter()
        .map(LocatedAddress::location)
        .collect();
    let mut seen = HashSet::new();
    let mut checked = 0usize;
    while let Some(loc) = queue.pop() {
        if !seen.insert(loc.segment) {
            continue;
        }
        let segment = g.get_segment(loc).unwrap();
        queue.extend(segment.prior());

        let first = segment.first_location();
        let last = segment.head_location().unwrap();
        for mc in first.max_cut.get()..=last.max_cut.get() {
            let at = Location::new(first.segment, MaxCut::new(mc));
            let cmd = segment.get_command(at).unwrap();
            let stored = segment.get_priority(at).unwrap();
            let expected = match cmd.parent() {
                Prior::None => Priority::Init,
                Prior::Merge(..) => Priority::Merge,
                Prior::Single(_) => {
                    Priority::Basic(u32::from(*cmd.id().as_bytes().last().unwrap()))
                }
            };
            assert_eq!(
                stored,
                expected,
                "command {} stored priority must be derived locally",
                cmd.id()
            );
            checked = checked.checked_add(1).unwrap();
        }
    }
    // a, b, c, p, q, m, r, plus any collapse merges commit created.
    assert!(checked >= 7, "walked only {checked} commands");
}

/// Two peers ingesting the same wire-shaped commands (which carry no
/// priority) must derive identical priorities and converge to identical
/// facts and heads.
#[test]
fn test_peers_converge_without_wire_priorities() {
    let (mut client_a, graph_id) = run();
    let (mut client_b, _) = run();

    let ga = client_a.provider.get_storage(graph_id).unwrap();
    let gb = client_b.provider.get_storage(graph_id).unwrap();

    let heads_a: Vec<CmdId> = ga.get_heads().unwrap().iter().map(|h| h.id).collect();
    let heads_b: Vec<CmdId> = gb.get_heads().unwrap().iter().map(|h| h.id).collect();
    assert_eq!(heads_a, heads_b);

    let seq_a = lookup(ga, "seq").unwrap();
    let seq_b = lookup(gb, "seq").unwrap();
    assert_eq!(seq_a, seq_b, "peers must braid identically");
}
