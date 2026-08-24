//! Priority-vs-structure validation tests.

use test_log::test;

use super::*;

/// A command whose `priority()` is an explicit field, decoupled from its
/// structure -- exactly how a command looks when reconstructed from wire
/// metadata (`SyncCommand`), where `Priority` is not covered by the id.
/// Used by the priority-validation tests below.
#[derive(Clone)]
struct PCmd {
    id: CmdId,
    prior: Prior<Address>,
    priority: Priority,
    data: Box<str>,
    is_init: bool,
}

impl Command for PCmd {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }
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

/// A merge command's [`Priority`] travels as unauthenticated sync metadata
/// (`SyncCommand::priority`, sourced from the wire `CommandMeta`) and is
/// used as the braid strand-ordering key. Merges are never evaluated by
/// policy, so the priority-shape check in `vm_policy` never runs for them.
/// Before the fix, a byzantine or buggy relay that altered one merge's
/// priority made downstream peers braid the SAME DAG in a DIFFERENT total
/// order: an identical head set (graph-equality passes) with divergent
/// facts. With `Priority::Finalize` (sorting last among concurrent
/// strands) the merge itself was emitted into the braid and crashed
/// evaluation.
///
/// The transaction must therefore reject, at ingest, any command whose
/// wire-supplied priority contradicts its `Prior::Merge` structure. Honest
/// peers always author merges with `Priority::Merge`, so this rejects only
/// invalid peer input.
#[test]
fn test_merge_priority_must_match_structure() {
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

    // Build a DAG where merge `m` (merge of two concurrent basics b,c) is
    // itself concurrent with another merge `r` (merge of p,q). `m`'s
    // subtree (b,c) is only reachable through `m`, so `m`'s strand
    // priority controls WHEN b,c enter the braid relative to p,q -- this
    // is the shape the pre-fix divergence reproduced on.
    //
    //        A (init)
    //      / | | \
    //     b  c p  q        (basics)
    //     \ /   \ /
    //      m     r         (merges)
    fn run(merge_m_priority: Priority) -> Result<(String, Vec<CmdId>), ClientError> {
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

        let mk = |id: CmdId, prior, priority, data: &str, is_init| PCmd {
            id,
            prior,
            priority,
            data: data.to_string().into_boxed_str(),
            is_init,
        };

        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(a, Prior::None, Priority::Init, "A", true),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                b,
                Prior::Single(addr(a, 0)),
                Priority::Basic(50),
                "B",
                false,
            ),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                c,
                Prior::Single(addr(a, 0)),
                Priority::Basic(60),
                "C",
                false,
            ),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                m,
                Prior::Merge(addr(b, 1), addr(c, 1)),
                merge_m_priority,
                "M",
                false,
            ),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                p,
                Prior::Single(addr(a, 0)),
                Priority::Basic(70),
                "P",
                false,
            ),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                q,
                Prior::Single(addr(a, 0)),
                Priority::Basic(90),
                "Z",
                false,
            ),
        )?;
        add(
            &mut trx,
            &mut client,
            &mut buffers,
            mk(
                r,
                Prior::Merge(addr(p, 1), addr(q, 1)),
                Priority::Merge,
                "R",
                false,
            ),
        )?;

        assert!(trx.commit(
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        )?);

        let g = client.provider.get_storage(GraphId::transmute(a)).unwrap();
        // Lazy merges keep the graph multi-head after commit; the head SET
        // (sorted by command id) is the graph-equality observable, and the
        // committed fact cache is the braided fact state across it.
        let heads: Vec<CmdId> = g.get_heads().unwrap().iter().map(|h| h.id).collect();
        let seq = lookup(g, "seq").unwrap();
        let seq = std::str::from_utf8(&seq).unwrap().to_string();
        Ok((seq, heads))
    }

    // Control: honest peers (merge `m` authored with Priority::Merge)
    // commit successfully and converge.
    let (honest_seq, honest_heads) = run(Priority::Merge).expect("honest peer must commit");
    let (honest_seq2, honest_heads2) = run(Priority::Merge).expect("honest peer must commit");
    assert_eq!(
        honest_seq, honest_seq2,
        "control: honest peers must converge"
    );
    assert_eq!(honest_heads, honest_heads2);

    // Byzantine relay: the same command `m` (same id, same Prior::Merge
    // structure) arrives with an altered priority. Every non-Merge value
    // must be rejected at ingest -- Basic(75) was the silent fact
    // divergence, Finalize the lone-strand crash, Init nonsensical.
    let m: CmdId = mkid("m");
    for bad in [Priority::Basic(75), Priority::Finalize, Priority::Init] {
        let err =
            run(bad.clone()).expect_err("merge with non-Merge wire priority must be rejected");
        assert!(
            matches!(err, ClientError::InvalidPriority(id) if id == m),
            "priority {bad:?}: expected InvalidPriority(m), got {err:?}"
        );
    }
}

/// Companion to [`test_merge_priority_must_match_structure`]: an init
/// command (`Prior::None`) whose wire-supplied priority is not
/// `Priority::Init` must be rejected when it initializes a graph.
#[test]
fn test_init_priority_must_match_structure() {
    let a: CmdId = mkid("a");
    let mut client = ClientState::new(SeqPolicyStore, MemStorageProvider::default());
    let mut trx = Transaction::new(GraphId::transmute(a));
    let mut buffers = RuntimeBuffers::new();

    let init = PCmd {
        id: a,
        prior: Prior::None,
        priority: Priority::Basic(0),
        data: "A".into(),
        is_init: true,
    };
    let err = trx
        .add_commands(
            &[init],
            &mut client.provider,
            &mut client.policy_store,
            &mut NullSink,
            &mut buffers,
            &MemSpill::new,
        )
        .expect_err("init with non-Init wire priority must be rejected");
    assert!(
        matches!(err, ClientError::InvalidPriority(id) if id == a),
        "{err:?}"
    );
}
