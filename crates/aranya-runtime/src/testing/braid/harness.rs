//! Building a shape's production graph and diffing it against the oracle.
//!
//! Given a shape from [`super::shapes`], this is the whole differential loop:
//!
//! 1. [`shape_only_program`] turns the shape into a distributed schedule — one
//!    client per concurrent branch, syncing a command's parents just before it
//!    is authored. Graph shape is the only variable.
//! 2. [`run_program`] plays that schedule across real [`ClientState`] peers
//!    (using [`super::policy`]), reconciles them through the real sync protocol,
//!    and reads back each peer's committed `"seq"` fact — production's
//!    evaluation order.
//! 3. [`check_program`] diffs every peer's order against [`naive_braid`]. A
//!    mismatch implicates the production braid walk, its incremental
//!    composition, the sync protocol, or the braid rules the oracle encodes.
//!
//! [`ClientState`]: crate::ClientState

use alloc::{collections::BTreeMap, format, string::String, vec, vec::Vec};

use aranya_crypto::Rng;

use super::{
    naive::{NaiveCommand, NaivePriority, naive_braid, spec_violation},
    policy::{ProbeCommand, ProbePolicyStore},
    shapes::{ProgParents, chain_clients},
};
use crate::{
    Address, ClientState, CmdId, GraphId, MAX_SYNC_MESSAGE_SIZE, MemSpill, PeerCache, Prior,
    RuntimeBuffers, StorageProvider, SyncRequester, Transaction,
    command::CommandExt as _,
    policy::NullSink,
    storage::{Query as _, Storage as _, linear::testing::MemStorageProvider},
    testing::{dsl::dispatch, hash_for_testing_only, short_b58},
};

/// One step of a schedule, performed by the named client. A distributed case
/// spreads authorship across clients and interleaves `Sync` steps; the
/// single-client unit tests use `client` 0 and no `Sync`.
#[derive(Debug, Clone)]
pub enum Step {
    /// `client` hands production graph command `command` (by structure index).
    Author { client: usize, command: usize },
    /// `client` commits its open transaction.
    Commit { client: usize },
    /// `to` pulls everything available from `from` through the real sync
    /// protocol.
    Sync { from: usize, to: usize },
}

/// One test case: a graph shape (structure, indexed by command number), the
/// number of clients, and a schedule over it. The same graph must reach the
/// same final state on every client regardless of authorship or sync
/// interleaving.
#[derive(Debug, Clone)]
pub struct Program {
    pub structure: Vec<ProgParents>,
    pub clients: usize,
    pub steps: Vec<Step>,
}

/// The graph (oracle input) and each client's final committed seq fact.
pub struct RunResult {
    pub graph: GraphCommands,
    pub seqs: Vec<String>,
}

/// Deterministic, hash-distributed command IDs: unique within a program
/// because the command index is part of the preimage.
fn derive_id(index: usize, parents: ProgParents) -> CmdId {
    let mut buf: Vec<u8> = Vec::new();
    let idx = u8::try_from(index).expect("command index fits in u8");
    match parents {
        ProgParents::Init => buf.push(0),
        ProgParents::Single(j) => {
            buf.push(1);
            buf.push(u8::try_from(j).expect("parent index fits in u8"));
        }
        ProgParents::Merge(j, k) => {
            buf.push(2);
            buf.push(u8::try_from(j).expect("parent index fits in u8"));
            buf.push(u8::try_from(k).expect("parent index fits in u8"));
        }
    }
    buf.push(idx);
    hash_for_testing_only(&buf)
}

/// Render an oracle order as the same string the probe policy builds.
pub fn render_order(order: &[usize], ids: &[CmdId]) -> String {
    let parts: Vec<String> = order.iter().map(|&i| short_b58(ids[i])).collect();
    parts.join(":")
}

/// The command's prior, with merge parents id-sorted like production's
/// `MergeIds`.
fn prior_of(structure: &[ProgParents], addrs: &[Address], i: usize) -> Prior<Address> {
    match structure[i] {
        ProgParents::Init => Prior::None,
        ProgParents::Single(j) => Prior::Single(addrs[j]),
        ProgParents::Merge(j, k) => {
            let (a, b) = (addrs[j], addrs[k]);
            let (left, right) = if a.id < b.id { (a, b) } else { (b, a) };
            Prior::Merge(left, right)
        }
    }
}

/// The per-command data derived from a graph, independent of any schedule:
/// the same graph yields the same ids, addresses, and oracle input however
/// (and by whichever client) it is built, so every client constructs
/// byte-identical commands.
pub struct GraphCommands {
    pub structure: Vec<ProgParents>,
    pub ids: Vec<CmdId>,
    pub addrs: Vec<Address>,
    pub naive_input: Vec<NaiveCommand>,
}

impl GraphCommands {
    pub fn new(structure: &[ProgParents]) -> Self {
        let mut addrs: Vec<Address> = Vec::with_capacity(structure.len());
        let mut naive_input: Vec<NaiveCommand> = Vec::with_capacity(structure.len());
        let mut ids: Vec<CmdId> = Vec::with_capacity(structure.len());
        for (i, &parents) in structure.iter().enumerate() {
            let id = derive_id(i, parents);
            let (parent_indices, naive_priority) = match parents {
                ProgParents::Init => (vec![], NaivePriority::Init),
                ProgParents::Single(j) => (vec![j], NaivePriority::Basic(0)),
                ProgParents::Merge(j, k) => (vec![j, k], NaivePriority::Merge),
            };
            let cmd = ProbeCommand::new(id, prior_of(structure, &addrs, i));
            let max_cut = cmd.max_cut().expect("max_cut computable");
            addrs.push(Address { id, max_cut });
            ids.push(id);
            naive_input.push(NaiveCommand {
                id: *id.as_array(),
                priority: naive_priority,
                parents: parent_indices,
            });
        }
        Self {
            structure: structure.to_vec(),
            ids,
            addrs,
            naive_input,
        }
    }

    pub fn graph_id(&self) -> GraphId {
        GraphId::transmute(self.ids[0])
    }

    /// The production command for graph command `i`.
    pub fn command(&self, i: usize) -> ProbeCommand {
        ProbeCommand::new(self.ids[i], prior_of(&self.structure, &self.addrs, i))
    }
}

type Client = ClientState<ProbePolicyStore, MemStorageProvider>;
type Trx = Transaction<MemStorageProvider, ProbePolicyStore>;
type Buffers = RuntimeBuffers<<MemStorageProvider as StorageProvider>::Segment>;

/// Two disjoint `&mut Client` from the client slice, for the one sync
/// exchange that borrows both a requester's and a responder's storage.
fn two_mut(clients: &mut [Client], a: usize, b: usize) -> (&mut Client, &mut Client) {
    assert_ne!(a, b);
    if a < b {
        let (lo, hi) = clients.split_at_mut(b);
        (&mut lo[a], &mut hi[0])
    } else {
        let (lo, hi) = clients.split_at_mut(a);
        (&mut hi[0], &mut lo[b])
    }
}

/// `to` pulls everything available from `from` through the real sync
/// protocol, committing and advancing peer caches as the DSL does. One
/// exchange transfers up to `COMMAND_RESPONSE_MAX` commands (100 under default
/// features, so a whole test graph moves in one round); the loop drains any
/// remainder and stops when a response is empty or adds nothing new. The
/// latter exit is required: the peer cache ignores addresses already covered
/// by a cached head, so a response of only already-held commands leaves the
/// next request unchanged, and without it the loop would never end. Returns
/// the number of new commands added.
fn sync_pull(
    clients: &mut [Client],
    req_caches: &mut BTreeMap<(usize, usize), PeerCache>,
    resp_caches: &mut BTreeMap<(usize, usize), PeerCache>,
    buffers: &mut Buffers,
    gid: GraphId,
    from: usize,
    to: usize,
) -> usize {
    let mut total = 0usize;
    loop {
        let (from_c, to_c) = two_mut(clients, from, to);
        let mut requester = SyncRequester::new(gid, Rng);
        let mut request = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let req_cache = req_caches.get(&(to, from)).expect("requester cache exists");
        let (req_len, _sample) = requester
            .poll(
                &mut request,
                to_c.provider(),
                &req_cache.session_heads(),
                &mut buffers.traversal.primary,
            )
            .expect("requester poll succeeds");

        let mut response = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let resp_cache = resp_caches
            .get_mut(&(from, to))
            .expect("responder cache exists");
        let resp_len = dispatch(
            &request[..req_len],
            &mut response,
            from_c.provider(),
            resp_cache,
            &mut buffers.traversal,
        )
        .expect("dispatch succeeds");
        if resp_len == 0 {
            break;
        }

        let Some(commands) = requester
            .receive(&response[..resp_len])
            .expect("requester receive succeeds")
        else {
            break;
        };
        if commands.is_empty() {
            break;
        }

        let mut trx = to_c.transaction(gid);
        let received = to_c
            .add_commands(&mut trx, &mut NullSink, &commands, buffers, MemSpill::new)
            .expect("add_commands succeeds");
        to_c.commit(trx, &mut NullSink, buffers, MemSpill::new)
            .expect("commit succeeds");

        let addrs: Vec<Address> = commands.iter().filter_map(|c| c.address().ok()).collect();
        let req_cache = req_caches
            .get_mut(&(to, from))
            .expect("requester cache exists");
        to_c.update_heads(gid, addrs, req_cache, &mut buffers.traversal.primary)
            .expect("update_heads succeeds");

        total = total.checked_add(received).expect("received count fits");
        if received == 0 {
            break;
        }
    }
    total
}

/// The committed seq fact on `client`, or the empty string if none exists.
fn seq_of(client: &mut Client, gid: GraphId) -> String {
    let storage = client.provider().get_storage(gid).expect("storage exists");
    let cache = storage.fact_cache().expect("fact cache exists");
    match cache.query("seq", &[]).expect("can query") {
        Some(seq) => String::from_utf8(seq.as_ref().to_vec()).expect("seq is valid utf8"),
        None => String::new(),
    }
}

/// Execute a program: run its schedule across `clients` production clients
/// (one for a single-client case), then, if there is more than one, run
/// full-mesh sync rounds until quiescent. Returns the oracle input and each
/// client's final committed seq fact.
pub fn run_program(program: &Program) -> RunResult {
    let graph = GraphCommands::new(&program.structure);
    let gid = graph.graph_id();

    let mut clients: Vec<Client> = (0..program.clients)
        .map(|_| ClientState::new(ProbePolicyStore, MemStorageProvider::default()))
        .collect();
    let mut open: Vec<Option<Trx>> = (0..program.clients).map(|_| None).collect();
    let mut buffers = Buffers::new();

    let mut req_caches: BTreeMap<(usize, usize), PeerCache> = BTreeMap::new();
    let mut resp_caches: BTreeMap<(usize, usize), PeerCache> = BTreeMap::new();
    for a in 0..program.clients {
        for b in 0..program.clients {
            if a != b {
                req_caches.insert((a, b), PeerCache::new());
                resp_caches.insert((a, b), PeerCache::new());
            }
        }
    }

    let commit_open =
        |clients: &mut [Client], open: &mut [Option<Trx>], c: usize, b: &mut Buffers| {
            if let Some(trx) = open[c].take() {
                clients[c]
                    .commit(trx, &mut NullSink, b, MemSpill::new)
                    .expect("commit succeeds");
            }
        };

    for step in &program.steps {
        match *step {
            Step::Author { client, command } => {
                let cmd = graph.command(command);
                let trx = open[client].get_or_insert_with(|| clients[client].transaction(gid));
                clients[client]
                    .add_commands(trx, &mut NullSink, &[cmd], &mut buffers, MemSpill::new)
                    .expect("add_commands succeeds");
            }
            Step::Commit { client } => {
                commit_open(&mut clients, &mut open, client, &mut buffers);
            }
            Step::Sync { from, to } => {
                // The responder serves only committed state, so flush both
                // sides before the exchange.
                commit_open(&mut clients, &mut open, from, &mut buffers);
                commit_open(&mut clients, &mut open, to, &mut buffers);
                sync_pull(
                    &mut clients,
                    &mut req_caches,
                    &mut resp_caches,
                    &mut buffers,
                    gid,
                    from,
                    to,
                );
            }
        }
    }
    for c in 0..program.clients {
        commit_open(&mut clients, &mut open, c, &mut buffers);
    }

    if program.clients > 1 {
        // Full-mesh sync until a whole round transfers nothing. Bounded
        // because each transferring round strictly grows a receiver's
        // committed command set.
        loop {
            let mut moved = 0usize;
            for from in 0..program.clients {
                for to in 0..program.clients {
                    if from != to {
                        moved = moved.saturating_add(sync_pull(
                            &mut clients,
                            &mut req_caches,
                            &mut resp_caches,
                            &mut buffers,
                            gid,
                            from,
                            to,
                        ));
                    }
                }
            }
            if moved == 0 {
                break;
            }
        }
    }

    let seqs = clients.iter_mut().map(|c| seq_of(c, gid)).collect();
    RunResult { graph, seqs }
}

/// Run a program and diff every client's committed seq fact against the
/// schedule-blind oracle. `Err` is a full mismatch report: the schedule, the
/// per-command table, both order strings, and a graphviz dot rendering.
pub fn check_program(program: &Program) -> Result<(), String> {
    let result = run_program(program);
    let order = naive_braid(&result.graph.naive_input);
    if let Some(violation) = spec_violation(&result.graph.naive_input, &order) {
        return Err(format!("oracle output violates graph.md: {violation}"));
    }
    let expected = render_order(&order, &result.graph.ids);

    for (client, seq) in result.seqs.iter().enumerate() {
        if *seq == expected {
            continue;
        }
        let mut report = String::new();
        report.push_str(&format!(
            "braid mismatch on client {client}!\n\nschedule:\n"
        ));
        for step in &program.steps {
            report.push_str(&format!("  {step:?}\n"));
        }
        report.push_str("\ncommands (index: short-id priority parents):\n");
        for (i, (cmd, id)) in result
            .graph
            .naive_input
            .iter()
            .zip(&result.graph.ids)
            .enumerate()
        {
            report.push_str(&format!(
                "  {i}: {} {:?} parents={:?}\n",
                short_b58(*id),
                cmd.priority,
                cmd.parents,
            ));
        }
        report.push_str(&format!("\nnaive (expected):    {expected}\n"));
        report.push_str(&format!("client {client} (seq):     {seq}\n"));
        report.push_str("\ndigraph braid {\n");
        for (i, cmd) in result.graph.naive_input.iter().enumerate() {
            report.push_str(&format!(
                "  n{i} [label=\"{i}:{} {:?}\"];\n",
                short_b58(result.graph.ids[i]),
                cmd.priority
            ));
            for &p in &cmd.parents {
                report.push_str(&format!("  n{p} -> n{i};\n"));
            }
        }
        report.push_str("}\n");
        return Err(report);
    }
    Ok(())
}

/// One canonical distributed case for a graph shape: each concurrent branch
/// is authored by its own client (via [`chain_clients`]), with a
/// just-in-time sync whenever a command's parent lives on another client
/// (branch forks and merges), then the convergence phase reconciles
/// everyone. The graph shape is the only variable. The client count comes
/// from the path cover and may exceed [`super::shapes::PEERS`], which caps
/// only the shape's width.
pub fn shape_only_program(structure: &[ProgParents]) -> Program {
    let n = structure.len();
    let client_of = chain_clients(structure);
    let clients = client_of
        .iter()
        .copied()
        .max()
        .expect("non-empty graph")
        .checked_add(1)
        .expect("client count fits");

    let bit = |i: usize| {
        1u32.checked_shl(u32::try_from(i).expect("command index fits"))
            .expect("command index fits")
    };
    // Per client: bitmask of the commands it currently holds committed.
    let mut holds = vec![0u32; clients];
    let mut steps = Vec::new();
    for i in 0..n {
        let c = client_of[i];
        let parents: Vec<usize> = match structure[i] {
            ProgParents::Init => vec![],
            ProgParents::Single(j) => vec![j],
            ProgParents::Merge(j, k) => vec![j, k],
        };
        for p in parents {
            if holds[c] & bit(p) == 0 {
                let src = client_of[p];
                steps.push(Step::Sync { from: src, to: c });
                holds[c] |= holds[src];
            }
        }
        steps.push(Step::Author {
            client: c,
            command: i,
        });
        steps.push(Step::Commit { client: c });
        holds[c] |= bit(i);
    }

    Program {
        structure: structure.to_vec(),
        clients,
        steps,
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{
        super::shapes::{
            PEERS, anc_masks, cmd_bit, concurrent, enumerate_braidable, find_merge, graph_width,
            has_child,
        },
        *,
    };

    fn prog(parents: &[ProgParents]) -> Program {
        // A single-client program: author each command in creation order,
        // commit once at the end.
        let mut steps = Vec::new();
        for i in 0..parents.len() {
            steps.push(Step::Author {
                client: 0,
                command: i,
            });
        }
        steps.push(Step::Commit { client: 0 });
        Program {
            structure: parents.to_vec(),
            clients: 1,
            steps,
        }
    }

    fn seq(out: &RunResult) -> &str {
        &out.seqs[0]
    }

    #[test]
    fn driver_linear_chain_seq() {
        // Only one topological order, so seq must be creation order.
        let out = run_program(&prog(&[
            ProgParents::Init,
            ProgParents::Single(0),
            ProgParents::Single(1),
        ]));
        assert_eq!(out.graph.ids.len(), 3);
        assert_eq!(seq(&out), render_order(&[0, 1, 2], &out.graph.ids));
    }

    #[test]
    fn driver_multi_head_final_state() {
        // Program ends with two heads and no merge command; the final commit
        // braids all heads into the fact cache.
        let out = run_program(&prog(&[
            ProgParents::Init,
            ProgParents::Single(0),
            ProgParents::Single(0),
        ]));
        let order = naive_braid(&out.graph.naive_input);
        assert_eq!(seq(&out), render_order(&order, &out.graph.ids));
    }

    /// Every braidable prime block for n <= 8, built by a canonical distributed
    /// schedule ([`shape_only_program`]) and reconciled through the real sync
    /// protocol. Graph shape is the only variable, and every shape a client can
    /// hold is tested.
    #[test]
    fn differential_braidable_shapes() {
        let mut cases = 0usize;
        for structure in enumerate_braidable(8) {
            if let Err(report) = check_program(&shape_only_program(&structure)) {
                panic!("{report}");
            }
            cases = cases.checked_add(1).expect("case count fits");
        }
        // 1 + 1 + 4 + 13 + 53 blocks at n = 4..8.
        assert_eq!(
            cases, 72,
            "braidable shape count changed; enumeration is broken"
        );
    }

    /// A deterministic, seedable PRNG for the random sweep, built on the
    /// module's test hash in counter mode — no external crate, no wrapping
    /// arithmetic, and every draw is reproducible from the seed.
    struct Prng {
        seed: u64,
        counter: u64,
        buf: [u8; 32],
        /// Number of u32 words already drawn from `buf` (0..8); 8 forces a
        /// refill on the next draw.
        pos: usize,
    }

    impl Prng {
        fn new(seed: u64) -> Self {
            Self {
                seed,
                counter: 0,
                buf: [0; 32],
                pos: 8,
            }
        }

        fn refill(&mut self) {
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&self.seed.to_le_bytes());
            input[8..].copy_from_slice(&self.counter.to_le_bytes());
            self.buf = *hash_for_testing_only(&input).as_array();
            self.counter = self.counter.checked_add(1).expect("counter fits");
            self.pos = 0;
        }

        fn next_u32(&mut self) -> u32 {
            if self.pos >= 8 {
                self.refill();
            }
            let start = self.pos.checked_mul(4).expect("offset fits");
            let end = start.checked_add(4).expect("offset fits");
            let mut b = [0u8; 4];
            b.copy_from_slice(&self.buf[start..end]);
            self.pos = self.pos.checked_add(1).expect("pos fits");
            u32::from_le_bytes(b)
        }

        /// A value in `0..bound`. Modulo bias is negligible at our bounds.
        fn below(&mut self, bound: usize) -> usize {
            let bound = u32::try_from(bound).expect("bound fits in u32");
            assert!(bound > 0, "bound must be positive");
            let value = self
                .next_u32()
                .checked_rem(bound)
                .expect("bound is positive");
            usize::try_from(value).expect("value fits in usize")
        }
    }

    /// A random client-holdable parent structure of `n` commands: command 0 is
    /// init; each later command is a merge of a random concurrent, not-yet-merged
    /// pair with probability `merge_pct`/100 (when one exists) or else a single
    /// child, which extends the most recent command with probability
    /// `extend_pct`/100 (keeping graphs chain-like, as real command graphs are)
    /// and otherwise forks off a random earlier command.
    ///
    /// A proposed move is rejected and re-drawn whenever it would push the width
    /// past [`PEERS`], so every shape stays inside the reachable space that
    /// [`enumerate_braidable`] walks (a graph is never wider than the peer
    /// count). A single child of the most recent command — always a sink, so it
    /// never widens the graph — is the guaranteed-safe fallback if the random
    /// draws keep exceeding the cap.
    fn random_structure(
        prng: &mut Prng,
        n: usize,
        merge_pct: usize,
        extend_pct: usize,
    ) -> Vec<ProgParents> {
        const WIDTH_RETRIES: usize = 32;
        let mut structure = vec![ProgParents::Init];
        let mut anc: Vec<u64> = vec![cmd_bit(0)];
        while structure.len() < n {
            let i = structure.len();
            let bit_i = cmd_bit(i);
            let prev = i.checked_sub(1).expect("i >= 1");
            let fallback = (ProgParents::Single(prev), anc[prev] | bit_i);
            let mut chosen = None;
            for _ in 0..WIDTH_RETRIES {
                // Every concurrent pair not yet merged. A pair is merged at
                // most once, matching the enumerator (in production a merge's
                // id is the hash of its parents, so a pair yields one merge
                // command; the harness's `derive_id` differs but the rule is
                // kept).
                let mut pairs: Vec<(usize, usize)> = Vec::new();
                if prng.below(100) < merge_pct {
                    for k in 1..i {
                        for j in 0..k {
                            if concurrent(&anc, j, k) && find_merge(&structure, j, k).is_none() {
                                pairs.push((j, k));
                            }
                        }
                    }
                }
                let candidate = if pairs.is_empty() {
                    let j = if prng.below(100) < extend_pct {
                        prev
                    } else {
                        prng.below(i)
                    };
                    (ProgParents::Single(j), anc[j] | bit_i)
                } else {
                    let (j, k) = pairs[prng.below(pairs.len())];
                    (ProgParents::Merge(j, k), anc[j] | anc[k] | bit_i)
                };
                structure.push(candidate.0);
                let within_width = graph_width(&structure) <= PEERS;
                structure.pop();
                if within_width {
                    chosen = Some(candidate);
                    break;
                }
            }
            let (parents, anc_i) = chosen.unwrap_or(fallback);
            structure.push(parents);
            anc.push(anc_i);
        }
        structure
    }

    #[test]
    fn random_structures_are_client_holdable() {
        // The generator must only ever emit shapes a client can hold: parents
        // precede children, merges join concurrent unique pairs, and the width
        // never exceeds the peer count.
        let mut prng = Prng::new(0xC0FFEE);
        for _ in 0..500 {
            let n = 4usize.checked_add(prng.below(20)).expect("n fits");
            let structure = random_structure(&mut prng, n, 30, 70);
            assert_eq!(structure.len(), n);
            assert!(
                graph_width(&structure) <= PEERS,
                "width exceeded: {structure:?}"
            );
            let anc = anc_masks(&structure);
            let mut merges: Vec<(usize, usize)> = Vec::new();
            for (i, p) in structure.iter().enumerate() {
                match *p {
                    ProgParents::Init => assert_eq!(i, 0, "init only at index 0"),
                    ProgParents::Single(j) => assert!(j < i, "parent precedes child"),
                    ProgParents::Merge(j, k) => {
                        assert!(j < k && k < i, "parents precede child");
                        assert!(concurrent(&anc, j, k), "merge of non-concurrent pair");
                        assert!(!merges.contains(&(j, k)), "duplicate merge pair");
                        merges.push((j, k));
                    }
                }
            }
        }
    }

    fn mismatches(structure: &[ProgParents]) -> bool {
        check_program(&shape_only_program(structure)).is_err()
    }

    /// `structure` with childless command `c` removed and indices renumbered.
    /// `c` must be childless, so nothing references it.
    fn without_command(structure: &[ProgParents], c: usize) -> Vec<ProgParents> {
        let remap = |p: usize| {
            if p < c {
                p
            } else {
                p.checked_sub(1)
                    .expect("c is childless, so no parent equals c")
            }
        };
        let mut out = Vec::with_capacity(structure.len().saturating_sub(1));
        for (idx, p) in structure.iter().enumerate() {
            if idx == c {
                continue;
            }
            out.push(match *p {
                ProgParents::Init => ProgParents::Init,
                ProgParents::Single(j) => ProgParents::Single(remap(j)),
                ProgParents::Merge(j, k) => {
                    let (a, b) = (remap(j), remap(k));
                    ProgParents::Merge(a.min(b), a.max(b))
                }
            });
        }
        out
    }

    /// Splice out single-parent command `x`: re-point its children onto its
    /// parent `p`, then remove it (collapsing a chain link). Returns `None`
    /// for a merge command, or when re-pointing would give a merge two
    /// non-concurrent parents. Since removal only shrinks ancestry, a pair
    /// concurrent in the original stays concurrent, so the check is sound.
    fn splice(structure: &[ProgParents], x: usize) -> Option<Vec<ProgParents>> {
        let ProgParents::Single(p) = structure[x] else {
            return None;
        };
        let anc = anc_masks(structure);
        let mut repointed = structure.to_vec();
        for slot in &mut repointed {
            match *slot {
                ProgParents::Single(j) if j == x => *slot = ProgParents::Single(p),
                ProgParents::Merge(j, k) if j == x || k == x => {
                    let other = if j == x { k } else { j };
                    if !concurrent(&anc, p, other) {
                        return None;
                    }
                    *slot = ProgParents::Merge(p.min(other), p.max(other));
                }
                _ => {}
            }
        }
        // Re-pointing must not collapse two merges onto the same parent pair
        // (a pair yields exactly one merge command).
        let mut merges: Vec<(usize, usize)> = repointed
            .iter()
            .filter_map(|p| match *p {
                ProgParents::Merge(a, b) => Some((a, b)),
                _ => None,
            })
            .collect();
        merges.sort_unstable();
        if merges.windows(2).any(|w| w[0] == w[1]) {
            return None;
        }
        Some(without_command(&repointed, x))
    }

    /// Single-command reductions: drop a childless (non-init) command, splice
    /// out a single-parent command (collapsing a chain link), or demote a
    /// merge to either of its single parents. Every result is a strictly
    /// smaller valid structure.
    fn reductions(structure: &[ProgParents]) -> Vec<Vec<ProgParents>> {
        let n = structure.len();
        let mut out = Vec::new();
        for (c, &has) in has_child(structure).iter().enumerate().skip(1) {
            if !has {
                out.push(without_command(structure, c));
            }
        }
        for x in 1..n {
            if let Some(spliced) = splice(structure, x) {
                out.push(spliced);
            }
        }
        for (m, p) in structure.iter().enumerate() {
            if let ProgParents::Merge(j, k) = *p {
                let mut demote_j = structure.to_vec();
                demote_j[m] = ProgParents::Single(j);
                out.push(demote_j);
                let mut demote_k = structure.to_vec();
                demote_k[m] = ProgParents::Single(k);
                out.push(demote_k);
            }
        }
        out
    }

    /// Greedily reduce a structure to a minimal one still satisfying `keep`
    /// (for the sweep, "still mismatches"). Terminates: every accepted step
    /// strictly shrinks (fewer commands, or fewer merges). Parametric over the
    /// predicate so it is unit-testable without a real production mismatch.
    fn shrink(
        structure: &[ProgParents],
        keep: &impl Fn(&[ProgParents]) -> bool,
    ) -> Vec<ProgParents> {
        let mut cur = structure.to_vec();
        loop {
            let mut improved = false;
            for candidate in reductions(&cur) {
                if keep(&candidate) {
                    cur = candidate;
                    improved = true;
                    break;
                }
            }
            if !improved {
                break;
            }
        }
        cur
    }

    #[test]
    fn shrinker_reaches_minimal_witness() {
        // A merge buried under a chain prefix, with a trailing leaf.
        let structure = vec![
            ProgParents::Init,        // 0
            ProgParents::Single(0),   // 1  chain prefix
            ProgParents::Single(1),   // 2  chain prefix
            ProgParents::Single(2),   // 3  branch A
            ProgParents::Single(2),   // 4  branch B (concurrent with 3)
            ProgParents::Merge(3, 4), // 5
            ProgParents::Single(5),   // 6  trailing leaf
        ];
        let has_merge = |s: &[ProgParents]| s.iter().any(|p| matches!(p, ProgParents::Merge(_, _)));
        // The minimal graph containing a merge is a diamond: init, two
        // concurrent children, the merge — 4 commands. Reaching it requires
        // dropping the leaf and splicing away the chain prefix.
        let minimal = shrink(&structure, &has_merge);
        assert_eq!(minimal.len(), 4, "got {minimal:?}");
        assert!(matches!(minimal[3], ProgParents::Merge(1, 2)));
        // With only a size floor, it collapses to init plus one command.
        let two = shrink(&structure, &|s: &[ProgParents]| s.len() >= 2);
        assert_eq!(two.len(), 2);
    }

    /// Run `iters` random shapes at n in `n_lo..=n_hi` through the same
    /// driver and oracle. Deterministic: iteration i uses seed
    /// `MASTER_SEED ^ i`, so any failure is reproducible and the sweeps nest
    /// (a longer run is a superset of a shorter one). A failing case is shrunk
    /// to a minimal counterexample before it is reported.
    fn random_sweep(iters: usize, n_lo: usize, n_hi: usize) {
        const MASTER_SEED: u64 = 0x5EED_B4A1_D000_0001;
        const MERGE_PCT: usize = 30;
        const EXTEND_PCT: usize = 70;
        let span = n_hi
            .checked_sub(n_lo)
            .expect("n_hi >= n_lo")
            .checked_add(1)
            .expect("span fits");
        for i in 0..iters {
            let seed = MASTER_SEED ^ u64::try_from(i).expect("iter fits");
            let mut prng = Prng::new(seed);
            let n = n_lo.checked_add(prng.below(span)).expect("n fits");
            let structure = random_structure(&mut prng, n, MERGE_PCT, EXTEND_PCT);
            if mismatches(&structure) {
                let minimal = shrink(&structure, &|s: &[ProgParents]| mismatches(s));
                let report = check_program(&shape_only_program(&minimal))
                    .expect_err("shrunk case still mismatches");
                panic!(
                    "random differential failure at iter {i} (seed {seed:#x}, n={n}); \
                     shrank to {} commands:\n{report}",
                    minimal.len()
                );
            }
        }
    }

    /// Random client-holdable shapes at n = 10..=30 through the real sync
    /// protocol, reaching sizes exhaustive enumeration cannot. Deterministic
    /// (seeded), so this fixed sample runs by default; the large sweep is
    /// [`differential_random_shapes_deep`].
    #[test]
    fn differential_random_shapes() {
        random_sweep(150, 10, 30);
    }

    /// A deep random sweep for manual or scheduled runs; too slow (thousands of
    /// graphs through the real sync protocol) for the default suite.
    /// cargo test ... testing::braid -- --ignored
    #[test]
    #[ignore = "deep random sweep; run manually or on a schedule"]
    fn differential_random_shapes_deep() {
        random_sweep(5_000, 10, 30);
    }
}
