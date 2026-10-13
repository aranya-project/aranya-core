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
    policy::{ProbeCommand, ProbePolicyStore, merge_id},
    shapes::{ProgParents, chain_clients},
};
use crate::{
    Address, ClientState, CmdId, GraphId, MAX_SYNC_MESSAGE_SIZE, PeerCache, Prior, RuntimeBuffers,
    StorageProvider, SyncRequester,
    command::CommandExt as _,
    mem_spill,
    policy::NullSink,
    storage::{Query as _, Storage as _, linear::testing::MemStorageProvider},
    testing::{dsl::dispatch, hash_for_testing_only, short_b58},
};

/// One step of a schedule, performed by the named client.
#[derive(Debug, Clone)]
pub enum Step {
    /// `client` adds production graph command `command` (by structure index)
    /// in its own transaction and commits it.
    Author { client: usize, command: usize },
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

/// Deterministic, hash-distributed command ids. Init and single commands hash
/// their index, so they are unique within a program; a merge takes the id
/// production expects for its parent pair ([`merge_id`]), which is unique
/// because a pair merges at most once.
fn derive_id(index: usize, parents: ProgParents, ids: &[CmdId]) -> CmdId {
    match parents {
        ProgParents::Init | ProgParents::Single(_) => {
            hash_for_testing_only(&[u8::try_from(index).expect("command index fits in u8")])
        }
        ProgParents::Merge(j, k) => {
            let (a, b) = (ids[j], ids[k]);
            merge_id(a.min(b), a.max(b))
        }
    }
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
            let id = derive_id(i, parents, &ids);
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
            .add_commands(&mut trx, &mut NullSink, &commands, buffers, mem_spill)
            .expect("add_commands succeeds");
        to_c.commit(trx, &mut NullSink, buffers, mem_spill)
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

    for step in &program.steps {
        match *step {
            Step::Author { client, command } => {
                let cmd = graph.command(command);
                let mut trx = clients[client].transaction(gid);
                clients[client]
                    .add_commands(&mut trx, &mut NullSink, &[cmd], &mut buffers, mem_spill)
                    .expect("add_commands succeeds");
                clients[client]
                    .commit(trx, &mut NullSink, &mut buffers, mem_spill)
                    .expect("commit succeeds");
            }
            Step::Sync { from, to } => {
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

/// One canonical distributed case for a graph shape: each chain is authored
/// by its own client (via [`chain_clients`]), with a just-in-time sync
/// whenever a command's parent lives on another client (branch forks and
/// merges), then the convergence phase reconciles everyone. The graph shape
/// is the only variable.
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

    use aranya_crypto::dangerous::spideroak_crypto::csprng::rand::{
        RngExt as _, SeedableRng as _, rngs::SmallRng,
    };

    use super::{
        super::shapes::{enumerate_shapes, extensions},
        *,
    };

    /// Every client-holdable shape for n <= 8, built by a canonical
    /// distributed schedule ([`shape_only_program`]) and reconciled through
    /// the real sync protocol. Enumeration visits shapes smallest-first, so a
    /// failure here is already a minimal counterexample.
    #[test]
    fn differential_all_shapes() {
        let mut cases = 0usize;
        for structure in enumerate_shapes(8) {
            if let Err(report) = check_program(&shape_only_program(&structure)) {
                panic!("{report}");
            }
            cases = cases.checked_add(1).expect("case count fits");
        }
        // 1 + 1 + 2 + 5 + 13 + 41 + 151 + 635 shapes at n = 1..8.
        assert_eq!(cases, 849, "shape count changed; enumeration is broken");
    }

    /// A random client-holdable shape of `n` commands: a uniformly random walk
    /// through [`extensions`] from the lone init.
    fn random_structure(rng: &mut SmallRng, n: usize) -> Vec<ProgParents> {
        let mut structure = vec![ProgParents::Init];
        while structure.len() < n {
            let next = extensions(&structure);
            structure = next[rng.random_range(0..next.len())].clone();
        }
        structure
    }

    /// Run `iters` random shapes at n in `n_lo..=n_hi` through the same
    /// driver and oracle. Deterministic: iteration i uses seed
    /// `MASTER_SEED ^ i`, so any failure is reproducible and the sweeps nest
    /// (a longer run is a superset of a shorter one). A failure reports the
    /// seed and the structure.
    fn random_sweep(iters: usize, n_lo: usize, n_hi: usize) {
        const MASTER_SEED: u64 = 0x5EED_B4A1_D000_0001;
        for i in 0..iters {
            let seed = MASTER_SEED ^ u64::try_from(i).expect("iter fits");
            let mut rng = SmallRng::seed_from_u64(seed);
            let n = rng.random_range(n_lo..=n_hi);
            let structure = random_structure(&mut rng, n);
            if let Err(report) = check_program(&shape_only_program(&structure)) {
                panic!(
                    "random differential failure at iter {i} (seed {seed:#x}, n={n})\n\
                     structure: {structure:?}\n\n{report}"
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
