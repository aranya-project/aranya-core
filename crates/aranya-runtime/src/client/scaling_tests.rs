//! Tests demonstrating super-linear storage access in the runtime.
//!
//! These count the serialized bytes that linear storage decodes (via
//! [`FetchStats`]) rather than measuring wall-clock time, so they are
//! deterministic. Each test runs the same workload at doubling sizes of `n`
//! and prints a table of how much the decoded byte count grows per
//! doubling:
//!
//! - work independent of `n` stays ~x1,
//! - linear work grows ~x2,
//! - quadratic work grows ~x4.
//!
//! They are `#[ignore]`d because they fail against the current storage
//! implementation. Run them with `--nocapture` to see the tables:
//!
//! ```text
//! cargo test -p aranya-runtime --lib scaling_tests -- --ignored --nocapture
//! ```

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_precision_loss,
    reason = "test-only byte counts, reported as approximate ratios"
)]

use buggy::BugExt as _;

use super::*;
use crate::{
    Address, ClientState, GraphId, Keys, MaxCut, MergeIds, Perspective, Policy, PolicyId, Prior,
    Priority, Query as _, mem_spill,
    policy::{ActionPlacement, CommandPlacement},
    storage::linear::testing::{FetchStats, MemStorageProvider},
    testing::hash_for_testing_only,
};

/// Command data prefix for commands that insert and query a fact.
const FACT: u8 = b'F';
/// Command data prefix for commands that touch no facts.
const QUIET: u8 = b'q';

/// Fact name used by [`ScalePolicy`].
const FACT_NAME: &str = "f";

/// Key that is never inserted. Looking it up misses every layer of the fact
/// index chain, which is the common case for policy `!exists` checks.
fn absent_key() -> Keys {
    Keys::from_iter([&[0u8; 32][..]])
}

struct ScalePolicyStore;

/// For [`FACT`] commands: queries [`absent_key`] and inserts one new fact
/// keyed by the command ID. For [`QUIET`] commands: does nothing.
struct ScalePolicy;

struct ScaleCommand {
    id: CmdId,
    prior: Prior<Address>,
    data: Box<[u8]>,
}

impl ScaleCommand {
    fn new(n: u64, prior: Prior<Address>, kind: u8, len: usize) -> Self {
        let mut data = vec![kind; len.max(1)].into_boxed_slice();
        data[0] = kind;
        Self {
            id: cmd_id(n),
            prior,
            data,
        }
    }
}

fn cmd_id(n: u64) -> CmdId {
    hash_for_testing_only(&n.to_le_bytes())
}

impl Command for ScaleCommand {
    fn id(&self) -> CmdId {
        self.id
    }

    fn parent(&self) -> Prior<Address> {
        self.prior
    }

    fn policy(&self) -> Option<&[u8]> {
        match self.prior {
            Prior::None => Some(b""),
            _ => None,
        }
    }

    fn bytes(&self) -> &[u8] {
        &self.data
    }
}

impl PolicyStore for ScalePolicyStore {
    type Policy = ScalePolicy;
    type Effect = ();

    fn add_policy(&mut self, _policy: &[u8]) -> Result<PolicyId, PolicyError> {
        Ok(PolicyId::new(0))
    }

    fn get_policy(&self, _id: PolicyId) -> Result<&Self::Policy, PolicyError> {
        Ok(&ScalePolicy)
    }

    fn seal_ctx(&self, _id: PolicyId) -> Result<&<Self::Policy as Policy>::SealCtx, PolicyError> {
        Ok(&())
    }
}

impl Policy for ScalePolicy {
    type Action<'a> = ();
    type SealCtx = ();
    type Effect = ();
    type Command<'a> = ScaleCommand;

    fn serial(&self) -> u32 {
        0
    }

    fn call_rule(
        &self,
        command: &impl Command,
        facts: &mut impl crate::FactPerspective,
        _sink: &mut impl Sink<Self::Effect>,
        _placement: CommandPlacement,
    ) -> Result<Priority, PolicyError> {
        if command.bytes().first() == Some(&FACT) {
            facts.query(FACT_NAME, &absent_key()).assume("can query")?;
            facts
                .insert(
                    FACT_NAME.into(),
                    Keys::from_iter([command.id().as_bytes()]),
                    Box::from(&b"value"[..]),
                )
                .assume("can insert")?;
        }
        Ok(match command.parent() {
            Prior::None => Priority::Init,
            _ => Priority::Basic(u32::from(command.id().as_bytes()[31])),
        })
    }

    fn call_action(
        &self,
        _action: Self::Action<'_>,
        _facts: &mut impl Perspective,
        _sink: &mut impl Sink<Self::Effect>,
        _placement: ActionPlacement,
        _seal_ctx: &(),
    ) -> Result<(), PolicyError> {
        unimplemented!()
    }

    fn merge<'a>(
        &self,
        _target: &'a mut [u8],
        ids: MergeIds,
    ) -> Result<Self::Command<'a>, PolicyError> {
        let (left, right): (Address, Address) = ids.into();
        let parents = [*left.id.as_array(), *right.id.as_array()];
        Ok(ScaleCommand {
            id: hash_for_testing_only(parents.as_flattened()),
            prior: Prior::Merge(left, right),
            data: Box::default(),
        })
    }

    fn validate_merge(&self, _command: &impl Command) -> Result<(), PolicyError> {
        Ok(())
    }
}

struct NullSink;
impl Sink<()> for NullSink {
    fn begin(&mut self) {}
    fn consume(&mut self, (): ()) {}
    fn rollback(&mut self) {}
    fn commit(&mut self) {}
}

type Client = ClientState<ScalePolicyStore, MemStorageProvider>;
type Buffers = RuntimeBuffers<<MemStorageProvider as StorageProvider>::Segment>;

/// A graph plus the state needed to keep adding commands to it.
struct Graph {
    client: Client,
    graph_id: GraphId,
    buffers: Buffers,
    trx: Transaction<MemStorageProvider, ScalePolicyStore>,
    next_id: u64,
}

impl Graph {
    /// Creates a graph containing only the init command (uncommitted).
    fn new() -> Self {
        let graph_id = GraphId::transmute(cmd_id(0));
        let mut graph = Self {
            client: ClientState::new(ScalePolicyStore, MemStorageProvider::default()),
            graph_id,
            buffers: RuntimeBuffers::new(),
            trx: Transaction::new(graph_id),
            next_id: 1,
        };
        graph.add(ScaleCommand::new(0, Prior::None, QUIET, 1));
        graph
    }

    fn init_addr() -> Address {
        Address {
            id: cmd_id(0),
            max_cut: MaxCut::new(0),
        }
    }

    fn add(&mut self, cmd: ScaleCommand) {
        self.trx
            .add_commands(
                &[cmd],
                &mut self.client.provider,
                &mut self.client.policy_store,
                &mut NullSink,
                &mut self.buffers,
                &mem_spill,
            )
            .expect("add_commands must succeed");
    }

    /// Appends `n` commands in a line after `prev` within the current
    /// transaction, returning the last one's address.
    fn line(&mut self, mut prev: Address, n: u64, kind: u8, len: usize) -> Address {
        for _ in 0..n {
            let id = self.next_id;
            self.next_id = id.checked_add(1).expect("id must not overflow");
            let max_cut = prev
                .max_cut
                .checked_add(1)
                .expect("max cut must not overflow");
            let cmd = ScaleCommand::new(id, Prior::Single(prev), kind, len);
            prev = Address {
                id: cmd.id,
                max_cut,
            };
            self.add(cmd);
        }
        prev
    }

    fn commit(&mut self) {
        let trx = core::mem::replace(&mut self.trx, Transaction::new(self.graph_id));
        assert!(
            trx.commit(
                &mut self.client.provider,
                &mut self.client.policy_store,
                &mut NullSink,
                &mut self.buffers,
                &mem_spill,
            )
            .expect("commit must succeed")
        );
    }

    fn stats(&mut self) -> FetchStats {
        self.client
            .provider
            .get_storage(self.graph_id)
            .expect("storage exists")
            .fetch_stats()
    }

    /// Runs `f` and returns the fetches it performed.
    fn measure(&mut self, f: impl FnOnce(&mut Self)) -> FetchStats {
        let before = self.stats();
        f(self);
        self.stats() - before
    }
}

/// A workload measured at doubling sizes.
struct Scaling<'a> {
    /// Printed as the table heading.
    title: &'a str,
    /// What one unit of work is, e.g. "command" or "query".
    unit: &'a str,
    /// Expected growth per doubling if the implementation scaled well.
    ideal_growth: f64,
    /// Explanation of what the observed growth means.
    interpretation: &'a str,
    /// Workload sizes. Each must be double the previous.
    sizes: &'a [u64],
}

impl Scaling<'_> {
    /// Runs `cost(n)` for every size, prints a table of decoded bytes and
    /// growth per doubling, then asserts the final doubling grew by less
    /// than 1.5x `ideal_growth`, halfway to the next complexity class. If
    /// neither of the last two sizes decoded anything, there is no growth
    /// and the check passes.
    ///
    /// `units(n)` is how many units of work the measurement at size `n`
    /// covers, used for the per-unit column.
    fn run(&self, units: impl Fn(u64) -> u64, mut cost: impl FnMut(u64) -> FetchStats) {
        println!();
        println!("== {} ==", self.title);
        println!(
            "ideal: bytes decoded grow x{} per doubling of n; {}",
            self.ideal_growth, self.interpretation
        );
        println!(
            "{:>8} {:>10} {:>16} {:>18} {:>8}",
            "n",
            "fetches",
            "bytes decoded",
            format!("bytes/{}", self.unit),
            "growth"
        );

        let mut prev: Option<u64> = None;
        let mut last = None;
        for &n in self.sizes {
            let stats = cost(n);
            let per_unit = stats.bytes / units(n).max(1);
            let shown = match prev {
                Some(p) => {
                    let g = growth(p, stats.bytes);
                    last = g;
                    match g {
                        None => "x-".into(),
                        Some(g) => format!("x{g:.1}"),
                    }
                }
                None => "-".into(),
            };
            println!(
                "{n:>8} {:>10} {:>16} {per_unit:>18} {shown:>8}",
                stats.fetches, stats.bytes
            );
            prev = Some(stats.bytes);
        }

        let max_growth = self.ideal_growth * 1.5;
        assert!(
            last.is_none_or(|g| g < max_growth),
            "{}: bytes decoded grew x{:.1} on the last doubling of n \
             (ideal x{}, failing at >= x{max_growth}); see table above",
            self.title,
            last.unwrap_or_default(),
            self.ideal_growth,
        );
    }
}

/// Growth factor from `prev` bytes decoded to `cur` bytes decoded.
///
/// Returns `None` when both are zero: nothing was decoded at either size,
/// so there is no growth to measure (e.g. a fix that serves everything
/// from a cache). Growing from zero to non-zero is unbounded growth and
/// returns infinity.
fn growth(prev: u64, cur: u64) -> Option<f64> {
    match (prev, cur) {
        (0, 0) => None,
        (0, _) => Some(f64::INFINITY),
        (p, c) => Some(c as f64 / p as f64),
    }
}

#[test]
fn growth_handles_zero_bytes() {
    assert_eq!(growth(0, 0), None);
    assert_eq!(growth(0, 10), Some(f64::INFINITY));
    assert_eq!(growth(10, 0), Some(0.0));
    assert_eq!(growth(10, 20), Some(2.0));
}

/// Braiding two concurrent branches should decode each command's segment
/// a bounded number of times, so the bytes decoded should grow linearly
/// with branch length.
///
/// Instead, `evaluate_braid` and the convergence map BFS both call
/// `get_segment` once per command, and `get_segment` decodes the whole
/// segment. A branch of `n` commands stored as one segment therefore
/// decodes `O(n)` bytes `n` times.
#[test]
#[ignore = "demonstrates O(n^2) segment decoding during braid"]
fn braid_segment_decoding_is_linear() {
    /// Payload per command. Large enough that command data dominates the
    /// segment encoding.
    const PAYLOAD: usize = 64;

    Scaling {
        title: "braid two concurrent branches of n commands each (one segment per branch)",
        unit: "command",
        ideal_growth: 2.0,
        interpretation: "x4 means O(n^2)",
        sizes: &[50, 100, 200, 400, 800],
    }
    .run(
        |n| n * 2,
        |n| {
            let mut g = Graph::new();
            g.line(Graph::init_addr(), n, QUIET, PAYLOAD);
            g.line(Graph::init_addr(), n, QUIET, PAYLOAD);
            // Committing two heads braids them.
            g.measure(Graph::commit)
        },
    );
}

/// Builds a committed linear graph with one fact-inserting command per
/// commit, like a device performing `facts` actions. Returns the graph and
/// its head.
fn graph_with_facts(facts: u64) -> (Graph, Address) {
    let mut g = Graph::new();
    g.commit();
    let mut head = Graph::init_addr();
    for _ in 0..facts {
        head = g.line(head, 1, FACT, 1);
        g.commit();
    }
    (g, head)
}

/// Looking up a fact should not require decoding every fact in the
/// database.
///
/// Instead, `LinearFactPerspective::query` and `LinearFactIndex::query`
/// fetch and fully deserialize each `FactIndexRepr` in the prior chain on
/// every call. After compaction the base of that chain holds the entire
/// fact database, so one lookup of a missing key costs `O(total facts)`.
#[test]
#[ignore = "demonstrates fact queries decoding the whole fact index"]
fn fact_query_cost_is_independent_of_fact_count() {
    Scaling {
        title: "one fact query (missing key) against a database of n facts",
        unit: "query",
        ideal_growth: 1.0,
        interpretation: "x2 means each query is O(n)",
        // Multiples of MAX_FACT_INDEX_DEPTH (16) so every graph is at the
        // same point in the compaction cycle.
        sizes: &[128, 256, 512, 1024, 2048],
    }
    .run(
        |_| 1,
        |n| {
            let (mut g, head) = graph_with_facts(n);
            let storage = g
                .client
                .provider
                .get_storage(g.graph_id)
                .expect("storage exists");
            let loc = storage
                .get_location(head, &mut TraversalBuffer::new())
                .expect("can search")
                .expect("head exists");
            let perspective = storage
                .get_fact_perspective(loc)
                .expect("can get perspective");

            let before = storage.fetch_stats();
            let found = perspective
                .query(FACT_NAME, &absent_key())
                .expect("can query");
            assert!(found.is_none());
            storage.fetch_stats() - before
        },
    );
}

/// The storage cost of adding and committing one command that queries and
/// inserts a single fact should not depend on how many facts already exist.
///
/// Instead, each command pays `O(total facts)`: its query decodes the full
/// fact index chain (see above), `write_facts_with_prior` decodes the prior
/// index just to read its depth, and a single-head `commit` decodes the
/// head's fact index just to pass its offset to `commit_heads`. Adding `n`
/// commands is therefore `O(n^2)`.
#[test]
#[ignore = "demonstrates per-command cost growing with total fact count"]
fn per_command_fact_cost_is_independent_of_fact_count() {
    /// Commands measured at each size. A multiple of 16 averages over a
    /// full fact index compaction cycle.
    const WINDOW: u64 = 32;

    Scaling {
        title: "add + commit one fact command on top of n existing facts",
        unit: "command",
        ideal_growth: 1.0,
        interpretation: "x2 means each command is O(n), so n commands are O(n^2)",
        sizes: &[128, 256, 512, 1024, 2048],
    }
    .run(
        |_| WINDOW,
        |n| {
            let (mut g, mut head) = graph_with_facts(n);
            g.measure(|g| {
                for _ in 0..WINDOW {
                    head = g.line(head, 1, FACT, 1);
                    g.commit();
                }
            })
        },
    );
}
