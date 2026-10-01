//! Hello sync topology report.
//!
//! Simulates hello sync in rounds across each [`HelloTopology`] and prints
//! the results as Markdown. A round stands in for one network round trip:
//!
//! 1. Writers add their commands for the round.
//! 2. Every client whose graph changed sends a hello to each subscriber.
//! 3. Clients pair up and sync. A client takes part in at most one sync
//!    per round, as puller or as responder, so a hub can serve only one
//!    spoke per round.
//!
//! Wall time is not reported, since the whole simulation runs serially in
//! one process; it only decides when to stop growing a run.
//!
//! It takes a long time, so it is ignored by default. Run it with:
//!
//! ```text
//! cargo make topology-report
//! ```
//!
//! Set `TOPOLOGY_REPORT=<path>` to also write the report to a file.

use std::{
    env,
    fmt::Write as _,
    fs,
    string::String,
    time::{Duration, Instant},
};

use super::{tests::MemBackend, *};

/// A run is abandoned once it takes longer than this, and a row stops
/// growing once a run reaches it.
const LIMIT: Duration = Duration::from_secs(30);
/// The largest command count tried for each client count.
const MAX_COMMANDS: u64 = 10_000;
const SINGLE_COMMAND_CLIENT_COUNTS: [u64; 2] = [100, 300];
const GRAPH: u64 = 0;

type Provider = <MemBackend as StorageBackend>::StorageProvider;
type Clients = BTreeMap<u64, RefCell<ClientState<TestPolicyStore, Provider>>>;
type Caches = BTreeMap<(u64, u64, u64), RefCell<PeerCache>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writers {
    /// The last client writes one command per round.
    Single,
    /// Every client writes one command per round until each has written
    /// an equal share.
    Equal,
}

impl Writers {
    /// Client counts to try. Equal writers do far more work per round, so
    /// they stop at a smaller team.
    fn client_counts(self) -> [u64; 3] {
        match self {
            Self::Single => [10, 100, 1000],
            Self::Equal => [10, 100, 200],
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Stats {
    commands: u64,
    /// Rounds until every client holds every command.
    rounds: u64,
    /// Rounds after the last write until every client holds every command.
    lag: u64,
    hellos: u64,
    syncs: u64,
    /// Most hellos sent by one client.
    max_hellos_sent: u64,
    /// Most syncs served by one client.
    max_syncs_served: u64,
    /// Wall time of the simulation, excluding setup.
    elapsed: Duration,
}

#[derive(Clone, Copy)]
enum Cell {
    Done(Stats),
    /// The run did not finish within [`LIMIT`].
    TimedOut,
    /// The cell does not apply (fewer commands than equal writers).
    NotApplicable,
}

fn topologies() -> Vec<(&'static str, HelloTopology)> {
    vec![
        ("Hub and spoke", HelloTopology::HubAndSpoke),
        ("Ring", HelloTopology::Ring),
        ("Two-way ring", HelloTopology::TwoWayRing),
        ("Clique", HelloTopology::Clique),
        (
            "Hierarchy (3 children)",
            HelloTopology::Hierarchy { children: 3 },
        ),
        ("Random (3 links)", HelloTopology::Random { links: 3 }),
        (
            "Small world (1 long link)",
            HelloTopology::SmallWorld { long_links: 1 },
        ),
    ]
}

/// Syncs `subscriber` from `publisher`, returning the commands received.
fn pull(
    clients: &Clients,
    caches: &mut Caches,
    sink: &mut TestSink,
    rt_buffers: &mut RuntimeBuffers<<Provider as StorageProvider>::Segment>,
    graph_id: GraphId,
    subscriber: u64,
    publisher: u64,
) -> Result<usize, TestError> {
    caches.entry((GRAPH, subscriber, publisher)).or_default();
    caches.entry((GRAPH, publisher, subscriber)).or_default();
    let mut request_client = clients
        .get(&subscriber)
        .ok_or(TestError::MissingClient)?
        .borrow_mut();
    pull_from(
        GRAPH,
        subscriber,
        publisher,
        &mut request_client,
        graph_id,
        clients,
        caches,
        sink,
        rt_buffers,
    )
}

/// Simulates `commands` commands spreading across `n` clients by hello
/// sync. Panics if the clients do not converge.
fn run(
    topology: &HelloTopology,
    n: u64,
    commands: u64,
    writers: Writers,
) -> Result<Cell, TestError> {
    if writers == Writers::Equal && commands < n {
        return Ok(Cell::NotApplicable);
    }
    let write_rounds = match writers {
        Writers::Single => commands,
        Writers::Equal => commands / n,
    };

    // Setup: every client starts with the graph's init command.
    let mut backend = MemBackend;
    let mut sink = TestSink::new();
    sink.ignore_expectations(true);
    let mut rt_buffers = RuntimeBuffers::<<Provider as StorageProvider>::Segment>::new();
    let clients: Clients = (0..n)
        .map(|id| {
            let state = ClientState::new(TestPolicyStore::new(), backend.provider(id));
            (id, RefCell::new(state))
        })
        .collect();
    let mut caches = Caches::new();
    let graph_id = clients[&0].borrow_mut().new_graph(
        0u64.to_be_bytes().as_slice(),
        TestActions::Init(0),
        &mut sink,
    )?;
    for i in 1..n {
        pull(
            &clients,
            &mut caches,
            &mut sink,
            &mut rt_buffers,
            graph_id,
            i,
            0,
        )?;
    }
    let mut subscribers = vec![Vec::new(); n as usize];
    for (client, peer) in hello_subscriptions(topology, n, &mut SmallRng::seed_from_u64(0)) {
        subscribers[peer as usize].push(client);
    }

    let start = Instant::now();
    let mut stats = Stats {
        commands,
        ..Stats::default()
    };
    // pending[s] maps each publisher that sent `s` a hello to the head it
    // advertised.
    let mut pending: Vec<BTreeMap<u64, Address>> = vec![BTreeMap::new(); n as usize];
    let mut changed = BTreeSet::new();
    let mut hellos_sent = vec![0u64; n as usize];
    let mut served = vec![0u64; n as usize];
    let mut written = 0u64;
    let mut round = 0u64;
    while round < write_rounds || !changed.is_empty() || pending.iter().any(|p| !p.is_empty()) {
        if start.elapsed() > LIMIT {
            return Ok(Cell::TimedOut);
        }
        round += 1;

        if round <= write_rounds {
            let round_writers = match writers {
                Writers::Single => n - 1..n,
                Writers::Equal => 0..n,
            };
            for writer in round_writers {
                let set = TestActions::SetValuePriority(written % 16, written, 0);
                clients[&writer].borrow_mut().action(
                    graph_id,
                    &mut sink,
                    set,
                    &mut rt_buffers,
                    mem_spill,
                )?;
                written += 1;
                changed.insert(writer);
            }
        }

        for publisher in core::mem::take(&mut changed) {
            let head = clients[&publisher].borrow_mut().hello_head(graph_id)?;
            for &subscriber in &subscribers[publisher as usize] {
                pending[subscriber as usize].insert(publisher, head);
                hellos_sent[publisher as usize] += 1;
            }
        }

        // Pair each client with at most one sync. The starting subscriber
        // rotates so no client is always served first.
        let mut busy = vec![false; n as usize];
        let mut pairs = Vec::new();
        for k in 0..n {
            let subscriber = (k + round) % n;
            if busy[subscriber as usize] {
                continue;
            }
            let mut chosen = None;
            let mut stale = Vec::new();
            for (&publisher, &head) in &pending[subscriber as usize] {
                if busy[publisher as usize] {
                    continue;
                }
                if clients[&subscriber].borrow_mut().should_sync_on_hello(
                    graph_id,
                    head,
                    &mut rt_buffers.traversal.primary,
                )? {
                    chosen = Some(publisher);
                    break;
                }
                stale.push(publisher);
            }
            for publisher in stale.into_iter().chain(chosen) {
                pending[subscriber as usize].remove(&publisher);
            }
            if let Some(publisher) = chosen {
                busy[subscriber as usize] = true;
                busy[publisher as usize] = true;
                pairs.push((subscriber, publisher));
            }
        }

        for (subscriber, publisher) in pairs {
            let received = pull(
                &clients,
                &mut caches,
                &mut sink,
                &mut rt_buffers,
                graph_id,
                subscriber,
                publisher,
            )?;
            stats.syncs += 1;
            served[publisher as usize] += 1;
            if received > 0 {
                stats.rounds = round;
                changed.insert(subscriber);
            }
        }
    }
    stats.elapsed = start.elapsed();
    stats.lag = stats.rounds.saturating_sub(write_rounds);
    stats.hellos = hellos_sent.iter().sum();
    stats.max_hellos_sent = hellos_sent.into_iter().max().unwrap_or(0);
    stats.max_syncs_served = served.into_iter().max().unwrap_or(0);

    let mut first = clients[&0].borrow_mut();
    for i in 1..n {
        let mut other = clients[&i].borrow_mut();
        assert!(
            graph_eq(
                first.provider().get_storage(graph_id)?,
                other.provider().get_storage(graph_id)?,
            ),
            "client {i} did not converge"
        );
    }
    Ok(Cell::Done(stats))
}

impl Stats {
    #[allow(clippy::cast_precision_loss, reason = "counts are far below 2^52")]
    fn commands_per_round(&self) -> f64 {
        self.commands as f64 / self.rounds as f64
    }
}

/// Formats `n` with thousands separators.
fn fmt_count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// Formats a cell on one line for progress output.
fn fmt_progress(cell: Cell) -> String {
    match cell {
        Cell::NotApplicable => "n/a".into(),
        Cell::TimedOut => format!("> {} s", LIMIT.as_secs()),
        Cell::Done(s) => format!(
            "{} rounds, lag {}, {:.2} cmd/round, {} hellos, {} syncs, busiest {} hellos {} served",
            s.rounds,
            s.lag,
            s.commands_per_round(),
            s.hellos,
            s.syncs,
            s.max_hellos_sent,
            s.max_syncs_served
        ),
    }
}

const STATS_HEADER: &str =
    "Rounds | Lag | Cmd/round | Hellos | Syncs | Busiest: hellos | Busiest: served |";
const STATS_ALIGN: &str = "---:|---:|---:|---:|---:|---:|---:|";

/// Formats `s` as the cells under [`STATS_HEADER`].
fn fmt_stats(s: &Stats) -> String {
    format!(
        "{} | {} | {:.2} | {} | {} | {} | {} |",
        fmt_count(s.rounds),
        fmt_count(s.lag),
        s.commands_per_round(),
        fmt_count(s.hellos),
        fmt_count(s.syncs),
        fmt_count(s.max_hellos_sent),
        fmt_count(s.max_syncs_served)
    )
}

/// Runs one row per client count, growing the command count by 10× up to
/// [`MAX_COMMANDS`] or until a run takes [`LIMIT`]. Once a row's first run
/// reaches the limit, larger client counts are skipped.
fn grid(name: &str, topology: &HelloTopology, writers: Writers) -> Vec<(u64, Vec<Cell>)> {
    let mut rows = Vec::new();
    for clients in writers.client_counts() {
        let mut row = Vec::new();
        let mut commands = 10;
        while commands <= MAX_COMMANDS {
            let cell = run(topology, clients, commands, writers).unwrap();
            eprintln!(
                "{name}: {clients} clients, {commands} commands: {}",
                fmt_progress(cell)
            );
            row.push(cell);
            match cell {
                Cell::Done(s) if s.elapsed < LIMIT => {}
                Cell::NotApplicable => {}
                _ => break,
            }
            commands *= 10;
        }
        let gave_up = row
            .iter()
            .find(|c| !matches!(c, Cell::NotApplicable))
            .is_some_and(|c| !matches!(c, Cell::Done(s) if s.elapsed < LIMIT));
        rows.push((clients, row));
        if gave_up {
            break;
        }
    }
    rows
}

/// Writes the finished runs in `rows` as a table, one row per run.
fn write_runs(out: &mut String, rows: &[(u64, Vec<Cell>)]) {
    let mut lines = String::new();
    for (clients, row) in rows {
        for (stats, commands) in row
            .iter()
            .zip(iter::successors(Some(10u64), |c| Some(c * 10)))
        {
            if let Cell::Done(s) = stats {
                writeln!(
                    lines,
                    "| {} | {} | {}",
                    fmt_count(*clients),
                    fmt_count(commands),
                    fmt_stats(s)
                )
                .unwrap();
            }
        }
    }
    if lines.is_empty() {
        out.push_str("No runs finished.\n\n");
        return;
    }
    writeln!(out, "| Clients | Commands | {STATS_HEADER}").unwrap();
    writeln!(out, "|---:|---:|{STATS_ALIGN}").unwrap();
    out.push_str(&lines);
    out.push('\n');
}

#[test]
#[ignore = "slow; run with `cargo make topology-report`"]
fn topology_report() {
    let mut out = String::new();
    writeln!(
        out,
        "# Hello sync topology report

> **Note:** the simulation runs serially in one process, so it is CPU
> constrained. Wall time measures how fast the simulator runs, not how fast
> a network would deliver commands, so results are reported in rounds.

Hello sync simulated in rounds, where a round stands in for one network
round trip. In each round, writers add their commands, every client whose
graph changed sends a hello to each of its subscribers, and then clients
pair up to sync. A client takes part in at most one sync per round, as
puller or as responder, so a hub serves only one spoke per round.

- **Rounds**: rounds until every client holds every command.
- **Lag**: rounds after the last write until every client holds every command.
- **Cmd/round**: commands delivered to every client per round.
- **Hellos**, **Syncs**: totals across all clients.
- **Busiest**: the most hellos sent, and the most syncs served, by any one client.

Command counts grow by 10× up to {max}. A run is abandoned after {limit} s of
wall time, and larger runs for that client count are skipped. Only finished
runs are listed. Equal writer runs with fewer commands than clients are
skipped, since the commands cannot be split equally.
",
        limit = LIMIT.as_secs(),
        max = MAX_COMMANDS,
    )
    .unwrap();

    writeln!(out, "## Single command propagation\n").unwrap();
    writeln!(out, "One command written by the last client.\n").unwrap();
    for clients in SINGLE_COMMAND_CLIENT_COUNTS {
        writeln!(out, "### {clients} clients\n").unwrap();
        writeln!(out, "| Topology | {STATS_HEADER}").unwrap();
        writeln!(out, "|---|{STATS_ALIGN}").unwrap();
        for (name, topology) in topologies() {
            let cell = run(&topology, clients, 1, Writers::Single).unwrap();
            eprintln!(
                "{name}: 1 command to {clients} clients: {}",
                fmt_progress(cell)
            );
            match cell {
                Cell::Done(s) => writeln!(out, "| {name} | {}", fmt_stats(&s)),
                _ => writeln!(out, "| {name} | {} | | | | | | |", fmt_progress(cell)),
            }
            .unwrap();
        }
        out.push('\n');
    }

    for (writers, title, detail) in [
        (
            Writers::Single,
            "Single writer",
            "The last client writes one command per round.",
        ),
        (
            Writers::Equal,
            "Equal writers",
            "Every client writes one command per round until each has written an equal share.",
        ),
    ] {
        writeln!(out, "## {title}\n\n{detail}\n").unwrap();
        for (name, topology) in topologies() {
            writeln!(out, "### {name}\n").unwrap();
            write_runs(&mut out, &grid(name, &topology, writers));
        }
    }

    println!("{out}");
    if let Ok(path) = env::var("TOPOLOGY_REPORT") {
        fs::write(path, &out).unwrap();
    }
}

#[test]
fn round_counts_match_topology() {
    let rounds = |topology| match run(&topology, 10, 1, Writers::Single).unwrap() {
        Cell::Done(s) => s.rounds,
        _ => panic!("run did not finish"),
    };
    // One hop per round around the ring.
    assert_eq!(rounds(HelloTopology::Ring), 9);
    // The hub pulls from the writer, then serves one spoke per round.
    assert_eq!(rounds(HelloTopology::HubAndSpoke), 9);
    // Spreads both ways, so the farthest client is 5 hops away.
    assert_eq!(rounds(HelloTopology::TwoWayRing), 5);
    // Each holder serves one new client per round, doubling each round.
    assert_eq!(rounds(HelloTopology::Clique), 4);
}
