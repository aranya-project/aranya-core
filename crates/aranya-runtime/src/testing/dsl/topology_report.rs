//! Hello sync topology report.
//!
//! Measures how fast commands propagate by hello sync alone across each
//! [`HelloTopology`] and prints the results as Markdown. It takes a long
//! time, so it is ignored by default. Run it with:
//!
//! ```text
//! cargo make topology-report
//! ```
//!
//! Set `TOPOLOGY_REPORT=<path>` to also write the report to a file.

use std::{
    collections::VecDeque,
    env,
    fmt::Write as _,
    fs,
    string::String,
    time::{Duration, Instant},
};

use super::{tests::MemBackend, *};

/// A run is abandoned once propagation takes longer than this, and a row
/// stops growing once a run reaches it.
const LIMIT: Duration = Duration::from_secs(30);
const CLIENT_COUNTS: [u64; 3] = [10, 100, 1000];
const SINGLE_COMMAND_CLIENT_COUNTS: [u64; 2] = [100, 300];
const GRAPH: u64 = 0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Writers {
    /// The last client writes every command.
    Single,
    /// Every client writes the same number of commands, round-robin.
    Equal,
}

#[derive(Clone, Copy)]
enum Cell {
    /// Propagation finished in the given time.
    Done(Duration),
    /// Propagation did not finish within [`LIMIT`].
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

/// Returns subscriptions for `topology` in which every client can reach
/// every other. A random topology can leave a client unreachable, which
/// hello sync can never fix, so seeds are tried until one is connected.
fn connected_subscriptions(topology: &HelloTopology, clients: u64) -> Vec<(u64, u64)> {
    (0..100)
        .map(|seed| hello_subscriptions(topology, clients, &mut SmallRng::seed_from_u64(seed)))
        .find(|subs| strongly_connected(clients, subs))
        .expect("no connected topology found in 100 seeds")
}

fn strongly_connected(clients: u64, subs: &[(u64, u64)]) -> bool {
    let reaches_all = |edges: &BTreeMap<u64, Vec<u64>>| {
        let mut seen = BTreeSet::from([0]);
        let mut queue = VecDeque::from([0]);
        while let Some(node) = queue.pop_front() {
            for &next in edges.get(&node).into_iter().flatten() {
                if seen.insert(next) {
                    queue.push_back(next);
                }
            }
        }
        seen.len() as u64 == clients
    };
    let mut forward: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut backward: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for &(client, peer) in subs {
        forward.entry(peer).or_default().push(client);
        backward.entry(client).or_default().push(peer);
    }
    reaches_all(&forward) && reaches_all(&backward)
}

/// Times how long `commands` commands take to reach all `clients` clients.
/// Setup is not timed. Panics if hello sync alone fails to converge.
fn run(topology: &HelloTopology, clients: u64, commands: u64, writers: Writers) -> Cell {
    if writers == Writers::Equal && commands < clients {
        return Cell::NotApplicable;
    }

    let mut rules = vec![TestRule::SetupClientsAndGraph {
        clients,
        graph: GRAPH,
        policy: 0,
    }];
    for (client, peer) in connected_subscriptions(topology, clients) {
        rules.push(TestRule::HelloSubscribe {
            client,
            peer,
            graph: GRAPH,
            notify_interval: 1,
        });
    }
    rules.push(TestRule::IgnoreExpectations { ignore: true });
    for i in 0..commands {
        let client = match writers {
            Writers::Single => clients - 1,
            Writers::Equal => i % clients,
        };
        rules.push(TestRule::ActionSet {
            client,
            graph: GRAPH,
            key: i % 16,
            value: i,
            repeat: 1,
            priority: 0,
        });
    }
    rules.push(TestRule::IgnoreExpectations { ignore: false });
    for i in 1..clients {
        rules.push(TestRule::CompareGraphs {
            clienta: 0,
            clientb: i,
            graph: GRAPH,
            equal: true,
        });
    }

    let mut start = None;
    let mut cell = Cell::TimedOut;
    run_test_with(MemBackend, &rules, |rule| {
        match (rule, start) {
            (TestRule::IgnoreExpectations { ignore: true }, _) => start = Some(Instant::now()),
            (TestRule::IgnoreExpectations { ignore: false }, Some(s)) => {
                cell = Cell::Done(s.elapsed());
            }
            (_, Some(s)) if matches!(cell, Cell::TimedOut) && s.elapsed() > LIMIT => {
                return ControlFlow::Break(());
            }
            _ => {}
        }
        ControlFlow::Continue(())
    })
    .unwrap();
    cell
}

fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.1} ms", secs * 1000.0)
    } else {
        format!("{secs:.2} s")
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "command counts are far below 2^52"
)]
fn fmt_cell(cell: Option<Cell>, commands: u64) -> String {
    match cell {
        None => "—".into(),
        Some(Cell::NotApplicable) => "n/a".into(),
        Some(Cell::TimedOut) => format!("> {} s", LIMIT.as_secs()),
        Some(Cell::Done(d)) => format!(
            "{}<br>{:.0} cmd/s",
            fmt_duration(d),
            commands as f64 / d.as_secs_f64()
        ),
    }
}

/// Runs one row per client count, growing the command count by 10× until a
/// run reaches [`LIMIT`]. Once a row's first run reaches the limit, larger
/// client counts are skipped.
fn grid(name: &str, topology: &HelloTopology, writers: Writers) -> Vec<Vec<Cell>> {
    let mut rows = Vec::new();
    for clients in CLIENT_COUNTS {
        let mut row = Vec::new();
        let mut commands = 10;
        loop {
            let cell = run(topology, clients, commands, writers);
            eprintln!(
                "{name}: {clients} clients, {commands} commands: {}",
                fmt_cell(Some(cell), commands).replace("<br>", ", ")
            );
            row.push(cell);
            match cell {
                Cell::Done(d) if d < LIMIT => {}
                Cell::NotApplicable => {}
                _ => break,
            }
            commands *= 10;
        }
        let gave_up = row
            .iter()
            .find(|c| !matches!(c, Cell::NotApplicable))
            .is_some_and(|c| !matches!(c, Cell::Done(d) if *d < LIMIT));
        rows.push(row);
        if gave_up {
            break;
        }
    }
    rows
}

fn write_grid(out: &mut String, rows: &[Vec<Cell>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let commands = |col: usize| 10u64.pow(u32::try_from(col).unwrap() + 1);
    out.push_str("| Clients |");
    for col in 0..columns {
        write!(out, " {} commands |", commands(col)).unwrap();
    }
    out.push_str("\n|---:|");
    out.push_str(&"---:|".repeat(columns));
    out.push('\n');
    for (i, clients) in CLIENT_COUNTS.iter().enumerate() {
        let row = rows.get(i);
        write!(out, "| {clients} |").unwrap();
        for col in 0..columns {
            let cell = row.and_then(|r| r.get(col)).copied();
            write!(out, " {} |", fmt_cell(cell, commands(col))).unwrap();
        }
        out.push('\n');
    }
    out.push('\n');
}

#[test]
#[ignore = "slow; run with `cargo make topology-report`"]
fn topology_report() {
    let mut out = String::new();
    writeln!(
        out,
        "# Hello sync topology report

Time for commands to reach every client by hello sync alone, with in-memory
storage and a notify interval of 1. Setup (creating clients and the initial
graph) is not timed. Commands are written one at a time and each fully
propagates before the next is written. Runs are abandoned after {limit} s,
and a row stops once a run takes {limit} s or more.

- `> {limit} s`: did not finish within the limit.
- `—`: not run, because a smaller run already reached the limit.
- `n/a`: fewer commands than clients, so they cannot be split equally.
",
        limit = LIMIT.as_secs()
    )
    .unwrap();

    writeln!(out, "## Single command propagation\n").unwrap();
    writeln!(out, "One command written by the last client.\n").unwrap();
    out.push_str("| Topology |");
    for clients in SINGLE_COMMAND_CLIENT_COUNTS {
        write!(out, " {clients} clients |").unwrap();
    }
    out.push_str("\n|---|");
    out.push_str(&"---:|".repeat(SINGLE_COMMAND_CLIENT_COUNTS.len()));
    out.push('\n');
    for (name, topology) in topologies() {
        write!(out, "| {name} |").unwrap();
        for clients in SINGLE_COMMAND_CLIENT_COUNTS {
            let cell = run(&topology, clients, 1, Writers::Single);
            eprintln!(
                "{name}: 1 command to {clients} clients: {}",
                fmt_cell(Some(cell), 1).replace("<br>", ", ")
            );
            write!(out, " {} |", fmt_cell(Some(cell), 1)).unwrap();
        }
        out.push('\n');
    }
    out.push('\n');

    for (writers, title, detail) in [
        (
            Writers::Single,
            "Single writer",
            "The last client writes every command.",
        ),
        (
            Writers::Equal,
            "Equal writers",
            "Every client writes the same number of commands, round-robin.",
        ),
    ] {
        writeln!(out, "## {title}\n\n{detail}\n").unwrap();
        for (name, topology) in topologies() {
            writeln!(out, "### {name}\n").unwrap();
            write_grid(&mut out, &grid(name, &topology, writers));
        }
    }

    println!("{out}");
    if let Ok(path) = env::var("TOPOLOGY_REPORT") {
        fs::write(path, &out).unwrap();
    }
}
