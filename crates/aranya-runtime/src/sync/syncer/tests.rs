#![cfg(test)]
#![allow(clippy::arithmetic_side_effects)]

//! End-to-end tests: several `Syncer`s over in-memory storage and a loopback
//! transport that delivers each outbound to its peer and carries the reply
//! back, exactly as a real driver loop would.

use alloc::{collections::BTreeSet, vec, vec::Vec};
use core::time::Duration;

use aranya_crypto::Rng;

use super::*;
use crate::{
    ClientState, MemSpill, RuntimeBuffers,
    command::Command as _,
    storage::{
        GraphId, LocatedAddress, Segment as _, Storage as _, StorageError, StorageProvider,
        linear::testing::MemStorageProvider,
    },
    sync::{COMMAND_RESPONSE_MAX, MAX_SYNC_MESSAGE_SIZE},
    testing::protocol::{TestActions, TestPolicyStore, TestSink},
};

type Peer = &'static str;
type Client = ClientState<TestPolicyStore, MemStorageProvider>;
type Segment = <MemStorageProvider as StorageProvider>::Segment;
type Machine<S = HeapSlots<Peer, Duration>> =
    Syncer<TestPolicyStore, MemStorageProvider, Peer, Duration, S>;

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn spill() -> Result<MemSpill, StorageError> {
    Ok(MemSpill::new())
}

/// One participant: storage, syncer, and a log of what it sent and got.
struct Node<S: SyncSlots<Peer, Duration> = HeapSlots<Peer, Duration>> {
    name: Peer,
    client: Client,
    sink: TestSink,
    buffers: RuntimeBuffers<Segment>,
    syncer: Machine<S>,
    out: Vec<u8>,
    /// Every outbound this node emitted: (kind, destination).
    sent: Vec<(OutboundKind, Peer)>,
    /// Every `Inbound` this node produced for a message or reply.
    got: Vec<Inbound>,
}

impl<S: SyncSlots<Peer, Duration>> Node<S> {
    fn with_syncer(name: Peer, syncer: Machine<S>) -> Self {
        let mut sink = TestSink::new();
        sink.ignore_expectations(true);
        Self {
            name,
            client: ClientState::new(TestPolicyStore::new(), MemStorageProvider::default()),
            sink,
            buffers: RuntimeBuffers::new(),
            syncer,
            out: vec![0u8; MAX_SYNC_MESSAGE_SIZE],
            sent: Vec::new(),
            got: Vec::new(),
        }
    }

    fn next_outbound(&mut self, now: Duration) -> Result<Option<Outbound<Peer>>, SyncerError> {
        let rng = Rng;
        let mut cx = SyncContext {
            client: &mut self.client,
            sink: &mut self.sink,
            buffers: &mut self.buffers,
            rng: &rng,
            make_spill: spill,
        };
        let ob = self.syncer.next_outbound(now, &mut cx, &mut self.out)?;
        if let Some(ob) = &ob {
            assert!(!ob.is_empty(), "empty outbound");
            self.sent.push((ob.kind(), ob.peer()));
        }
        Ok(ob)
    }

    fn handle_incoming(
        &mut self,
        peer: Peer,
        data: &[u8],
        now: Duration,
    ) -> Result<Inbound, SyncerError> {
        let rng = Rng;
        let mut cx = SyncContext {
            client: &mut self.client,
            sink: &mut self.sink,
            buffers: &mut self.buffers,
            rng: &rng,
            make_spill: spill,
        };
        let inbound = self
            .syncer
            .handle_incoming(peer, data, now, &mut cx, &mut self.out)?;
        self.got.push(inbound);
        Ok(inbound)
    }

    fn handle_reply(
        &mut self,
        token: Token<Peer>,
        data: &[u8],
        now: Duration,
    ) -> Result<Inbound, SyncerError> {
        let rng = Rng;
        let mut cx = SyncContext {
            client: &mut self.client,
            sink: &mut self.sink,
            buffers: &mut self.buffers,
            rng: &rng,
            make_spill: spill,
        };
        let inbound = self.syncer.handle_reply(token, data, now, &mut cx)?;
        self.got.push(inbound);
        Ok(inbound)
    }

    fn new_graph(&mut self) -> GraphId {
        self.client
            .new_graph(&0u64.to_be_bytes(), TestActions::Init(0), &mut self.sink)
            .expect("new_graph")
    }

    /// Performs a local action and tells the syncer about it.
    fn action(&mut self, graph_id: GraphId, key: u64, now: Duration) {
        self.client
            .action(
                graph_id,
                &mut self.sink,
                TestActions::SetValue(key, key),
                &mut self.buffers,
                spill,
            )
            .expect("action");
        self.syncer.notify_local_change(graph_id, now);
    }

    fn head(&mut self, graph_id: GraphId) -> Option<Address> {
        self.client.head_address(graph_id).ok()
    }

    fn command_count(&mut self, graph_id: GraphId) -> usize {
        let Ok(storage) = self.client.provider().get_storage(graph_id) else {
            return 0;
        };
        let mut count = 0;
        let heads = storage.get_heads().expect("heads");
        let mut seen = BTreeSet::new();
        let mut stack: Vec<_> = heads.iter().map(LocatedAddress::location).collect();
        while let Some(loc) = stack.pop() {
            let segment = storage.get_segment(loc).expect("segment");
            for cmd in segment.get_from(segment.first_location()) {
                if seen.insert(cmd.id()) {
                    count += 1;
                }
            }
            for prior in segment.prior() {
                stack.push(prior);
            }
        }
        count
    }

    fn sent_kinds(&self, kind: OutboundKind) -> usize {
        self.sent.iter().filter(|(k, _)| *k == kind).count()
    }
}

impl Node {
    fn new(name: Peer) -> Self {
        Self::with_syncer(name, Syncer::new())
    }

    fn with_limits(name: Peer, limits: Limits) -> Self {
        Self::with_syncer(name, Syncer::with_limits(limits))
    }
}

/// A loopback network of nodes addressed by name.
struct Net {
    nodes: Vec<Node>,
    /// Peers that cannot be reached: sends to them fail.
    down: BTreeSet<Peer>,
}

impl Net {
    fn new(names: &[Peer]) -> Self {
        Self {
            nodes: names.iter().map(|n| Node::new(n)).collect(),
            down: BTreeSet::new(),
        }
    }

    fn idx(&self, name: Peer) -> usize {
        self.nodes
            .iter()
            .position(|n| n.name == name)
            .unwrap_or_else(|| panic!("no node {name}"))
    }

    fn node(&mut self, name: Peer) -> &mut Node {
        let i = self.idx(name);
        &mut self.nodes[i]
    }

    /// Lets every node send everything due at `now`, delivering each message
    /// and its reply, until the network is quiet. Returns the number of
    /// messages delivered.
    fn settle(&mut self, now: Duration) -> usize {
        let mut total = 0;
        loop {
            let mut progressed = false;
            for i in 0..self.nodes.len() {
                while let Some(ob) = self.nodes[i].next_outbound(now).expect("next_outbound") {
                    progressed = true;
                    total += 1;
                    assert!(total < 2000, "network did not settle");
                    let src = self.nodes[i].name;
                    let dst = *ob.peer();
                    let bytes = self.nodes[i].out[..ob.len()].to_vec();
                    if self.down.contains(&dst) {
                        self.nodes[i]
                            .syncer
                            .complete(ob.token(), Outcome::Failed, now);
                        continue;
                    }
                    let j = self.idx(dst);
                    let inbound = self.nodes[j]
                        .handle_incoming(src, &bytes, now)
                        .expect("handle_incoming");
                    if ob.expects_reply() {
                        let reply = match inbound {
                            Inbound::Reply { len } => self.nodes[j].out[..len].to_vec(),
                            _ => Vec::new(),
                        };
                        self.nodes[i]
                            .handle_reply(ob.token(), &reply, now)
                            .expect("handle_reply");
                    } else {
                        self.nodes[i]
                            .syncer
                            .complete(ob.token(), Outcome::Sent, now);
                    }
                }
            }
            if !progressed {
                return total;
            }
        }
    }

    fn assert_same_head(&mut self, graph_id: GraphId, a: Peer, b: Peer) {
        let ha = self.node(a).head(graph_id);
        let hb = self.node(b).head(graph_id);
        assert!(ha.is_some(), "{a} has no graph");
        assert_eq!(ha, hb, "{a} and {b} differ");
    }
}

/// A node with a graph of `1 + actions` commands.
fn seeded(net: &mut Net, name: Peer, actions: u64) -> GraphId {
    let node = net.node(name);
    let graph_id = node.new_graph();
    for i in 1..=actions {
        node.action(graph_id, i, secs(0));
    }
    graph_id
}

// ---- poll ------------------------------------------------------------------------

#[test]
fn poll_bootstraps_a_cold_peer_in_one_drain() {
    let mut net = Net::new(&["a", "b"]);
    // Well over two full responses, so the session needs several rounds.
    let actions = (COMMAND_RESPONSE_MAX as u64) * 2 + 49;
    let g = seeded(&mut net, "a", actions);
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();

    net.settle(secs(0));

    net.assert_same_head(g, "a", "b");
    assert_eq!(net.node("b").command_count(g), actions as usize + 1);
    // One transaction across all rounds, one commit.
    let rounds = net.node("b").sent_kinds(OutboundKind::PollRequest);
    assert_eq!(rounds, 3, "{:?}", net.node("b").sent);
    let committed: Vec<_> = net
        .node("b")
        .got
        .iter()
        .filter(|i| matches!(i, Inbound::Committed { .. }))
        .collect();
    assert_eq!(committed.len(), 1);
    assert_eq!(net.node("b").syncer.next_deadline(), None);
}

#[test]
fn periodic_poll_picks_up_later_changes() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    net.settle(secs(0));
    net.assert_same_head(g, "a", "b");

    net.node("a").action(g, 100, secs(10));
    assert_eq!(net.settle(secs(10)), 0);
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(30)));
    net.settle(secs(30));
    net.assert_same_head(g, "a", "b");
    assert_eq!(net.node("b").sent_kinds(OutboundKind::PollRequest), 2);
}

#[test]
fn up_to_date_poll_commits_nothing() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    net.settle(secs(0));
    net.node("b").got.clear();
    net.node("b").syncer.sync_now(&"a", g, secs(1));
    net.settle(secs(1));
    assert_eq!(net.node("b").got, [Inbound::Handled]);
}

#[test]
fn failed_poll_backs_off_then_recovers() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    net.down.insert("a");

    net.settle(secs(0));
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(1)));
    net.settle(secs(1));
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(3)));
    assert!(net.node("b").head(g).is_none());

    net.down.clear();
    net.settle(secs(3));
    net.assert_same_head(g, "a", "b");
    // Back on the regular interval after success.
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(63)));
}

#[test]
fn reply_timeout_aborts_session_and_backs_off() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    let ob = b.next_outbound(secs(0)).unwrap().expect("poll request");
    assert_eq!(ob.kind(), OutboundKind::PollRequest);
    // Waiting on the reply: nothing else fires, not even the interval.
    assert_eq!(b.syncer.next_deadline(), Some(secs(30)));
    assert!(b.next_outbound(secs(29)).unwrap().is_none());
    // Timeout: the session is gone and the peer is backed off.
    assert!(b.next_outbound(secs(30)).unwrap().is_none());
    assert_eq!(b.syncer.next_deadline(), Some(secs(31)));
    assert_eq!(
        b.handle_reply(ob.token(), &[], secs(30)).unwrap(),
        Inbound::Ignored(IgnoreReason::StaleToken)
    );
    // The retry is a brand-new session.
    let retry = b.next_outbound(secs(31)).unwrap().expect("retry");
    assert_eq!(retry.kind(), OutboundKind::PollRequest);
    assert_ne!(retry.token(), ob.token());
}

#[test]
fn one_poll_session_at_a_time() {
    let mut net = Net::new(&["a", "b", "c"]);
    let g = seeded(&mut net, "a", 2);
    seeded(&mut net, "c", 1);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let first = b.next_outbound(secs(0)).unwrap().expect("first");
    // "c" is due too, but the session with "a" holds the only seat.
    assert!(b.next_outbound(secs(0)).unwrap().is_none());
    // A completed round frees it.
    b.handle_reply(first.token(), &[], secs(0)).unwrap();
    let second = b.next_outbound(secs(0)).unwrap().expect("second");
    assert_ne!(second.peer(), first.peer());
}

#[test]
fn stale_poll_reply_is_ignored() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let ob = b.next_outbound(secs(0)).unwrap().expect("poll");
    b.handle_reply(ob.token(), &[], secs(0)).unwrap();
    assert_eq!(
        b.handle_reply(ob.token(), &[], secs(0)).unwrap(),
        Inbound::Ignored(IgnoreReason::StaleToken)
    );
}

#[test]
fn remove_graph_drops_the_open_session() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    let ob = b.next_outbound(secs(0)).unwrap().expect("poll");
    b.syncer.remove_graph(g);
    assert_eq!(
        b.handle_reply(ob.token(), &[], secs(0)).unwrap(),
        Inbound::Ignored(IgnoreReason::StaleToken)
    );
    assert_eq!(b.syncer.next_deadline(), None);
}

// ---- push ------------------------------------------------------------------------

fn push_cfg(remain_open: u64, max_bytes: u64) -> PushConfig {
    PushConfig {
        remain_open: secs(remain_open),
        max_bytes,
    }
}

#[test]
fn push_subscription_catches_up_then_streams_changes() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();

    net.settle(secs(0));
    // Subscribe accepted, then an immediate catch-up push.
    assert_eq!(net.node("b").sent_kinds(OutboundKind::Subscribe), 1);
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 1);
    assert!(net.node("b").got.contains(&Inbound::Handled));
    net.assert_same_head(g, "a", "b");

    net.node("a").action(g, 100, secs(5));
    net.settle(secs(5));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 2);
    net.assert_same_head(g, "a", "b");

    // Renewal at half the lease.
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(30)));
    net.settle(secs(30));
    assert_eq!(net.node("b").sent_kinds(OutboundKind::Subscribe), 2);
}

#[test]
fn push_larger_than_one_message_continues() {
    let mut net = Net::new(&["a", "b"]);
    let actions = (COMMAND_RESPONSE_MAX as u64) + 20;
    let g = seeded(&mut net, "a", actions);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.settle(secs(0));
    assert!(net.node("a").sent_kinds(OutboundKind::Push) >= 2);
    net.assert_same_head(g, "a", "b");
    assert_eq!(net.node("b").command_count(g), actions as usize + 1);
}

#[test]
fn push_budget_exhaustion_drops_subscriber() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 16), secs(0))
        .unwrap();
    net.settle(secs(0));
    // The catch-up push would overrun a 16-byte budget: nothing is sent
    // and the subscriber is gone.
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 0);
    net.node("a").action(g, 100, secs(1));
    net.settle(secs(1));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 0);
    assert!(net.node("b").head(g).is_none());
}

#[test]
fn push_unsubscribe_stops_pushes() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.settle(secs(0));
    net.node("b")
        .syncer
        .push_unsubscribe("a", g, secs(1))
        .unwrap();
    net.settle(secs(1));
    assert_eq!(net.node("b").sent_kinds(OutboundKind::Unsubscribe), 1);
    assert_eq!(net.node("b").syncer.next_deadline(), None);
    net.node("a").action(g, 100, secs(2));
    net.settle(secs(2));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 1);
}

#[test]
fn rejected_push_subscribe_is_reported_and_retried() {
    let mut net = Net::new(&["b"]);
    net.nodes.push(Node::with_limits(
        "a",
        Limits::builder().max_push_subs(0).build(),
    ));
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.settle(secs(0));
    assert!(net.node("b").got.contains(&Inbound::SubscribeRejected));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 0);
    // Still tracked: the next renewal tries again.
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(30)));
}

#[test]
fn unsolicited_push_is_ignored() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    // "a" believes "b" subscribed; "b" never asked.
    net.node("a")
        .syncer
        .schedule
        .add_push_subscriber("b", g, secs(60), 1 << 30, secs(0))
        .unwrap();
    net.settle(secs(0));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Push), 1);
    assert_eq!(
        net.node("b").got,
        [Inbound::Ignored(IgnoreReason::NotSubscribed)]
    );
    assert!(net.node("b").head(g).is_none());
}

#[test]
fn push_during_open_poll_session_is_busy() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    // Both directions of a push subscription exist, and "b" also polls.
    net.node("b")
        .syncer
        .schedule
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.node("a")
        .syncer
        .schedule
        .add_push_subscriber("b", g, secs(60), 1 << 30, secs(0))
        .unwrap();
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    // Open the poll session on "b" without answering it.
    let mut saw_poll = false;
    while let Some(ob) = net.node("b").next_outbound(secs(0)).unwrap() {
        if ob.kind() == OutboundKind::PollRequest {
            saw_poll = true;
            break;
        }
        net.node("b")
            .syncer
            .complete(ob.token(), Outcome::Sent, secs(0));
    }
    assert!(saw_poll);
    let push = net.node("a").next_outbound(secs(0)).unwrap().expect("push");
    assert_eq!(push.kind(), OutboundKind::Push);
    let bytes = net.node("a").out[..push.len()].to_vec();
    assert_eq!(
        net.node("b").handle_incoming("a", &bytes, secs(0)).unwrap(),
        Inbound::Ignored(IgnoreReason::Busy)
    );
}

#[test]
fn push_cascades_through_a_chain_and_a_cycle_terminates() {
    let mut net = Net::new(&["a", "b", "c"]);
    let g = seeded(&mut net, "a", 2);
    net.node("b")
        .syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.node("c")
        .syncer
        .push_subscribe("b", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    // And a cycle back to the origin.
    net.node("a")
        .syncer
        .push_subscribe("c", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    net.settle(secs(0));
    net.assert_same_head(g, "a", "b");
    net.assert_same_head(g, "a", "c");

    net.node("a").action(g, 100, secs(5));
    let delivered = net.settle(secs(5));
    assert!(delivered > 0);
    net.assert_same_head(g, "a", "b");
    net.assert_same_head(g, "a", "c");
}

// ---- hello ---------------------------------------------------------------------

fn hello_cfg(debounce: u64, duration: u64, schedule: u64) -> HelloConfig {
    HelloConfig {
        graph_change_delay: secs(debounce),
        duration: secs(duration),
        schedule_delay: secs(schedule),
    }
}

#[test]
fn hello_triggers_a_poll_only_when_something_is_new() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let cfg = PeerConfig {
        interval: None,
        sync_now: false,
        sync_on_hello: true,
    };
    net.node("b").syncer.add_peer("a", g, cfg, secs(0)).unwrap();
    net.node("b")
        .syncer
        .hello_subscribe("a", g, hello_cfg(2, 60, 20), secs(0))
        .unwrap();
    net.settle(secs(0));
    assert_eq!(net.node("b").sent_kinds(OutboundKind::HelloSubscribe), 1);
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 0);

    // A change: hello, then a poll because "b" lacks the head.
    net.node("a").action(g, 100, secs(1));
    net.settle(secs(1));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 1);
    assert_eq!(net.node("b").sent_kinds(OutboundKind::PollRequest), 1);
    net.assert_same_head(g, "a", "b");

    // Inside the debounce: no hello.
    net.node("a").action(g, 101, secs(2));
    net.settle(secs(2));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 1);
    // Past it: hello and poll.
    net.settle(secs(3));
    net.node("a").syncer.notify_local_change(g, secs(3));
    net.settle(secs(3));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 2);
    assert_eq!(net.node("b").sent_kinds(OutboundKind::PollRequest), 2);
    net.assert_same_head(g, "a", "b");

    // Scheduled keepalive with nothing new: hello, no poll.
    net.settle(secs(23));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 3);
    assert_eq!(net.node("b").sent_kinds(OutboundKind::PollRequest), 2);

    // Hello renewal at half the lease.
    net.settle(secs(30));
    assert_eq!(net.node("b").sent_kinds(OutboundKind::HelloSubscribe), 2);
}

#[test]
fn hello_without_sync_on_hello_does_not_poll() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    net.node("b")
        .syncer
        .hello_subscribe("a", g, hello_cfg(1, 60, 20), secs(0))
        .unwrap();
    net.settle(secs(0));
    net.node("a").action(g, 100, secs(1));
    net.settle(secs(1));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 1);
    assert_eq!(net.node("b").sent_kinds(OutboundKind::PollRequest), 0);
    net.node("b")
        .syncer
        .hello_unsubscribe("a", g, secs(2))
        .unwrap();
    net.settle(secs(2));
    assert_eq!(net.node("b").sent_kinds(OutboundKind::HelloUnsubscribe), 1);
    net.node("a").action(g, 101, secs(5));
    net.settle(secs(5));
    assert_eq!(net.node("a").sent_kinds(OutboundKind::Hello), 1);
}

// ---- storage, determinism -------------------------------------------------------

#[test]
fn fixed_slots_drive_the_machine() {
    type Fixed = FixedSlots<Peer, Duration, 2>;
    let mut net = Net::new(&["a", "c"]);
    let g = seeded(&mut net, "a", 3);
    seeded(&mut net, "c", 0);
    let mut b: Node<Fixed> = Node::with_syncer("b", Syncer::new_in(Fixed::new()));
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    assert_eq!(
        b.syncer.add_peer("d", g, PeerConfig::immediate(), secs(0)),
        Err(OutOfSlots)
    );

    // Drive "b" by hand against the network's "a".
    while let Some(ob) = b.next_outbound(secs(0)).unwrap() {
        let dst = *ob.peer();
        let bytes = b.out[..ob.len()].to_vec();
        let inbound = net.node(dst).handle_incoming("b", &bytes, secs(0)).unwrap();
        if ob.expects_reply() {
            let reply = match inbound {
                Inbound::Reply { len } => net.node(dst).out[..len].to_vec(),
                _ => Vec::new(),
            };
            b.handle_reply(ob.token(), &reply, secs(0)).unwrap();
        } else {
            b.syncer.complete(ob.token(), Outcome::Sent, secs(0));
        }
    }
    assert_eq!(b.head(g), net.node("a").head(g));
}

#[test]
fn same_script_yields_the_same_traffic() {
    fn run() -> Vec<(OutboundKind, Peer)> {
        let mut net = Net::new(&["a", "b", "c"]);
        let g = seeded(&mut net, "a", 5);
        net.node("b")
            .syncer
            .add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
            .unwrap();
        net.node("c")
            .syncer
            .push_subscribe("a", g, push_cfg(60, 1 << 30), secs(0))
            .unwrap();
        net.node("c")
            .syncer
            .hello_subscribe("b", g, hello_cfg(1, 60, 7), secs(0))
            .unwrap();
        for t in [0, 3, 7, 10, 14, 20] {
            if t == 3 {
                net.node("a").action(g, 100, secs(t));
            }
            net.settle(secs(t));
        }
        let mut all = Vec::new();
        for node in &net.nodes {
            all.extend(node.sent.iter().copied());
        }
        all
    }
    assert_eq!(run(), run());
}
