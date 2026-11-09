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
    MemSpill,
    storage::linear::testing::MemStorageProvider,
    sync::{MAX_SYNC_MESSAGE_SIZE, SubscribeResponse, SyncIncoming},
    testing::protocol::{TestActions, TestPolicyStore, TestSink},
};

type Peer = &'static str;
type Client = ClientState<TestPolicyStore, MemStorageProvider>;
type Segment = <MemStorageProvider as StorageProvider>::Segment;
type Machine<S = HeapSlots<Peer, Duration>> = Syncer<Peer, Duration, S>;

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
            self.sent.push((ob.kind(), *ob.peer()));
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

    fn action(&mut self, graph_id: GraphId, key: u64) {
        self.client
            .action(
                graph_id,
                &mut self.sink,
                TestActions::SetValue(key, key),
                &mut self.buffers,
                spill,
            )
            .expect("action");
    }

    fn head(&mut self, graph_id: GraphId) -> Option<Address> {
        self.client.head_address(graph_id).ok()
    }

    fn polls_sent(&self) -> usize {
        self.sent
            .iter()
            .filter(|(k, _)| *k == OutboundKind::PollRequest)
            .count()
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

    /// Delivers `bytes` from `src` to `dst` and returns the reply bytes.
    fn deliver(&mut self, src: Peer, dst: Peer, bytes: &[u8], now: Duration) -> Vec<u8> {
        let j = self.idx(dst);
        match self.nodes[j]
            .handle_incoming(src, bytes, now)
            .expect("handle_incoming")
        {
            Inbound::Reply { len } => self.nodes[j].out[..len].to_vec(),
            _ => Vec::new(),
        }
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
                    if self.down.contains(&dst) {
                        self.nodes[i]
                            .syncer
                            .complete(ob.token(), Outcome::Failed, now);
                        continue;
                    }
                    let bytes = self.nodes[i].out[..ob.len()].to_vec();
                    let reply = self.deliver(src, dst, &bytes, now);
                    self.nodes[i]
                        .handle_reply(ob.token(), &reply, now)
                        .expect("handle_reply");
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
        node.action(graph_id, i);
    }
    graph_id
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

    net.node("a").action(g, 100);
    assert_eq!(net.settle(secs(10)), 0);
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(30)));
    net.settle(secs(30));
    net.assert_same_head(g, "a", "b");
    assert_eq!(net.node("b").polls_sent(), 2);
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
    net.node("b").syncer.sync_now(&"a", g, secs(1)).unwrap();
    net.settle(secs(1));
    assert_eq!(net.node("b").got, [Inbound::Handled]);
}

#[test]
fn poll_of_a_peer_without_the_graph_is_handled() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    // "a" polls "b", which has never seen the graph.
    net.node("a")
        .syncer
        .add_peer("b", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    net.settle(secs(0));
    assert_eq!(net.node("a").got, [Inbound::Handled]);
    assert_eq!(net.node("b").got, [Inbound::Reply { len: 0 }]);
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
fn reply_timeout_fails_the_request_and_backs_off() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    let ob = b.next_outbound(secs(0)).unwrap().expect("poll request");
    // Waiting on the reply: nothing else fires, not even the interval.
    assert_eq!(b.syncer.next_deadline(), Some(secs(30)));
    assert!(b.next_outbound(secs(29)).unwrap().is_none());
    // Timeout: the request is gone and the peer is backed off.
    assert!(b.next_outbound(secs(30)).unwrap().is_none());
    assert_eq!(b.syncer.next_deadline(), Some(secs(31)));
    assert_eq!(
        b.handle_reply(ob.token(), &[], secs(30)).unwrap(),
        Inbound::Ignored(IgnoreReason::StaleToken)
    );
    let retry = b.next_outbound(secs(31)).unwrap().expect("retry");
    assert_ne!(retry.token(), ob.token());
}

#[test]
fn polls_to_different_peers_overlap() {
    let mut net = Net::new(&["a", "b", "c"]);
    let g = seeded(&mut net, "a", 2);
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let first = b.next_outbound(secs(0)).unwrap().expect("first");
    // A slow first peer does not hold up the second.
    let second = b.next_outbound(secs(0)).unwrap().expect("second");
    assert_ne!(second.peer(), first.peer());
    // Replies may come back in either order.
    let bytes = b.out[..second.len()].to_vec();
    let reply = net.deliver("b", second.peer(), &bytes, secs(0));
    net.node("b")
        .handle_reply(second.token(), &reply, secs(0))
        .unwrap();
    net.node("b")
        .syncer
        .complete(first.token(), Outcome::Failed, secs(0));
    assert_eq!(net.node("b").syncer.next_deadline(), Some(secs(1)));
}

#[test]
fn inflight_cap_limits_concurrent_polls() {
    let mut b = Node::with_limits("b", Limits::builder().max_inflight_polls(1).build());
    let g = GraphId::from_bytes([1; 32]);
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let first = b.next_outbound(secs(0)).unwrap().expect("first");
    assert!(b.next_outbound(secs(0)).unwrap().is_none());
    // The held-back poll is not a deadline: sleep until the timeout.
    assert_eq!(b.syncer.next_deadline(), Some(secs(30)));
    b.syncer.complete(first.token(), Outcome::Failed, secs(0));
    let second = b.next_outbound(secs(0)).unwrap().expect("second");
    assert_ne!(second.peer(), first.peer());
}

#[test]
fn removing_a_peer_mid_poll_frees_its_seat() {
    let mut b = Node::with_limits("b", Limits::builder().max_inflight_polls(1).build());
    let g = GraphId::from_bytes([1; 32]);
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let first = b.next_outbound(secs(0)).unwrap().expect("first");
    b.syncer.remove_peer(first.peer(), g);
    // The other peer is not stuck behind the removed one.
    let second = b.next_outbound(secs(0)).unwrap().expect("second");
    assert_ne!(second.peer(), first.peer());
    assert_eq!(
        b.handle_reply(first.token(), &[], secs(0)).unwrap(),
        Inbound::Ignored(IgnoreReason::StaleToken)
    );
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
fn remove_graph_drops_the_request_in_flight() {
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

#[test]
fn answering_keeps_a_cache_for_the_peer() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 3);
    net.node("b")
        .syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    net.settle(secs(0));
    // Once "b" holds the graph, its next poll's sample tells "a" what it has.
    net.node("a").action(g, 100);
    net.node("b").syncer.sync_now(&"a", g, secs(1)).unwrap();
    net.settle(secs(1));
    // "a" never polls "b", but kept what answering taught it.
    let a = net.node("a");
    assert_eq!(a.syncer.next_deadline(), None);
    assert!(!a.syncer.peer_cache(g, &"b").unwrap().heads().is_empty());
    // Removing the peer forgets the cache.
    a.syncer.remove_peer(&"b", g);
    assert_eq!(a.syncer.schedule.slot_count(), 0);
}

#[test]
fn polls_for_a_graph_we_lack_keep_no_state() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    net.node("a")
        .syncer
        .add_peer("b", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    net.settle(secs(0));
    assert_eq!(net.node("b").got, [Inbound::Reply { len: 0 }]);
    assert_eq!(net.node("b").syncer.schedule.slot_count(), 0);
}

#[test]
fn full_slots_still_answer_polls() {
    type One = FixedSlots<Peer, Duration, 1>;
    let mut net = Net::new(&["b"]);
    let mut a: Node<One> = Node::with_syncer("a", Syncer::new_in(One::new()));
    let g = a.new_graph();
    a.action(g, 1);
    // "a" spends its only slot on polling "c".
    a.syncer
        .add_peer("c", g, PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    let b = net.node("b");
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    let ob = b.next_outbound(secs(0)).unwrap().expect("poll");
    let request = b.out[..ob.len()].to_vec();
    let Inbound::Reply { len } = a.handle_incoming("b", &request, secs(0)).unwrap() else {
        panic!("poll not answered");
    };
    let reply = a.out[..len].to_vec();
    net.node("b")
        .handle_reply(ob.token(), &reply, secs(0))
        .unwrap();
    assert_eq!(net.node("b").head(g), a.head(g));
}

#[test]
fn sync_now_registers_an_unknown_peer() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    net.node("b").syncer.sync_now(&"a", g, secs(0)).unwrap();
    net.settle(secs(0));
    net.assert_same_head(g, "a", "b");
    assert_eq!(net.node("b").syncer.peers().count(), 1);
}

#[test]
fn claiming_more_without_progress_ends_the_catch_up() {
    let mut net = Net::new(&["a", "b"]);
    let g = seeded(&mut net, "a", 2);
    let head = net.node("a").head(g).expect("head");
    let b = net.node("b");
    b.syncer.sync_now(&"a", g, secs(0)).unwrap();
    // "a" answers with only a sample: it claims more but sends nothing.
    let mut first = true;
    while let Some(ob) = b.next_outbound(secs(0)).unwrap() {
        assert!(first, "polled again after a reply that added nothing");
        first = false;
        let Ok(SyncIncoming::Poll(poll)) = SyncIncoming::decode(&b.out[..ob.len()]) else {
            panic!("not a poll");
        };
        let mut sample = heapless::Vec::new();
        sample.push(head).unwrap();
        let message = crate::sync::SyncResponseMessage::SyncResponse {
            session_id: poll.session_id(),
            response_index: 0,
            commands: heapless::Vec::new(),
            sample,
        };
        let mut reply = [0u8; MAX_SYNC_MESSAGE_SIZE];
        let len = postcard::to_slice(&message, &mut reply).unwrap().len();
        assert_eq!(
            b.handle_reply(ob.token(), &reply[..len], secs(0)).unwrap(),
            Inbound::Handled
        );
    }
    assert!(!first);
}

#[test]
fn unsupported_messages_are_ignored() {
    let mut a = Node::new("a");
    let mut msg = [0u8; 64];
    let len = SubscribeResponse::Success.encode_to(&mut msg).unwrap();
    // Not a sync message at all.
    assert!(a.handle_incoming("b", &msg[..len], secs(0)).is_err());
    let len = crate::sync::HelloUnsubscribe::new(GraphId::from_bytes([1; 32]))
        .encode_to(&mut msg)
        .unwrap();
    assert_eq!(
        a.handle_incoming("b", &msg[..len], secs(0)).unwrap(),
        Inbound::Ignored(IgnoreReason::Unsupported)
    );
}

#[test]
fn fixed_slots_drive_the_machine() {
    type Fixed = FixedSlots<Peer, Duration, 2>;
    let mut net = Net::new(&["a", "c"]);
    let g = seeded(&mut net, "a", 3);
    let mut b: Node<Fixed> = Node::with_syncer("b", Syncer::new_in(Fixed::new()));
    b.syncer
        .add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    b.syncer
        .add_peer("c", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    assert_eq!(
        b.syncer.add_peer("d", g, PeerConfig::immediate(), secs(0)),
        Err(OutOfSlots)
    );

    // Drive "b" by hand against the network.
    while let Some(ob) = b.next_outbound(secs(0)).unwrap() {
        let bytes = b.out[..ob.len()].to_vec();
        let reply = net.deliver("b", ob.peer(), &bytes, secs(0));
        b.handle_reply(ob.token(), &reply, secs(0)).unwrap();
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
            .add_peer("b", g, PeerConfig::periodic(secs(7)), secs(0))
            .unwrap();
        for t in [0, 3, 7, 10, 14, 20] {
            if t == 3 {
                net.node("a").action(g, 100);
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
