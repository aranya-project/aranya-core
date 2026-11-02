#![cfg(test)]
#![allow(clippy::arithmetic_side_effects)]

use alloc::vec::Vec;
use core::time::Duration;

use aranya_crypto::Rng;
use proptest::prelude::*;

use super::{
    FixedSlots, HeapSlots, Limits, OutOfSlots, PeerConfig, SyncSlots,
    schedule::{Due, PollResult, Schedule},
    slots::Inflight,
};
use crate::{storage::GraphId, sync::SyncRequester};

type Peer = &'static str;
type Sched = Schedule<Peer, Duration, HeapSlots<Peer, Duration>>;
type FixedSched<const N: usize> = Schedule<Peer, Duration, FixedSlots<Peer, Duration, N>>;

fn sched() -> Sched {
    Schedule::new(Limits::default(), HeapSlots::new())
}

fn sched_with(limits: Limits) -> Sched {
    Schedule::new(limits, HeapSlots::new())
}

fn gid(n: u8) -> GraphId {
    GraphId::from_bytes([n; 32])
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn inflight(graph_id: GraphId, seq: u32, timeout_at: Duration) -> Inflight<Duration> {
    Inflight {
        requester: SyncRequester::new(graph_id, Rng),
        seq,
        timeout_at,
    }
}

/// Drains every due poll, panicking if the drain does not terminate.
fn drain<S: SyncSlots<Peer, Duration>>(
    s: &mut Schedule<Peer, Duration, S>,
    now: Duration,
) -> Vec<Due<Peer>> {
    let mut dues = Vec::new();
    for _ in 0..64 {
        match s.next_due(now) {
            Some(due) => dues.push(due),
            None => {
                assert!(s.deadline_cache_is_consistent(), "stale deadline cache");
                return dues;
            }
        }
    }
    panic!("drain did not terminate: {dues:?}");
}

fn peers_of(dues: &[Due<Peer>]) -> Vec<Peer> {
    dues.iter().map(|d| d.peer).collect()
}

#[test]
fn sync_now_fires_immediately_once() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    assert_eq!(peers_of(&drain(&mut s, secs(0))), ["a"]);
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.next_deadline(), None);
    // The role stays registered for `sync_now`.
    assert_eq!(s.peers().count(), 1);
}

#[test]
fn periodic_peer_reschedules() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    assert_eq!(peers_of(&drain(&mut s, secs(0))), ["a"]);
    assert_eq!(s.next_deadline(), Some(secs(30)));
    assert!(drain(&mut s, secs(29)).is_empty());
    assert_eq!(peers_of(&drain(&mut s, secs(30))), ["a"]);
    assert_eq!(s.next_deadline(), Some(secs(60)));
}

#[test]
fn interval_without_sync_now_waits_one_period() {
    let mut s = sched();
    let cfg = PeerConfig {
        interval: Some(secs(10)),
        sync_now: false,
    };
    s.add_peer("a", gid(1), cfg, secs(5)).unwrap();
    assert!(drain(&mut s, secs(5)).is_empty());
    assert_eq!(s.next_deadline(), Some(secs(15)));
}

#[test]
fn sync_now_polls_registered_peer_and_keeps_interval() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    assert!(s.sync_now(&"a", gid(1), secs(5)));
    assert_eq!(peers_of(&drain(&mut s, secs(5))), ["a"]);
    assert_eq!(s.next_deadline(), Some(secs(35)));
    assert!(!s.sync_now(&"zz", gid(1), secs(5)));
}

#[test]
fn sync_now_during_a_request_follows_its_reply() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 1, secs(30)));
    assert!(s.sync_now(&"a", gid(1), secs(5)));
    // Still awaiting the reply.
    assert!(drain(&mut s, secs(5)).is_empty());
    assert!(s.take_inflight(gid(1), &"a", 1).is_some());
    s.poll_finished(gid(1), &"a", PollResult::Done, secs(6));
    assert_eq!(peers_of(&drain(&mut s, secs(6))), ["a"]);
}

#[test]
fn remove_peer_cancels_schedule_and_request() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 1, secs(30)));
    assert!(s.remove_peer(&"a", gid(1)));
    assert!(!s.remove_peer(&"a", gid(1)));
    assert!(s.take_inflight(gid(1), &"a", 1).is_none());
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.slot_count(), 0);
    assert_eq!(s.inflight_count(), 0);
}

#[test]
fn zero_poll_interval_is_floored() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(Duration::ZERO), secs(0))
        .unwrap();
    assert_eq!(peers_of(&drain(&mut s, secs(0))), ["a"]);
    assert_eq!(s.next_deadline(), Some(secs(1)));
}

#[test]
fn readding_a_peer_keeps_its_request() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 1, secs(30)));
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(10)), secs(1))
        .unwrap();
    // Still awaiting the reply: the poll timer is disarmed, the timeout is
    // armed.
    assert_eq!(s.next_deadline(), Some(secs(30)));
    assert!(s.take_inflight(gid(1), &"a", 1).is_some());
}

#[test]
fn inflight_request_disarms_poll_and_arms_timeout() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 1, secs(30)));
    assert_eq!(s.next_deadline(), Some(secs(30)));
    assert!(drain(&mut s, secs(10)).is_empty());
    // The timeout is applied inside the drain, not reported.
    assert!(drain(&mut s, secs(30)).is_empty());
    assert_eq!(s.inflight_count(), 0);
    // Backoff: min(initial 1 s, interval 10 s) = 1 s.
    assert_eq!(s.next_deadline(), Some(secs(31)));
}

#[test]
fn take_inflight_matches_sequence() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 7, secs(30)));
    assert!(s.take_inflight(gid(1), &"a", 6).is_none());
    assert!(!s.fail_inflight(gid(1), &"a", 6, secs(0)));
    assert!(s.take_inflight(gid(1), &"a", 7).is_some());
    assert!(s.take_inflight(gid(1), &"a", 7).is_none());
}

#[test]
fn more_makes_poll_due_now() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_sent(gid(1), &"a", inflight(gid(1), 1, secs(30)));
    s.take_inflight(gid(1), &"a", 1);
    s.poll_finished(gid(1), &"a", PollResult::More, secs(5));
    assert_eq!(s.next_deadline(), Some(secs(5)));
    assert_eq!(peers_of(&drain(&mut s, secs(5))), ["a"]);
    assert_eq!(s.next_deadline(), Some(secs(65)));
}

#[test]
fn success_resets_backoff() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(0));
    assert_eq!(s.next_deadline(), Some(secs(1)));
    drain(&mut s, secs(1));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(1));
    assert_eq!(s.next_deadline(), Some(secs(3)));
    drain(&mut s, secs(3));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(3));
    assert_eq!(s.next_deadline(), Some(secs(7)));
    drain(&mut s, secs(7));
    s.poll_finished(gid(1), &"a", PollResult::Done, secs(7));
    // Interval reschedule from the fire at 7 s stands.
    assert_eq!(s.next_deadline(), Some(secs(67)));
    drain(&mut s, secs(67));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(67));
    assert_eq!(s.next_deadline(), Some(secs(68)));
}

#[test]
fn backoff_is_capped_by_interval_and_max_backoff() {
    let limits = Limits::builder()
        .initial_backoff(secs(100))
        .max_backoff(secs(150))
        .build();
    let mut s = sched_with(limits);
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(120)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(0));
    assert_eq!(s.next_deadline(), Some(secs(100)));
    drain(&mut s, secs(100));
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(100));
    // 200 s capped by interval 120 s (and max 150 s).
    assert_eq!(s.next_deadline(), Some(secs(220)));

    let mut s = sched_with(limits);
    s.add_peer("b", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_finished(gid(1), &"b", PollResult::Failed, secs(0));
    s.poll_finished(gid(1), &"b", PollResult::Failed, secs(0));
    // One-shot: no interval, so max_backoff 150 s caps it.
    assert_eq!(s.next_deadline(), Some(secs(150)));
}

#[test]
fn one_shot_peer_is_dropped_after_retries() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    for _ in 0..3 {
        s.poll_finished(gid(1), &"a", PollResult::Failed, secs(0));
        assert_eq!(s.peers().count(), 1);
    }
    s.poll_finished(gid(1), &"a", PollResult::Failed, secs(0));
    assert_eq!(s.peers().count(), 0);
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn inflight_cap_holds_back_due_polls() {
    let mut s = sched_with(Limits::builder().max_inflight_polls(2).build());
    for peer in ["a", "b", "c"] {
        s.add_peer(peer, gid(1), PeerConfig::periodic(secs(60)), secs(0))
            .unwrap();
    }
    let a = s.next_due(secs(0)).expect("a");
    s.poll_sent(gid(1), &a.peer, inflight(gid(1), 1, secs(30)));
    let b = s.next_due(secs(0)).expect("b");
    s.poll_sent(gid(1), &b.peer, inflight(gid(1), 2, secs(30)));
    assert_eq!([a.peer, b.peer], ["a", "b"]);
    // "c" is due but held back, and does not count as a deadline.
    assert!(s.next_due(secs(0)).is_none());
    assert_eq!(s.next_deadline(), Some(secs(30)));
    // A reply frees a seat.
    s.take_inflight(gid(1), &"a", 1);
    s.poll_finished(gid(1), &"a", PollResult::Done, secs(1));
    assert_eq!(s.next_deadline(), Some(secs(0)));
    assert_eq!(peers_of(&drain(&mut s, secs(1))), ["c"]);
}

#[test]
fn polls_across_graphs_and_peers_run_concurrently() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    s.add_peer("a", gid(2), PeerConfig::immediate(), secs(0))
        .unwrap();
    s.add_peer("b", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    let mut seq = 0;
    while let Some(due) = s.next_due(secs(0)) {
        seq += 1;
        s.poll_sent(
            due.graph_id,
            &due.peer,
            inflight(due.graph_id, seq, secs(30)),
        );
    }
    assert_eq!(s.inflight_count(), 3);
}

#[test]
fn earliest_due_fires_first() {
    let mut s = sched();
    s.add_peer("late", gid(1), PeerConfig::periodic(secs(5)), secs(0))
        .unwrap();
    s.add_peer("early", gid(1), PeerConfig::periodic(secs(3)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    // Both overdue at 10 s; the one due at 3 s fires first.
    assert_eq!(peers_of(&drain(&mut s, secs(10))), ["early", "late"]);
}

#[test]
fn remove_graph_clears_all_state() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    s.add_peer("a", gid(2), PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    s.remove_graph(gid(1));
    assert_eq!(s.slot_count(), 1);
    assert_eq!(peers_of(&drain(&mut s, secs(0))), ["a"]);
}

#[test]
fn fixed_slots_enforce_capacity() {
    let mut s: FixedSched<2> = Schedule::new(Limits::default(), FixedSlots::new());
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    s.add_peer("b", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    assert_eq!(
        s.add_peer("c", gid(1), PeerConfig::immediate(), secs(0)),
        Err(OutOfSlots)
    );
    // Reconfiguring an existing pair needs no new slot.
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(5)), secs(0))
        .unwrap();
    // Freeing a slot makes room.
    assert!(s.remove_peer(&"b", gid(1)));
    s.add_peer("c", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
}

#[derive(Clone, Debug)]
enum Op {
    AddPeer(u8, u8, Option<u64>, bool),
    RemovePeer(u8, u8),
    SyncNow(u8, u8),
    PollSent(u8, u8, u64),
    Reply(u8, u8, u8),
    Fail(u8, u8),
    Advance(u64),
}

const PEERS: [Peer; 3] = ["p0", "p1", "p2"];

fn op_strategy() -> impl Strategy<Value = Op> {
    let peer = 0..3u8;
    let graph = 1..3u8;
    prop_oneof![
        (
            peer.clone(),
            graph.clone(),
            proptest::option::of(0..20u64),
            any::<bool>()
        )
            .prop_map(|(p, g, iv, now)| Op::AddPeer(p, g, iv, now)),
        (peer.clone(), graph.clone()).prop_map(|(p, g)| Op::RemovePeer(p, g)),
        (peer.clone(), graph.clone()).prop_map(|(p, g)| Op::SyncNow(p, g)),
        (peer.clone(), graph.clone(), 1..10u64).prop_map(|(p, g, t)| Op::PollSent(p, g, t)),
        (peer.clone(), graph.clone(), 0..3u8).prop_map(|(p, g, r)| Op::Reply(p, g, r)),
        (peer, graph).prop_map(|(p, g)| Op::Fail(p, g)),
        (0..10u64).prop_map(Op::Advance),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn random_operations_keep_invariants(ops in proptest::collection::vec(op_strategy(), 1..60)) {
        let mut s = sched_with(Limits::builder().max_inflight_polls(2).build());
        let mut now = Duration::ZERO;
        let mut seq = 0u32;
        for op in ops {
            match op {
                Op::AddPeer(p, g, iv, sync_now) => {
                    let cfg = PeerConfig { interval: iv.map(secs), sync_now };
                    s.add_peer(PEERS[p as usize], gid(g), cfg, now).unwrap();
                }
                Op::RemovePeer(p, g) => { s.remove_peer(&PEERS[p as usize], gid(g)); }
                Op::SyncNow(p, g) => { s.sync_now(&PEERS[p as usize], gid(g), now); }
                Op::PollSent(p, g, t) => {
                    seq += 1;
                    s.poll_sent(gid(g), &PEERS[p as usize], inflight(gid(g), seq, now + secs(t)));
                }
                Op::Reply(p, g, r) => {
                    if s.take_inflight(gid(g), &PEERS[p as usize], seq).is_some() {
                        let result = [PollResult::Done, PollResult::More, PollResult::Failed][r as usize];
                        s.poll_finished(gid(g), &PEERS[p as usize], result, now);
                    }
                }
                Op::Fail(p, g) => { s.fail_inflight(gid(g), &PEERS[p as usize], seq, now); }
                Op::Advance(d) => now += secs(d),
            }
            prop_assert!(s.deadline_cache_is_consistent());
            // Termination: a drain at fixed `now` ends.
            let dues = drain(&mut s, now);
            prop_assert!(dues.len() <= 64);
            // Exactness: after a drain nothing is due at `now`, so a driver
            // sleeping until the deadline never spins.
            if let Some(dl) = s.next_deadline() {
                prop_assert!(dl > now, "deadline {dl:?} not after {now:?}");
            }
        }
    }
}
