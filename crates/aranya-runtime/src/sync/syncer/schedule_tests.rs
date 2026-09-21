#![cfg(test)]
#![allow(clippy::arithmetic_side_effects)]

use alloc::vec::Vec;
use core::time::Duration;

use proptest::prelude::*;

use super::{
    FixedSlots, HeapSlots, HelloConfig, Limits, OutOfSlots, PeerConfig, PushConfig, SyncSlots,
    schedule::{Due, Gate, Schedule, SubscriberLimitReached},
    slots::DueKind,
};
use crate::storage::GraphId;

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

fn push_cfg(remain_open: u64) -> PushConfig {
    PushConfig {
        remain_open: secs(remain_open),
        max_bytes: 1 << 20,
    }
}

fn hello_cfg(debounce: u64, duration: u64, schedule: u64) -> HelloConfig {
    HelloConfig {
        graph_change_delay: secs(debounce),
        duration: secs(duration),
        schedule_delay: secs(schedule),
    }
}

/// Drains every due item with open gates, panicking if the drain does not
/// terminate.
fn drain<S: SyncSlots<Peer, Duration>>(
    s: &mut Schedule<Peer, Duration, S>,
    now: Duration,
) -> Vec<Due<Peer>> {
    let mut dues = Vec::new();
    for _ in 0..64 {
        match s.next_due(now, &Gate::Open, &Gate::Open) {
            Some(due) => dues.push(due),
            None => {
                assert!(s.deadline_cache_is_consistent(), "stale deadline cache");
                return dues;
            }
        }
    }
    panic!("drain did not terminate: {dues:?}");
}

fn kinds(dues: &[Due<Peer>]) -> Vec<DueKind> {
    dues.iter().map(|d| d.kind).collect()
}

// ---- poll -----------------------------------------------------------------

#[test]
fn sync_now_fires_immediately_once() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Poll]);
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.next_deadline(), None);
    // The role stays registered for `sync_now` and hello-triggered polls.
    assert_eq!(s.peers().count(), 1);
}

#[test]
fn periodic_peer_reschedules() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Poll]);
    assert_eq!(s.next_deadline(), Some(secs(30)));
    assert!(drain(&mut s, secs(29)).is_empty());
    assert_eq!(kinds(&drain(&mut s, secs(30))), [DueKind::Poll]);
    assert_eq!(s.next_deadline(), Some(secs(60)));
}

#[test]
fn interval_without_sync_now_waits_one_period() {
    let mut s = sched();
    let cfg = PeerConfig {
        interval: Some(secs(10)),
        sync_now: false,
        sync_on_hello: false,
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
    assert_eq!(kinds(&drain(&mut s, secs(5))), [DueKind::Poll]);
    assert_eq!(s.next_deadline(), Some(secs(35)));
    assert!(!s.sync_now(&"zz", gid(1), secs(5)));
}

#[test]
fn remove_peer_cancels_schedule() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    assert!(s.remove_peer(&"a", gid(1)));
    assert!(!s.remove_peer(&"a", gid(1)));
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn zero_poll_interval_is_floored() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(Duration::ZERO), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Poll]);
    assert_eq!(s.next_deadline(), Some(secs(1)));
}

#[test]
fn readding_a_peer_keeps_its_open_session() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_round_sent(gid(1), &"a", secs(30));
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(10)), secs(1))
        .unwrap();
    // Still awaiting the reply: the poll timer is disarmed, the timeout is
    // armed.
    assert_eq!(s.next_deadline(), Some(secs(30)));
}

#[test]
fn inflight_round_disarms_poll_and_arms_timeout() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Poll]);
    s.poll_round_sent(gid(1), &"a", secs(30));
    assert_eq!(s.next_deadline(), Some(secs(30)));
    assert!(drain(&mut s, secs(10)).is_empty());
    assert_eq!(kinds(&drain(&mut s, secs(30))), [DueKind::PollTimeout]);
    // Backoff: min(initial 1 s, interval 10 s) = 1 s.
    assert_eq!(s.next_deadline(), Some(secs(31)));
}

#[test]
fn follow_up_makes_poll_due_now() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_round_sent(gid(1), &"a", secs(30));
    s.poll_follow_up(gid(1), &"a", secs(5));
    assert_eq!(s.next_deadline(), Some(secs(5)));
    assert_eq!(kinds(&drain(&mut s, secs(5))), [DueKind::Poll]);
    assert_eq!(s.next_deadline(), Some(secs(65)));
}

#[test]
fn success_resets_backoff() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(60)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_finished(gid(1), &"a", false, secs(0));
    assert_eq!(s.next_deadline(), Some(secs(1)));
    drain(&mut s, secs(1));
    s.poll_finished(gid(1), &"a", false, secs(1));
    assert_eq!(s.next_deadline(), Some(secs(3)));
    drain(&mut s, secs(3));
    s.poll_finished(gid(1), &"a", false, secs(3));
    assert_eq!(s.next_deadline(), Some(secs(7)));
    drain(&mut s, secs(7));
    s.poll_finished(gid(1), &"a", true, secs(7));
    // Interval reschedule from the fire at 7 s stands.
    assert_eq!(s.next_deadline(), Some(secs(67)));
    drain(&mut s, secs(67));
    s.poll_finished(gid(1), &"a", false, secs(67));
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
    s.poll_finished(gid(1), &"a", false, secs(0));
    assert_eq!(s.next_deadline(), Some(secs(100)));
    drain(&mut s, secs(100));
    s.poll_finished(gid(1), &"a", false, secs(100));
    // 200 s capped by interval 120 s (and max 150 s).
    assert_eq!(s.next_deadline(), Some(secs(220)));

    s.add_peer("b", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.poll_finished(gid(1), &"b", false, secs(0));
    s.poll_finished(gid(1), &"b", false, secs(0));
    // One-shot: no interval, so max_backoff 150 s caps it.
    let b_next = s
        .peers()
        .find(|(_, p, _)| **p == "b")
        .map(|_| s.next_deadline());
    assert_eq!(b_next, Some(Some(secs(150))));
}

#[test]
fn one_shot_peer_is_dropped_after_retries() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    for _ in 0..3 {
        s.poll_finished(gid(1), &"a", false, secs(0));
        assert_eq!(s.peers().count(), 1);
    }
    s.poll_finished(gid(1), &"a", false, secs(0));
    assert_eq!(s.peers().count(), 0);
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn poll_gate_blocks_other_slots() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    s.add_peer("b", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    let gate = Gate::Only(gid(1), "b");
    let due = s.next_due(secs(0), &gate, &Gate::Open).unwrap();
    assert_eq!((due.kind, due.peer), (DueKind::Poll, "b"));
    assert!(s.next_due(secs(0), &gate, &Gate::Open).is_none());
    // "a" is still due once the gate opens.
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Poll]);
}

// ---- push subscriber --------------------------------------------------------

#[test]
fn new_push_subscriber_gets_an_immediate_push() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 1000, secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Push]);
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.push_budget(gid(1), &"a", secs(0)), Some(1000));
}

#[test]
fn push_subscriber_cap_and_replace() {
    let mut s = sched_with(Limits::builder().max_push_subs(1).build());
    s.add_push_subscriber("a", gid(1), secs(60), 10, secs(0))
        .unwrap();
    assert_eq!(
        s.add_push_subscriber("b", gid(1), secs(60), 10, secs(0)),
        Err(SubscriberLimitReached)
    );
    // Replacing does not count against the cap.
    s.add_push_subscriber("a", gid(1), secs(60), 20, secs(0))
        .unwrap();
    assert_eq!(s.push_budget(gid(1), &"a", secs(0)), Some(20));
    // Once "a" expires, "b" fits.
    s.add_push_subscriber("b", gid(1), secs(60), 10, secs(61))
        .unwrap();
}

#[test]
fn push_budget_exhaustion_drops_subscriber() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 100, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.record_push(gid(1), &"a", 60);
    assert_eq!(s.push_budget(gid(1), &"a", secs(1)), Some(40));
    s.record_push(gid(1), &"a", 40);
    assert_eq!(s.push_budget(gid(1), &"a", secs(1)), None);
    s.notify_local_change(gid(1), secs(1));
    assert!(drain(&mut s, secs(1)).is_empty());
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn zero_budget_is_already_exhausted() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 0, secs(0))
        .unwrap();
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn oversized_lifetimes_are_capped() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(10 * 365 * 24 * 3600), 10, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    let year = secs(365 * 24 * 3600);
    assert_eq!(s.push_budget(gid(1), &"a", year - secs(1)), Some(10));
    assert_eq!(s.push_budget(gid(1), &"a", year), None);
}

#[test]
fn notify_targets_only_the_changed_graph() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 10, secs(0))
        .unwrap();
    s.add_push_subscriber("a", gid(2), secs(60), 10, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.notify_local_change(gid(2), secs(1));
    let dues = drain(&mut s, secs(1));
    assert_eq!(dues.len(), 1);
    assert_eq!(dues[0].graph_id, gid(2));
}

#[test]
fn drain_skips_push_expired_since_enqueue() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(10), 10, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.notify_local_change(gid(1), secs(5));
    assert!(drain(&mut s, secs(10)).is_empty());
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn burst_of_changes_dedupes_to_one_push() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 10, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    for t in 1..4 {
        s.notify_local_change(gid(1), secs(t));
    }
    assert_eq!(kinds(&drain(&mut s, secs(3))), [DueKind::Push]);
}

#[test]
fn requeued_push_continues_on_next_drain() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 100, secs(0))
        .unwrap();
    let due = s.next_due(secs(0), &Gate::Open, &Gate::Open).unwrap();
    assert_eq!(due.kind, DueKind::Push);
    s.record_push(gid(1), &"a", 10);
    s.requeue_push(gid(1), &"a", secs(0));
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Push]);
}

#[test]
fn push_gate_blocks_other_slots() {
    let mut s = sched();
    s.add_push_subscriber("a", gid(1), secs(60), 10, secs(0))
        .unwrap();
    s.add_push_subscriber("b", gid(1), secs(60), 10, secs(0))
        .unwrap();
    let gate = Gate::Only(gid(1), "a");
    let due = s.next_due(secs(0), &Gate::Open, &gate).unwrap();
    assert_eq!((due.kind, due.peer), (DueKind::Push, "a"));
    assert!(s.next_due(secs(0), &Gate::Open, &gate).is_none());
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::Push]);
}

// ---- hello subscriber -------------------------------------------------------

#[test]
fn hello_subscriber_cap_and_replace() {
    let mut s = sched_with(Limits::builder().max_hello_subs(1).build());
    s.add_hello_subscriber("a", gid(1), secs(1), secs(60), secs(10), secs(0))
        .unwrap();
    assert_eq!(
        s.add_hello_subscriber("b", gid(1), secs(1), secs(60), secs(10), secs(0)),
        Err(SubscriberLimitReached)
    );
    s.add_hello_subscriber("a", gid(1), secs(1), secs(60), secs(5), secs(0))
        .unwrap();
    assert_eq!(s.next_deadline(), Some(secs(5)));
}

#[test]
fn scheduled_hellos_fire_on_cadence_until_expiry() {
    let mut s = sched();
    s.add_hello_subscriber("a", gid(1), secs(1), secs(25), secs(10), secs(0))
        .unwrap();
    assert!(drain(&mut s, secs(0)).is_empty());
    assert_eq!(kinds(&drain(&mut s, secs(10))), [DueKind::ScheduledHello]);
    assert_eq!(kinds(&drain(&mut s, secs(20))), [DueKind::ScheduledHello]);
    // Expired at 25 s: no farewell hello, slot gone.
    assert!(drain(&mut s, secs(30)).is_empty());
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn change_triggered_hello_respects_debounce() {
    let mut s = sched();
    s.add_hello_subscriber("a", gid(1), secs(5), secs(60), secs(100), secs(0))
        .unwrap();
    s.notify_local_change(gid(1), secs(0));
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::ScheduledHello]);
    s.notify_local_change(gid(1), secs(1));
    assert!(drain(&mut s, secs(1)).is_empty());
    s.notify_local_change(gid(1), secs(5));
    assert_eq!(kinds(&drain(&mut s, secs(5))), [DueKind::ScheduledHello]);
}

#[test]
fn sent_hello_resets_the_scheduled_cadence() {
    let mut s = sched();
    s.add_hello_subscriber("a", gid(1), secs(1), secs(60), secs(10), secs(0))
        .unwrap();
    s.notify_local_change(gid(1), secs(3));
    assert_eq!(kinds(&drain(&mut s, secs(3))), [DueKind::ScheduledHello]);
    assert_eq!(s.next_deadline(), Some(secs(13)));
}

#[test]
fn remote_hello_delays_are_floored_and_drain_terminates() {
    let mut s = sched();
    s.add_hello_subscriber(
        "a",
        gid(1),
        Duration::ZERO,
        secs(60),
        Duration::ZERO,
        secs(0),
    )
    .unwrap();
    s.notify_local_change(gid(1), secs(0));
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::ScheduledHello]);
    assert_eq!(s.next_deadline(), Some(secs(1)));
}

// ---- outbound requests --------------------------------------------------------

#[test]
fn push_subscribe_renews_at_half_life() {
    let mut s = sched();
    s.push_subscribe("a", gid(1), push_cfg(100), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::PushRenewal]);
    assert_eq!(s.push_request_params(gid(1), &"a"), Some((100, 1 << 20)));
    assert_eq!(s.next_deadline(), Some(secs(50)));
    assert_eq!(kinds(&drain(&mut s, secs(50))), [DueKind::PushRenewal]);
}

#[test]
fn subsecond_remain_open_rounds_up_to_one_second() {
    let mut s = sched();
    s.push_subscribe(
        "a",
        gid(1),
        PushConfig {
            remain_open: Duration::from_millis(1),
            max_bytes: 1,
        },
        secs(0),
    )
    .unwrap();
    assert_eq!(s.push_request_params(gid(1), &"a"), Some((1, 1)));
    s.push_subscribe(
        "a",
        gid(1),
        PushConfig {
            remain_open: Duration::from_millis(1500),
            max_bytes: 1,
        },
        secs(0),
    )
    .unwrap();
    assert_eq!(s.push_request_params(gid(1), &"a"), Some((2, 1)));
}

#[test]
fn inflight_push_subscribe_blocks_renewal_until_timeout() {
    let mut s = sched();
    s.push_subscribe("a", gid(1), push_cfg(100), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.push_subscribe_sent(gid(1), &"a", 7, secs(30));
    assert_eq!(s.next_deadline(), Some(secs(30)));
    // The timeout settles silently; renewal at 50 s stands.
    assert!(drain(&mut s, secs(30)).is_empty());
    assert_eq!(s.next_deadline(), Some(secs(50)));
}

#[test]
fn push_subscribe_settled_matches_sequence() {
    let mut s = sched();
    s.push_subscribe("a", gid(1), push_cfg(100), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.push_subscribe_sent(gid(1), &"a", 7, secs(30));
    assert!(!s.push_subscribe_settled(gid(1), &"a", 6));
    assert!(s.push_subscribe_settled(gid(1), &"a", 7));
    assert!(!s.push_subscribe_settled(gid(1), &"a", 7));
    assert_eq!(s.next_deadline(), Some(secs(50)));
}

#[test]
fn push_unsubscribe_emits_once_and_drops() {
    let mut s = sched();
    s.push_subscribe("a", gid(1), push_cfg(100), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.push_unsubscribe("a", gid(1), secs(1)).unwrap();
    assert!(!s.has_active_push_request(gid(1), &"a"));
    assert_eq!(kinds(&drain(&mut s, secs(1))), [DueKind::PushCancel]);
    assert_eq!(s.slot_count(), 0);
    // Idempotent teardown of something never tracked.
    s.push_unsubscribe("b", gid(1), secs(1)).unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(1))), [DueKind::PushCancel]);
}

#[test]
fn resubscribe_before_drain_replaces_teardown() {
    let mut s = sched();
    s.push_unsubscribe("a", gid(1), secs(0)).unwrap();
    s.push_subscribe("a", gid(1), push_cfg(100), secs(0))
        .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::PushRenewal]);
}

#[test]
fn hello_subscribe_renews_blindly_with_clamped_params() {
    let mut s = sched();
    s.hello_subscribe(
        "a",
        gid(1),
        HelloConfig {
            graph_change_delay: Duration::ZERO,
            duration: secs(10 * 365 * 24 * 3600),
            schedule_delay: Duration::ZERO,
        },
        secs(0),
    )
    .unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(0))), [DueKind::HelloRenewal]);
    let cfg = s.hello_request_params(gid(1), &"a").unwrap();
    assert_eq!(cfg.graph_change_delay, secs(1));
    assert_eq!(cfg.schedule_delay, secs(1));
    assert_eq!(cfg.duration, secs(365 * 24 * 3600));
    assert_eq!(s.next_deadline(), Some(secs(365 * 12 * 3600)));
    s.hello_unsubscribe("a", gid(1), secs(5)).unwrap();
    assert_eq!(kinds(&drain(&mut s, secs(5))), [DueKind::HelloCancel]);
    assert_eq!(s.slot_count(), 0);
}

#[test]
fn hello_sync_requires_sync_on_hello() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    let cfg = PeerConfig {
        interval: None,
        sync_now: false,
        sync_on_hello: true,
    };
    s.add_peer("b", gid(1), cfg, secs(0)).unwrap();
    s.hello_subscribe("c", gid(1), hello_cfg(1, 60, 10), secs(0))
        .unwrap();
    assert!(!s.wants_hello_sync(gid(1), &"a"));
    assert!(s.wants_hello_sync(gid(1), &"b"));
    assert!(!s.wants_hello_sync(gid(1), &"c"));
}

// ---- ordering, graphs, storage --------------------------------------------------

#[test]
fn earliest_due_ordering_across_sources() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(7)), secs(0))
        .unwrap();
    drain(&mut s, secs(0)); // poll at 7
    s.add_hello_subscriber("b", gid(1), secs(1), secs(60), secs(5), secs(0))
        .unwrap(); // hello at 5
    s.push_subscribe("c", gid(1), push_cfg(6), secs(0)).unwrap();
    drain(&mut s, secs(0)); // renewal at 3
    s.add_push_subscriber("d", gid(1), secs(60), 10, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    s.notify_local_change(gid(1), secs(4)); // push at 4, hello pulled to 4
    let dues = drain(&mut s, secs(7));
    // Equal deadlines (4 s) fire in slot order: "b" before "d".
    assert_eq!(
        kinds(&dues),
        [
            DueKind::PushRenewal,
            DueKind::ScheduledHello,
            DueKind::Push,
            DueKind::Poll,
        ]
    );
}

#[test]
fn remove_graph_clears_all_state() {
    let mut s = sched();
    s.add_peer("a", gid(1), PeerConfig::periodic(secs(7)), secs(0))
        .unwrap();
    s.add_push_subscriber("b", gid(1), secs(60), 10, secs(0))
        .unwrap();
    s.add_hello_subscriber("c", gid(1), secs(1), secs(60), secs(5), secs(0))
        .unwrap();
    s.push_subscribe("d", gid(1), push_cfg(60), secs(0))
        .unwrap();
    s.add_peer("e", gid(2), PeerConfig::periodic(secs(7)), secs(0))
        .unwrap();
    s.remove_graph(gid(1));
    let dues = drain(&mut s, secs(100));
    assert!(dues.iter().all(|d| d.graph_id == gid(2)), "{dues:?}");
    assert_eq!(s.slot_count(), 1);
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
    assert_eq!(
        s.add_push_subscriber("c", gid(1), secs(60), 10, secs(0)),
        Err(SubscriberLimitReached)
    );
    // Roles share the pair's slot, so this does not need a third.
    s.push_subscribe("a", gid(1), push_cfg(60), secs(0))
        .unwrap();
    assert_eq!(
        kinds(
            &drain(&mut s, secs(0))
                .iter()
                .filter(|d| d.peer == "a")
                .cloned()
                .collect::<Vec<_>>()
        ),
        [DueKind::Poll, DueKind::PushRenewal]
    );
    // Freeing a slot makes room.
    assert!(s.remove_peer(&"b", gid(1)));
    s.add_peer("c", gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
}

// ---- property: drains terminate, deadlines are exact, caches agree --------------

#[derive(Debug, Clone)]
enum Op {
    AddPeer(u8, u8, Option<u64>, bool),
    RemovePeer(u8, u8),
    SyncNow(u8, u8),
    Subscribe(u8, u8, u64),
    Unsubscribe(u8, u8),
    HelloSubscribe(u8, u8, u64, u64, u64),
    AddPushSub(u8, u8, u64, u64),
    AddHelloSub(u8, u8, u64, u64, u64),
    Notify(u8),
    RecordPush(u8, u8, u64),
    PollSent(u8, u8, u64),
    PollFinished(u8, u8, bool),
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
        (peer.clone(), graph.clone(), 0..40u64).prop_map(|(p, g, d)| Op::Subscribe(p, g, d)),
        (peer.clone(), graph.clone()).prop_map(|(p, g)| Op::Unsubscribe(p, g)),
        (peer.clone(), graph.clone(), 0..5u64, 0..40u64, 0..10u64)
            .prop_map(|(p, g, a, b, c)| Op::HelloSubscribe(p, g, a, b, c)),
        (peer.clone(), graph.clone(), 0..40u64, 0..200u64)
            .prop_map(|(p, g, d, b)| Op::AddPushSub(p, g, d, b)),
        (peer.clone(), graph.clone(), 0..5u64, 0..40u64, 0..10u64)
            .prop_map(|(p, g, a, b, c)| Op::AddHelloSub(p, g, a, b, c)),
        graph.clone().prop_map(Op::Notify),
        (peer.clone(), graph.clone(), 0..100u64).prop_map(|(p, g, b)| Op::RecordPush(p, g, b)),
        (peer.clone(), graph.clone(), 1..10u64).prop_map(|(p, g, t)| Op::PollSent(p, g, t)),
        (peer, graph, any::<bool>()).prop_map(|(p, g, ok)| Op::PollFinished(p, g, ok)),
        (0..10u64).prop_map(Op::Advance),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn random_operations_keep_invariants(ops in proptest::collection::vec(op_strategy(), 1..60)) {
        let mut s = sched_with(Limits::builder().max_push_subs(4).max_hello_subs(4).build());
        let mut now = Duration::ZERO;
        for op in ops {
            match op {
                Op::AddPeer(p, g, iv, sync_now) => {
                    let cfg = PeerConfig { interval: iv.map(secs), sync_now, sync_on_hello: false };
                    s.add_peer(PEERS[p as usize], gid(g), cfg, now).unwrap();
                }
                Op::RemovePeer(p, g) => { s.remove_peer(&PEERS[p as usize], gid(g)); }
                Op::SyncNow(p, g) => { s.sync_now(&PEERS[p as usize], gid(g), now); }
                Op::Subscribe(p, g, d) => { s.push_subscribe(PEERS[p as usize], gid(g), push_cfg(d), now).unwrap(); }
                Op::Unsubscribe(p, g) => { s.push_unsubscribe(PEERS[p as usize], gid(g), now).unwrap(); }
                Op::HelloSubscribe(p, g, a, b, c) => {
                    s.hello_subscribe(PEERS[p as usize], gid(g), hello_cfg(a, b, c), now).unwrap();
                }
                Op::AddPushSub(p, g, d, b) => { let _ = s.add_push_subscriber(PEERS[p as usize], gid(g), secs(d), b, now); }
                Op::AddHelloSub(p, g, a, b, c) => {
                    let _ = s.add_hello_subscriber(PEERS[p as usize], gid(g), secs(a), secs(b), secs(c), now);
                }
                Op::Notify(g) => s.notify_local_change(gid(g), now),
                Op::RecordPush(p, g, b) => s.record_push(gid(g), &PEERS[p as usize], b),
                Op::PollSent(p, g, t) => s.poll_round_sent(gid(g), &PEERS[p as usize], now + secs(t)),
                Op::PollFinished(p, g, ok) => s.poll_finished(gid(g), &PEERS[p as usize], ok, now),
                Op::Advance(d) => now += secs(d),
            }
            prop_assert!(s.deadline_cache_is_consistent());
            // Termination: a drain at fixed `now` ends.
            let dues = drain(&mut s, now);
            prop_assert!(dues.len() <= 64);
            // Exactness: after a drain nothing is due at `now`.
            if let Some(dl) = s.next_deadline() {
                prop_assert!(dl > now, "deadline {dl:?} not after {now:?}");
            }
            // Every reported item names a live slot's graph and peer.
            for due in &dues {
                prop_assert!(PEERS.contains(&due.peer));
            }
        }
    }
}
