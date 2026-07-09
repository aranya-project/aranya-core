#![cfg(test)]

use core::cell::RefCell;

use super::*;

type TestSyncer = Syncer<&'static str, Duration>;
type PersistentSyncer = Syncer<String, Duration>;
type FixedSyncer<const N: usize> =
    Syncer<&'static str, Duration, FixedSlots<&'static str, Duration, N>>;

fn gid(n: u8) -> GraphId {
    GraphId::from_bytes([n; 32])
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn owned(peer: &str) -> String {
    String::from(peer)
}

/// Drains every due action, panicking if the drain does not terminate.
fn drain<A: Clone + Ord + fmt::Debug, S: SyncSlots<A, Duration>>(
    syncer: &mut Syncer<A, Duration, S>,
    now: Duration,
) -> Vec<SyncAction<A>> {
    let mut actions = Vec::new();
    for _ in 0..64 {
        match syncer.poll_action(now) {
            Some(action) => actions.push(action),
            None => return actions,
        }
    }
    panic!("drain did not terminate: {actions:?}");
}

#[test]
fn sync_now_fires_immediately_once() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::immediate(), secs(5))
        .unwrap();
    assert_eq!(
        drain(&mut s, secs(5)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(drain(&mut s, secs(100)), []);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn periodic_peer_reschedules() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    // Immediate first poll.
    assert_eq!(drain(&mut s, secs(0)).len(), 1);
    assert_eq!(s.next_deadline(), Some(secs(10)));
    // Nothing fires early.
    assert_eq!(drain(&mut s, secs(9)), []);
    // Due at the interval; reschedules from `now`.
    assert_eq!(
        drain(&mut s, secs(10)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(s.next_deadline(), Some(secs(20)));
}

#[test]
fn interval_without_sync_now_waits_one_period() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    let cfg = PeerConfig {
        interval: Some(secs(10)),
        sync_now: false,
        sync_on_hello: false,
    };
    s.add_peer("a", g, cfg, secs(3)).unwrap();
    assert_eq!(drain(&mut s, secs(3)), []);
    assert_eq!(s.next_deadline(), Some(secs(13)));
}

#[test]
fn sync_now_polls_registered_peer_and_keeps_interval() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    assert!(s.sync_now(&"a", g, secs(2)));
    assert_eq!(
        drain(&mut s, secs(2)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
    // The interval is kept: rescheduled from the manual poll.
    assert_eq!(s.next_deadline(), Some(secs(12)));
    // Unregistered peers are reported.
    assert!(!s.sync_now(&"b", g, secs(2)));
    assert!(!s.sync_now(&"a", gid(2), secs(2)));
}

#[test]
fn sync_now_needs_the_poll_role_not_just_a_slot() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // The pair holds a slot (outbound subscription) but no poll schedule.
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    assert!(!s.sync_now(&"a", g, secs(1)));
    // Only the subscription's work is emitted — no poll.
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::Subscribe {
            peer: "a",
            graph_id: g,
            remain_open_secs: 100,
            max_bytes: 5_000
        }],
    );
}

#[test]
fn remove_peer_cancels_schedule() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    assert!(s.remove_peer(&"a", g));
    assert!(!s.remove_peer(&"a", g));
    assert_eq!(drain(&mut s, secs(0)), []);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn zero_poll_interval_is_floored() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    let cfg = PeerConfig {
        interval: Some(Duration::ZERO),
        sync_now: false,
        sync_on_hello: false,
    };
    s.add_peer("a", g, cfg, secs(0)).unwrap();
    // Floored at the default `min_delay`.
    assert_eq!(s.next_deadline(), Some(DEFAULT_MIN_DELAY));
    // A due poll reschedules a full `min_delay` out, so a drain at a
    // fixed `now` terminates.
    assert_eq!(drain(&mut s, secs(1)).len(), 1);
    assert_eq!(s.next_deadline(), Some(secs(2)));
}

#[test]
fn remote_hello_delays_are_floored_and_drain_terminates() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // A hostile peer supplies zero delays; both are floored at `min_delay`.
    s.add_hello_subscriber("a", g, Duration::ZERO, secs(60), Duration::ZERO, secs(0))
        .unwrap();
    // The scheduled hello is due one floored `schedule_delay` out, and
    // rescheduling pushes it a full `min_delay` ahead: the drain
    // terminates instead of re-firing at `now` forever.
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::SendHello {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(s.next_deadline(), Some(secs(2)));
    // The change debounce is floored too: a change right after the sent
    // hello is suppressed.
    s.notify_local_change(g, secs(1));
    assert_eq!(drain(&mut s, secs(1)), []);
}

#[test]
fn oversized_lifetimes_are_capped() {
    let limits = Limits::builder().max_sub_duration(secs(100)).build();
    let mut s = TestSyncer::with_limits(limits);
    let g = gid(1);
    // Hello `duration` is capped at 100 s: the sub expires (and is
    // silently dropped) at t = 100 despite the far longer request.
    s.add_hello_subscriber("a", g, secs(1), secs(1_000_000), secs(40), secs(0))
        .unwrap();
    assert_eq!(drain(&mut s, secs(40)).len(), 1);
    assert_eq!(drain(&mut s, secs(80)).len(), 1);
    // The next scheduled hello (t = 120) is past expiry: dropped.
    assert_eq!(drain(&mut s, secs(120)), []);
    assert_eq!(s.next_deadline(), None);

    // Push `remain_open` is capped likewise: expired at t = 100.
    s.add_push_subscriber("a", g, secs(1_000_000), 1_000, secs(0))
        .unwrap();
    s.notify_local_change(g, secs(100));
    assert_eq!(drain(&mut s, secs(100)), []);
}

#[test]
fn with_limits_floors_zero_min_delay() {
    let mut s = TestSyncer::with_limits(Limits::builder().min_delay(Duration::ZERO).build());
    let g = gid(1);
    s.add_hello_subscriber("a", g, Duration::ZERO, secs(60), Duration::ZERO, secs(0))
        .unwrap();
    // Even with `min_delay` configured to zero, the 1 ns floor keeps a
    // due hello from rescheduling to `now` forever.
    assert_eq!(drain(&mut s, secs(1)).len(), 1);
    assert_eq!(s.next_deadline(), Some(Duration::new(1, 1)));
}

#[test]
fn subsecond_remain_open_rounds_up_to_one_second() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, Duration::from_millis(300), 1_000, secs(0))
        .unwrap();
    assert_eq!(
        drain(&mut s, secs(0)),
        [SyncAction::Subscribe {
            peer: "a",
            graph_id: g,
            remain_open_secs: 1,
            max_bytes: 1_000
        }],
    );
}

#[test]
fn fractional_remain_open_rounds_up() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, Duration::from_millis(4_200), 1_000, secs(0))
        .unwrap();
    match drain(&mut s, secs(0)).as_slice() {
        [
            SyncAction::Subscribe {
                remain_open_secs: 5,
                ..
            },
        ] => {}
        other => panic!("unexpected actions: {other:?}"),
    }
}

#[test]
fn push_subscriber_cap_and_replace() {
    let limits = Limits::builder().max_push_subs(2).build();
    let mut s = TestSyncer::with_limits(limits);
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.add_push_subscriber("b", g, secs(60), 1_000, secs(0))
        .unwrap();
    // A new key at the cap is rejected...
    assert_eq!(
        s.add_push_subscriber("c", g, secs(60), 1_000, secs(0)),
        Err(SubscriberLimitReached),
    );
    // ...but re-subscribing an existing key replaces in place.
    s.add_push_subscriber("b", g, secs(90), 2_000, secs(0))
        .unwrap();
    // Expired entries are pruned before the cap check: at t = 70 "a"
    // (expiry t = 60) no longer holds a slot.
    s.add_push_subscriber("c", g, secs(60), 1_000, secs(70))
        .unwrap();
    s.notify_local_change(g, secs(70));
    let actions = drain(&mut s, secs(70));
    assert_eq!(actions.len(), 2);
    assert!(actions.contains(&SyncAction::Push {
        peer: "b",
        graph_id: g
    }));
    assert!(actions.contains(&SyncAction::Push {
        peer: "c",
        graph_id: g
    }));
}

#[test]
fn push_budget_exhaustion_drops_subscriber() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 100, secs(0))
        .unwrap();
    s.record_push(&"a", g, 60);
    s.notify_local_change(g, secs(1));
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::Push {
            peer: "a",
            graph_id: g
        }],
    );
    // Over-consumption saturates; the subscription drops at zero.
    s.record_push(&"a", g, 400);
    s.notify_local_change(g, secs(2));
    assert_eq!(drain(&mut s, secs(2)), []);
}

#[test]
fn zero_byte_budget_is_already_exhausted() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 0, secs(0)).unwrap();
    s.notify_local_change(g, secs(1));
    assert_eq!(drain(&mut s, secs(1)), []);
}

#[test]
fn record_push_after_subscriber_left_is_a_noop() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 100, secs(0))
        .unwrap();
    s.notify_local_change(g, secs(1));
    assert_eq!(drain(&mut s, secs(1)).len(), 1);
    // The push completes after the subscriber unsubscribed: the accounting
    // lands on a pair with no slot and changes nothing.
    assert!(s.remove_push_subscriber(&"a", g));
    s.record_push(&"a", g, 60);
    assert_eq!(s.next_deadline(), None);
    s.notify_local_change(g, secs(2));
    assert_eq!(drain(&mut s, secs(2)), []);
}

#[test]
fn record_push_without_the_push_role_keeps_the_slot() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    // Accounting against a pair that only polls: there is no budget to
    // consume, and the slot's other roles are untouched.
    s.record_push(&"a", g, 1_000_000);
    assert_eq!(
        drain(&mut s, secs(0)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
}

#[test]
fn notify_targets_only_the_changed_graph() {
    let mut s = TestSyncer::new();
    s.add_push_subscriber("a", gid(1), secs(60), 1_000, secs(0))
        .unwrap();
    s.add_push_subscriber("a", gid(2), secs(60), 1_000, secs(0))
        .unwrap();
    s.notify_local_change(gid(1), secs(1));
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::Push {
            peer: "a",
            graph_id: gid(1)
        }],
    );
}

#[test]
fn drain_skips_actions_whose_subscription_was_removed() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0))
        .unwrap();
    s.notify_local_change(g, secs(1));
    // Both subscriptions die between the event and the drain.
    s.remove_push_subscriber(&"a", g);
    s.remove_hello_subscriber(&"b", g);
    assert_eq!(drain(&mut s, secs(1)), []);
}

#[test]
fn drain_skips_push_expired_since_enqueue() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(10), 1_000, secs(0))
        .unwrap();
    // Queued while live, drained only after expiry.
    s.notify_local_change(g, secs(9));
    assert_eq!(drain(&mut s, secs(20)), []);
}

#[test]
fn hello_subscriber_cap_and_replace() {
    let limits = Limits::builder().max_hello_subs(1).build();
    let mut s = TestSyncer::with_limits(limits);
    let g = gid(1);
    s.add_hello_subscriber("a", g, secs(1), secs(60), secs(30), secs(0))
        .unwrap();
    assert_eq!(
        s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0)),
        Err(SubscriberLimitReached),
    );
    // Replacing the existing key is allowed at the cap.
    s.add_hello_subscriber("a", g, secs(2), secs(90), secs(45), secs(0))
        .unwrap();
    // Expired entries are pruned before the cap check.
    s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(100))
        .unwrap();
}

#[test]
fn scheduled_hellos_fire_on_cadence_until_expiry() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_hello_subscriber("a", g, secs(1), secs(70), secs(30), secs(0))
        .unwrap();
    assert_eq!(drain(&mut s, secs(29)), []);
    assert_eq!(
        drain(&mut s, secs(30)),
        [SyncAction::SendHello {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(
        drain(&mut s, secs(60)),
        [SyncAction::SendHello {
            peer: "a",
            graph_id: g
        }],
    );
    // The next scheduled hello (t = 90) lands past expiry (t = 70):
    // dropped silently, no farewell hello.
    assert_eq!(drain(&mut s, secs(90)), []);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn change_triggered_hello_respects_debounce() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_hello_subscriber("a", g, secs(10), secs(100), secs(60), secs(0))
        .unwrap();
    // The first change always fires.
    s.notify_local_change(g, secs(1));
    assert_eq!(drain(&mut s, secs(1)).len(), 1);
    // Inside the debounce window: suppressed.
    s.notify_local_change(g, secs(5));
    assert_eq!(drain(&mut s, secs(5)), []);
    // Window over (1 + 10 = 11): fires again.
    s.notify_local_change(g, secs(11));
    assert_eq!(drain(&mut s, secs(11)).len(), 1);
}

#[test]
fn sent_hello_resets_the_scheduled_cadence() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_hello_subscriber("a", g, secs(1), secs(1_000), secs(60), secs(0))
        .unwrap();
    // A change-triggered hello at t = 50...
    s.notify_local_change(g, secs(50));
    assert_eq!(drain(&mut s, secs(50)).len(), 1);
    // ...also satisfies the keepalive: the scheduled hello moves a full
    // period out (t = 110) instead of re-sending the same head at t = 60.
    assert_eq!(s.next_deadline(), Some(secs(110)));
    assert_eq!(drain(&mut s, secs(60)), []);
    assert_eq!(drain(&mut s, secs(110)).len(), 1);
}

#[test]
fn expired_hello_sub_drops_silently_and_scan_continues() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // `schedule_delay >= duration`: the only scheduled hello lands past
    // expiry.
    s.add_hello_subscriber("a", g, secs(1), secs(50), secs(60), secs(0))
        .unwrap();
    // A second, live subscriber whose hello is due *later* than the dead
    // one's timer: the scan must continue past the drop to reach it.
    s.add_hello_subscriber("b", g, secs(1), secs(1_000), secs(70), secs(0))
        .unwrap();
    assert_eq!(
        drain(&mut s, secs(70)),
        [SyncAction::SendHello {
            peer: "b",
            graph_id: g
        }],
    );
    // "a" is gone: no timer left besides "b"'s next hello.
    assert_eq!(s.next_deadline(), Some(secs(140)));
}

#[test]
fn change_triggered_hellos_work_up_to_expiry() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // No keepalive fits before expiry (schedule 60 >= duration 50), but
    // change-triggered hellos keep working for the whole lifetime.
    s.add_hello_subscriber("a", g, secs(1), secs(50), secs(60), secs(0))
        .unwrap();
    s.notify_local_change(g, secs(45));
    assert_eq!(drain(&mut s, secs(45)).len(), 1);
    // At expiry the subscription is gone.
    s.notify_local_change(g, secs(50));
    assert_eq!(drain(&mut s, secs(50)), []);
}

#[test]
fn subscribe_renews_at_half_life_with_stored_params() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    let expected = || SyncAction::Subscribe {
        peer: "a",
        graph_id: g,
        remain_open_secs: 100,
        max_bytes: 5_000,
    };
    assert_eq!(drain(&mut s, secs(0)), [expected()]);
    // The renewal is due at half the lifetime.
    assert_eq!(s.next_deadline(), Some(secs(50)));
    assert_eq!(drain(&mut s, secs(50)), [expected()]);
    // And again, rescheduled from the renewal.
    assert_eq!(s.next_deadline(), Some(secs(100)));
    assert_eq!(drain(&mut s, secs(100)), [expected()]);
}

#[test]
fn too_many_subscriptions_stops_renewals() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    drain(&mut s, secs(0));
    s.on_subscribe_response(&"a", g, SubscribeResponse::TooManySubscriptions);
    assert_eq!(drain(&mut s, secs(500)), []);
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn late_rejection_after_teardown_is_a_noop() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    drain(&mut s, secs(0));
    // A rejection racing an undrained teardown leaves the teardown alone...
    s.unsubscribe("a", g, secs(1)).unwrap();
    s.on_subscribe_response(&"a", g, SubscribeResponse::TooManySubscriptions);
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::Unsubscribe {
            peer: "a",
            graph_id: g
        }],
    );
    // ...and one arriving after the teardown drained (slot gone) is a no-op.
    s.on_subscribe_response(&"a", g, SubscribeResponse::TooManySubscriptions);
    assert_eq!(s.next_deadline(), None);
    assert_eq!(drain(&mut s, secs(500)), []);
}

#[test]
fn success_response_keeps_renewals() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    drain(&mut s, secs(0));
    s.on_subscribe_response(&"a", g, SubscribeResponse::Success);
    assert_eq!(drain(&mut s, secs(50)).len(), 1);
}

#[test]
fn unsubscribe_stops_renewals_and_emits() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    drain(&mut s, secs(0));
    s.unsubscribe("a", g, secs(0)).unwrap();
    assert_eq!(
        drain(&mut s, secs(0)),
        [SyncAction::Unsubscribe {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(drain(&mut s, secs(500)), []);
    // Idempotent teardown: emitted even when untracked.
    s.unsubscribe("a", g, secs(500)).unwrap();
    assert_eq!(
        drain(&mut s, secs(500)),
        [SyncAction::Unsubscribe {
            peer: "a",
            graph_id: g
        }],
    );
}

#[test]
fn resubscribe_before_drain_replaces_teardown() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.subscribe("a", g, secs(100), 5_000, secs(0)).unwrap();
    drain(&mut s, secs(0));
    // Unsubscribe then re-subscribe before a drain: the teardown is
    // superseded — the peer-side subscription is being replaced anyway,
    // so only the new Subscribe goes out.
    s.unsubscribe("a", g, secs(1)).unwrap();
    s.subscribe("a", g, secs(200), 9_000, secs(1)).unwrap();
    assert_eq!(
        drain(&mut s, secs(1)),
        [SyncAction::Subscribe {
            peer: "a",
            graph_id: g,
            remain_open_secs: 200,
            max_bytes: 9_000
        }],
    );
}

#[test]
fn hello_subscribe_renews_blindly() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.hello_subscribe("a", g, secs(5), secs(200), secs(30), secs(0))
        .unwrap();
    let expected = || SyncAction::HelloSubscribe {
        peer: "a",
        graph_id: g,
        graph_change_delay: secs(5),
        duration: secs(200),
        schedule_delay: secs(30),
    };
    assert_eq!(drain(&mut s, secs(0)), [expected()]);
    // No reply is ever fed in; the renewal still fires at half-life.
    assert_eq!(drain(&mut s, secs(100)), [expected()]);
    assert_eq!(s.next_deadline(), Some(secs(200)));
    // Until told to stop.
    s.hello_unsubscribe("a", g, secs(150)).unwrap();
    assert_eq!(
        drain(&mut s, secs(500)),
        [SyncAction::HelloUnsubscribe {
            peer: "a",
            graph_id: g
        }],
    );
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn hello_subscribe_params_are_clamped() {
    let mut s = TestSyncer::with_limits(Limits::builder().max_sub_duration(secs(100)).build());
    let g = gid(1);
    s.hello_subscribe("a", g, Duration::ZERO, secs(1_000), Duration::ZERO, secs(0))
        .unwrap();
    match drain(&mut s, secs(0)).as_slice() {
        [
            SyncAction::HelloSubscribe {
                graph_change_delay,
                duration,
                schedule_delay,
                ..
            },
        ] => {
            assert_eq!(*graph_change_delay, DEFAULT_MIN_DELAY);
            assert_eq!(*duration, secs(100));
            assert_eq!(*schedule_delay, DEFAULT_MIN_DELAY);
        }
        other => panic!("unexpected actions: {other:?}"),
    }
}

#[test]
fn on_hello_polls_only_with_sync_on_hello() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    let armed = PeerConfig {
        interval: None,
        sync_now: false,
        sync_on_hello: true,
    };
    let unarmed = PeerConfig {
        interval: None,
        sync_now: false,
        sync_on_hello: false,
    };
    s.add_peer("a", g, armed, secs(0)).unwrap();
    s.add_peer("b", g, unarmed, secs(0)).unwrap();
    assert!(s.on_hello(&"a", g, secs(5)));
    assert!(!s.on_hello(&"b", g, secs(5)));
    assert!(!s.on_hello(&"unknown", g, secs(5)));
    assert_eq!(
        drain(&mut s, secs(5)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
}

#[test]
fn burst_of_changes_dedupes_to_one_action_per_subscriber() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0))
        .unwrap();
    s.notify_local_change(g, secs(1));
    s.notify_local_change(g, secs(1));
    s.notify_local_change(g, secs(1));
    let actions = drain(&mut s, secs(1));
    assert_eq!(actions.len(), 2);
    assert!(actions.contains(&SyncAction::Push {
        peer: "a",
        graph_id: g
    }));
    assert!(actions.contains(&SyncAction::SendHello {
        peer: "b",
        graph_id: g
    }));
}

#[test]
fn earliest_due_ordering_across_sources() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // Scheduled hello due at t = 30.
    s.add_hello_subscriber("h", g, secs(1), secs(500), secs(30), secs(0))
        .unwrap();
    // Push renewal due at t = 40 (half of 80 s).
    s.subscribe("p", g, secs(80), 1_000, secs(0)).unwrap();
    // Poll due at t = 50.
    let cfg = PeerConfig {
        interval: Some(secs(50)),
        sync_now: false,
        sync_on_hello: false,
    };
    s.add_peer("q", g, cfg, secs(0)).unwrap();
    // The initial Subscribe is due immediately; nothing else is due yet.
    assert_eq!(drain(&mut s, secs(0)).len(), 1);
    assert_eq!(s.next_deadline(), Some(secs(30)));
    // At t = 50 all three are due: earliest-due first.
    assert_eq!(
        drain(&mut s, secs(50)),
        [
            SyncAction::SendHello {
                peer: "h",
                graph_id: g
            },
            SyncAction::Subscribe {
                peer: "p",
                graph_id: g,
                remain_open_secs: 80,
                max_bytes: 1_000
            },
            SyncAction::Poll {
                peer: "q",
                graph_id: g
            },
        ],
    );
}

#[test]
fn next_deadline_sees_one_shot_work() {
    let mut s = TestSyncer::new();
    let g = gid(1);
    // A push queued by a local change.
    s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.notify_local_change(g, secs(2));
    assert_eq!(s.next_deadline(), Some(secs(2)));
    assert_eq!(drain(&mut s, secs(2)).len(), 1);
    // A pending push teardown.
    s.unsubscribe("b", g, secs(3)).unwrap();
    assert_eq!(s.next_deadline(), Some(secs(3)));
    assert_eq!(drain(&mut s, secs(3)).len(), 1);
    // A pending hello teardown.
    s.hello_unsubscribe("c", g, secs(4)).unwrap();
    assert_eq!(s.next_deadline(), Some(secs(4)));
}

#[test]
fn remove_graph_clears_all_state() {
    let mut s = TestSyncer::new();
    let (g1, g2) = (gid(1), gid(2));
    for g in [g1, g2] {
        s.add_peer("peer", g, PeerConfig::periodic(secs(10)), secs(0))
            .unwrap();
        s.add_push_subscriber("sub", g, secs(60), 1_000, secs(0))
            .unwrap();
        s.add_hello_subscriber("sub", g, secs(1), secs(60), secs(30), secs(0))
            .unwrap();
        s.subscribe("req", g, secs(100), 1_000, secs(0)).unwrap();
        s.hello_subscribe("req", g, secs(1), secs(100), secs(10), secs(0))
            .unwrap();
        s.notify_local_change(g, secs(0));
    }
    s.remove_graph(g1);
    // Everything left belongs to g2.
    let actions = drain(&mut s, secs(5));
    assert!(!actions.is_empty());
    assert!(actions.iter().all(|action| action.graph_id() == g2));
    assert!(!s.remove_peer(&"peer", g1));
    assert!(!s.remove_push_subscriber(&"sub", g1));
    assert!(!s.remove_hello_subscriber(&"sub", g1));
}

#[test]
fn fixed_slots_enforce_capacity() {
    let mut s: FixedSyncer<2> = Syncer::new_in(FixedSlots::new());
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    s.add_peer("b", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    // A third pair does not fit...
    assert_eq!(
        s.add_peer("c", g, PeerConfig::periodic(secs(10)), secs(0)),
        Err(OutOfSlots),
    );
    // ...but reconfiguring a registered pair needs no new slot.
    s.add_peer("a", g, PeerConfig::immediate(), secs(0))
        .unwrap();
    // Freeing a slot makes room again.
    assert!(s.remove_peer(&"b", g));
    s.add_peer("c", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
}

#[test]
fn roles_share_one_slot_per_pair() {
    let mut s: FixedSyncer<1> = Syncer::new_in(FixedSlots::new());
    let g = gid(1);
    // Every role for the same (graph, peer) pair fits in the one slot.
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    s.subscribe("a", g, secs(100), 1_000, secs(0)).unwrap();
    s.hello_subscribe("a", g, secs(1), secs(100), secs(10), secs(0))
        .unwrap();
    s.add_push_subscriber("a", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.add_hello_subscriber("a", g, secs(1), secs(60), secs(30), secs(0))
        .unwrap();
    // A different peer does not fit.
    assert_eq!(
        s.add_peer("b", g, PeerConfig::immediate(), secs(0)),
        Err(OutOfSlots),
    );
    // Clearing one role keeps the slot; clearing all frees it.
    assert!(s.remove_push_subscriber(&"a", g));
    assert!(s.remove_hello_subscriber(&"a", g));
    assert!(s.remove_peer(&"a", g));
    assert_eq!(
        s.add_peer("b", g, PeerConfig::immediate(), secs(0)),
        Err(OutOfSlots),
    );
    // The outbound requests still pin the slot until torn down and
    // drained.
    s.unsubscribe("a", g, secs(0)).unwrap();
    s.hello_unsubscribe("a", g, secs(0)).unwrap();
    assert_eq!(drain(&mut s, secs(0)).len(), 2);
    s.add_peer("b", g, PeerConfig::immediate(), secs(0))
        .unwrap();
}

#[test]
fn full_slots_reject_new_subscribers() {
    let mut s: FixedSyncer<1> = Syncer::new_in(FixedSlots::new());
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    // The caps allow more subscribers, but the slots are full: the
    // remote-facing adds report the subscriber limit.
    assert_eq!(
        s.add_push_subscriber("b", g, secs(60), 1_000, secs(0)),
        Err(SubscriberLimitReached),
    );
    assert_eq!(
        s.add_hello_subscriber("b", g, secs(1), secs(60), secs(30), secs(0)),
        Err(SubscriberLimitReached),
    );
    // An untracked teardown needs a slot too.
    assert_eq!(s.unsubscribe("b", g, secs(0)), Err(OutOfSlots));
    assert_eq!(s.hello_unsubscribe("b", g, secs(0)), Err(OutOfSlots));
}

#[test]
fn removing_an_absent_slot_is_a_noop() {
    let mut heap: HeapSlots<&'static str, Duration> = HeapSlots::new();
    heap.remove(gid(1), &"nobody");
    assert!(heap.get(gid(1), &"nobody").is_none());
    let mut fixed: FixedSlots<&'static str, Duration, 2> = FixedSlots::new();
    fixed.remove(gid(1), &"nobody");
    assert!(fixed.get(gid(1), &"nobody").is_none());
}

#[test]
fn fixed_slots_drive_the_machine() {
    // Parity smoke test: the same scheduling flows over caller-supplied
    // fixed storage.
    let mut s: FixedSyncer<4> = Syncer::new_in(FixedSlots::new());
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), secs(0))
        .unwrap();
    s.add_push_subscriber("b", g, secs(60), 1_000, secs(0))
        .unwrap();
    s.add_hello_subscriber("c", g, secs(1), secs(60), secs(30), secs(0))
        .unwrap();
    assert_eq!(
        drain(&mut s, secs(0)),
        [SyncAction::Poll {
            peer: "a",
            graph_id: g
        }],
    );
    s.notify_local_change(g, secs(1));
    assert_eq!(
        drain(&mut s, secs(1)),
        [
            SyncAction::Push {
                peer: "b",
                graph_id: g
            },
            SyncAction::SendHello {
                peer: "c",
                graph_id: g
            },
        ],
    );
    // Poll at t = 10; the hello keepalive was reset to t = 31 by the
    // change-triggered hello.
    assert_eq!(drain(&mut s, secs(10)).len(), 1);
    assert_eq!(s.next_deadline(), Some(secs(20)));
}

/// Milliseconds since an arbitrary origin, as a caller-supplied instant.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Tick(u64);

impl SyncInstant for Tick {
    fn saturating_add(self, d: Duration) -> Self {
        let millis = u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
        Self(self.0.saturating_add(millis))
    }

    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }
}

#[test]
fn drives_a_custom_instant_type() {
    let mut s: Syncer<&'static str, Tick> = Syncer::new();
    let g = gid(1);
    s.add_peer("a", g, PeerConfig::periodic(secs(10)), Tick(500))
        .unwrap();
    assert_eq!(
        s.poll_action(Tick(500)),
        Some(SyncAction::Poll {
            peer: "a",
            graph_id: g
        }),
    );
    assert_eq!(s.poll_action(Tick(500)), None);
    assert_eq!(s.next_deadline(), Some(Tick(10_500)));
    assert_eq!(s.poll_action(Tick(10_499)), None);
    assert!(s.poll_action(Tick(10_500)).is_some());
}

#[test]
fn instant_arithmetic_saturates_at_bounds() {
    // The provided `Duration` impl clamps instead of wrapping/panicking.
    assert_eq!(
        SyncInstant::saturating_add(Duration::MAX, secs(1)),
        Duration::MAX,
    );
    assert_eq!(
        SyncInstant::saturating_duration_since(secs(1), secs(5)),
        Duration::ZERO,
    );
    // So does a custom instant near its bounds.
    assert_eq!(Tick(u64::MAX).saturating_add(secs(1)), Tick(u64::MAX));
    assert_eq!(
        Tick(u64::MAX.saturating_sub(1)).saturating_add(Duration::MAX),
        Tick(u64::MAX),
    );
    assert_eq!(Tick(0).saturating_duration_since(Tick(5)), Duration::ZERO);
}

/// A [`SyncSlots`] implementation that violates the contract: the first
/// `for_each` scan also reports a ghost slot that the keyed lookups cannot
/// see. The trait is caller-supplied, so the machine treats a scan/lookup
/// mismatch as a stale schedule entry to skip — not a panic or a livelock.
struct GhostSlots {
    inner: HeapSlots<&'static str, Duration>,
    ghost: RefCell<Option<SyncSlot<&'static str, Duration>>>,
}

impl SyncSlots<&'static str, Duration> for GhostSlots {
    fn get(
        &self,
        graph_id: GraphId,
        peer: &&'static str,
    ) -> Option<&SyncSlot<&'static str, Duration>> {
        self.inner.get(graph_id, peer)
    }

    fn get_mut(
        &mut self,
        graph_id: GraphId,
        peer: &&'static str,
    ) -> Option<&mut SyncSlot<&'static str, Duration>> {
        self.inner.get_mut(graph_id, peer)
    }

    fn get_or_insert(
        &mut self,
        graph_id: GraphId,
        peer: &&'static str,
    ) -> Result<&mut SyncSlot<&'static str, Duration>, OutOfSlots> {
        self.inner.get_or_insert(graph_id, peer)
    }

    fn remove(&mut self, graph_id: GraphId, peer: &&'static str) {
        self.inner.remove(graph_id, peer);
    }

    fn for_each(&self, mut f: impl FnMut(&SyncSlot<&'static str, Duration>)) {
        self.inner.for_each(&mut f);
        if let Some(ghost) = self.ghost.borrow_mut().take() {
            f(&ghost);
        }
    }

    fn retain(&mut self, f: impl FnMut(&mut SyncSlot<&'static str, Duration>) -> bool) {
        self.inner.retain(f);
    }
}

/// Drives `poll_action` over a table whose scan reported a due `role` for a
/// pair the lookups resolve to nothing — or, with `resolves_to_empty_slot`,
/// to a slot that no longer holds the scanned role. The stale item must be
/// skipped and the drain must terminate.
fn assert_stale_due_item_skipped(
    role: impl FnOnce(&mut SyncSlot<&'static str, Duration>),
    resolves_to_empty_slot: bool,
) {
    let g = gid(9);
    let mut ghost = SyncSlot::new(g, "ghost");
    role(&mut ghost);
    let mut slots = GhostSlots {
        inner: HeapSlots::new(),
        ghost: RefCell::new(Some(ghost)),
    };
    if resolves_to_empty_slot {
        slots
            .get_or_insert(g, &"ghost")
            .expect("heap slots have room");
    }
    let mut s: Syncer<&'static str, Duration, GhostSlots> = Syncer::new_in(slots);
    assert_eq!(s.poll_action(secs(1)), None);
    // The stale item cost nothing: the table still serves real slots
    // through a full lifecycle.
    s.add_peer("real", g, PeerConfig::periodic(secs(10)), secs(1))
        .expect("heap slots have room");
    assert_eq!(
        s.poll_action(secs(1)),
        Some(SyncAction::Poll {
            peer: "real",
            graph_id: g
        }),
    );
    s.notify_local_change(g, secs(1));
    assert!(s.remove_peer(&"real", g));
    assert_eq!(s.next_deadline(), None);
}

#[test]
fn drain_skips_due_item_whose_slot_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.poll = Some(PollState {
                config: PeerConfig::periodic(secs(10)),
                next_sync: Some(Duration::ZERO),
            });
        },
        false,
    );
}

#[test]
fn drain_skips_stale_poll_whose_role_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.poll = Some(PollState {
                config: PeerConfig::periodic(secs(10)),
                next_sync: Some(Duration::ZERO),
            });
        },
        true,
    );
}

#[test]
fn drain_skips_stale_push_renewal_whose_request_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.push_req = Some(PushReq::Active {
                remain_open_secs: 60,
                max_bytes: 1_000,
                renew_at: Duration::ZERO,
            });
        },
        true,
    );
}

#[test]
fn drain_skips_stale_push_cancel_whose_request_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.push_req = Some(PushReq::Cancel {
                due: Duration::ZERO,
            });
        },
        true,
    );
}

#[test]
fn drain_skips_stale_hello_renewal_whose_request_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.hello_req = Some(HelloReq::Active {
                graph_change_delay: secs(1),
                duration: secs(60),
                schedule_delay: secs(30),
                renew_at: Duration::ZERO,
            });
        },
        true,
    );
}

#[test]
fn drain_skips_stale_hello_cancel_whose_request_is_gone() {
    assert_stale_due_item_skipped(
        |slot| {
            slot.hello_req = Some(HelloReq::Cancel {
                due: Duration::ZERO,
            });
        },
        true,
    );
}

#[test]
fn absolute_snapshot_round_trips() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    s.add_peer(owned("a"), g, PeerConfig::periodic(secs(30)), secs(10))
        .unwrap();
    s.subscribe(owned("b"), g, secs(100), 5_000, secs(10))
        .unwrap();
    s.hello_subscribe(owned("c"), g, secs(5), secs(200), secs(20), secs(10))
        .unwrap();
    s.add_push_subscriber(owned("d"), g, secs(300), 9_000, secs(10))
        .unwrap();
    s.add_hello_subscriber(owned("e"), g, secs(5), secs(300), secs(25), secs(10))
        .unwrap();
    // Clear the one-shots (Poll + Subscribe + HelloSubscribe).
    assert_eq!(drain(&mut s, secs(10)).len(), 3);

    let blob = s.save_absolute().unwrap();
    assert_eq!(blob[0], SNAPSHOT_VERSION);
    // `now` is ignored for an absolute blob.
    let mut restored = PersistentSyncer::load(&blob, secs(9_999)).unwrap();
    // Deadlines are preserved exactly; the earliest is the hello sub's
    // first scheduled hello (t = 35).
    assert_eq!(restored.next_deadline(), s.next_deadline());
    assert_eq!(restored.next_deadline(), Some(secs(35)));
    // Restored subscriber state drives: a local change pushes to "d" and
    // hellos "e". The hello fires first — "e"'s scheduled hello (t = 35)
    // was already due before the change.
    restored.notify_local_change(g, secs(36));
    assert_eq!(
        drain(&mut restored, secs(36)),
        [
            SyncAction::SendHello {
                peer: owned("e"),
                graph_id: g
            },
            SyncAction::Push {
                peer: owned("d"),
                graph_id: g
            },
        ],
    );
}

#[test]
fn relative_snapshot_reanchors_offsets() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    let cfg = PeerConfig {
        interval: Some(secs(30)),
        sync_now: false,
        sync_on_hello: false,
    };
    s.add_peer(owned("a"), g, cfg, secs(0)).unwrap();
    s.subscribe(owned("b"), g, secs(100), 5_000, secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    // Saved at t = 20, the poll (t = 30) and renewal (t = 50) become
    // offsets of 10 and 30; loading at t' = 1000 reproduces the spacing.
    let blob = s.save_relative(secs(20)).unwrap();
    let mut restored = PersistentSyncer::load(&blob, secs(1_000)).unwrap();
    assert_eq!(restored.next_deadline(), Some(secs(1_010)));
    assert_eq!(
        drain(&mut restored, secs(1_010)),
        [SyncAction::Poll {
            peer: owned("a"),
            graph_id: g
        }],
    );
    assert_eq!(
        drain(&mut restored, secs(1_030)),
        [SyncAction::Subscribe {
            peer: owned("b"),
            graph_id: g,
            remain_open_secs: 100,
            max_bytes: 5_000
        }],
    );
}

#[test]
fn relative_snapshot_fires_already_due_timers_immediately() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    // Due at t = 5, saved at t = 50: the offset saturates to zero.
    s.add_peer(owned("a"), g, PeerConfig::immediate(), secs(5))
        .unwrap();
    let blob = s.save_relative(secs(50)).unwrap();
    let mut restored = PersistentSyncer::load(&blob, secs(1_000)).unwrap();
    assert_eq!(
        drain(&mut restored, secs(1_000)),
        [SyncAction::Poll {
            peer: owned("a"),
            graph_id: g
        }],
    );
}

#[test]
fn debounce_window_survives_relative_snapshot() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    s.add_hello_subscriber(owned("a"), g, secs(10), secs(600), secs(300), secs(0))
        .unwrap();
    // Fires at t = 0; the debounce window runs to t = 10.
    s.notify_local_change(g, secs(0));
    drain(&mut s, secs(0));
    // Two seconds into the window, snapshot; restore at t' = 100.
    let blob = s.save_relative(secs(2)).unwrap();
    let mut restored = PersistentSyncer::load(&blob, secs(100)).unwrap();
    // Eight seconds of the window remain: still suppressed at t' + 7...
    restored.notify_local_change(g, secs(107));
    assert_eq!(drain(&mut restored, secs(107)), []);
    // ...open again at t' + 8.
    restored.notify_local_change(g, secs(108));
    assert_eq!(
        drain(&mut restored, secs(108)),
        [SyncAction::SendHello {
            peer: owned("a"),
            graph_id: g
        }],
    );
}

#[test]
fn outbound_requests_survive_both_modes_and_renew() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    s.subscribe(owned("a"), g, secs(100), 5_000, secs(0))
        .unwrap();
    s.hello_subscribe(owned("b"), g, secs(5), secs(200), secs(20), secs(0))
        .unwrap();
    drain(&mut s, secs(0));
    let push_renewal = || SyncAction::Subscribe {
        peer: owned("a"),
        graph_id: g,
        remain_open_secs: 100,
        max_bytes: 5_000,
    };
    let hello_renewal = || SyncAction::HelloSubscribe {
        peer: owned("b"),
        graph_id: g,
        graph_change_delay: secs(5),
        duration: secs(200),
        schedule_delay: secs(20),
    };

    let absolute = PersistentSyncer::load(&s.save_absolute().unwrap(), secs(0)).unwrap();
    let relative = PersistentSyncer::load(&s.save_relative(secs(0)).unwrap(), secs(0)).unwrap();
    for mut restored in [absolute, relative] {
        // The push renewal (t = 50) fires, rescheduling itself to t = 100
        // where the hello renewal is also due.
        assert_eq!(drain(&mut restored, secs(50)), [push_renewal()]);
        assert_eq!(
            drain(&mut restored, secs(100)),
            [push_renewal(), hello_renewal()],
        );
    }
}

#[test]
fn pending_actions_are_not_persisted() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    s.add_push_subscriber(owned("a"), g, secs(600), 5_000, secs(0))
        .unwrap();
    // Queued but never drained.
    s.notify_local_change(g, secs(0));
    let blob = s.save_absolute().unwrap();
    let mut restored = PersistentSyncer::load(&blob, secs(0)).unwrap();
    assert_eq!(drain(&mut restored, secs(0)), []);
    // The subscription itself survived; the next change pushes again.
    restored.notify_local_change(g, secs(1));
    assert_eq!(drain(&mut restored, secs(1)).len(), 1);
}

#[test]
fn save_relative_works_without_rkyv_instant_bounds() {
    // `Tick` has no rkyv impls: absolute saves would have to persist
    // `Tick`s and don't compile, but relative saves only store offsets.
    let mut s: Syncer<String, Tick> = Syncer::new();
    let g = gid(1);
    s.add_peer(owned("a"), g, PeerConfig::periodic(secs(30)), Tick(0))
        .unwrap();
    let blob = s.save_relative(Tick(10)).unwrap();
    // A relative blob is instant-agnostic: any rkyv-capable clock can
    // re-anchor it (the poll was already due, so it is due at load).
    let restored: Syncer<String, Duration> = Syncer::load(&blob, Duration::ZERO).unwrap();
    assert_eq!(restored.next_deadline(), Some(Duration::ZERO));
}

#[test]
fn load_requires_capacity_for_the_snapshot() {
    let mut s = PersistentSyncer::new();
    let g = gid(1);
    s.add_peer(owned("a"), g, PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    s.add_peer(owned("b"), g, PeerConfig::periodic(secs(30)), secs(0))
        .unwrap();
    let blob = s.save_absolute().unwrap();
    // Two pairs do not fit in one slot.
    match Syncer::<String, Duration, FixedSlots<String, Duration, 1>>::load_in(
        &blob,
        secs(0),
        FixedSlots::new(),
    ) {
        Err(SnapshotError::OutOfSlots) => {}
        other => panic!("unexpected result: {other:?}"),
    }
    // They fit in two — and any existing contents are cleared first.
    let mut prefilled = FixedSlots::<String, Duration, 2>::new();
    prefilled.get_or_insert(gid(9), &owned("stale")).unwrap();
    let restored = Syncer::<String, Duration, _>::load_in(&blob, secs(0), prefilled).unwrap();
    assert_eq!(restored.next_deadline(), Some(secs(0)));
}

#[test]
fn unknown_snapshot_version_is_rejected_without_decoding() {
    let mut s = PersistentSyncer::new();
    s.add_peer(owned("a"), gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    let mut blob = s.save_absolute().unwrap();
    blob[0] = 99;
    match PersistentSyncer::load(&blob, secs(0)) {
        Err(SnapshotError::UnsupportedVersion(99)) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn corrupt_snapshots_fail_cleanly() {
    // Too short for the header.
    assert!(matches!(
        PersistentSyncer::load(&[], secs(0)),
        Err(SnapshotError::Decode(_)),
    ));
    assert!(matches!(
        PersistentSyncer::load(&[SNAPSHOT_VERSION], secs(0)),
        Err(SnapshotError::Decode(_)),
    ));
    // An unknown timer mode.
    assert!(matches!(
        PersistentSyncer::load(&[SNAPSHOT_VERSION, 9], secs(0)),
        Err(SnapshotError::Decode(_)),
    ));
    // A truncated payload fails validation rather than panicking.
    let mut s = PersistentSyncer::new();
    s.add_peer(owned("a"), gid(1), PeerConfig::immediate(), secs(0))
        .unwrap();
    s.subscribe(owned("b"), gid(1), secs(100), 5_000, secs(0))
        .unwrap();
    let blob = s.save_absolute().unwrap();
    let truncated = &blob[..blob.len().saturating_sub(5)];
    assert!(matches!(
        PersistentSyncer::load(truncated, secs(0)),
        Err(SnapshotError::Decode(_)),
    ));
    // Garbage likewise.
    let mut garbage = vec![SNAPSHOT_VERSION, MODE_ABSOLUTE];
    garbage.extend_from_slice(&[0xAB; 64]);
    assert!(matches!(
        PersistentSyncer::load(&garbage, secs(0)),
        Err(SnapshotError::Decode(_)),
    ));
}
