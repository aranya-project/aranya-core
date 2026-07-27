//! Snapshot persistence for [`Syncer`]: an opaque, versioned rkyv blob.

use alloc::vec::Vec;
use core::{fmt, time::Duration};

use rkyv::{
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    de::Pool,
    rancor::{Error as RancorError, Source as _, Strategy},
    ser::allocator::ArenaHandle,
    util::AlignedVec,
};

use super::{
    HeapSlots, HelloReq, HelloSub, Limits, OutOfSlots, PeerConfig, PollState, PushReq, PushSub,
    SyncInstant, SyncSlots, Syncer,
};
use crate::storage::GraphId;

/// Error from persisting or restoring a [`Syncer`] snapshot
/// ([`save_absolute`](Syncer::save_absolute),
/// [`save_relative`](Syncer::save_relative), [`load`](Syncer::load)).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SnapshotError {
    /// rkyv failed to serialize the state.
    #[error("failed to encode syncer snapshot: {0}")]
    Encode(#[source] rkyv::rancor::Error),
    /// Bytes were truncated/corrupt or failed rkyv `CheckBytes` validation.
    #[error("failed to decode syncer snapshot: {0}")]
    Decode(#[source] rkyv::rancor::Error),
    /// The blob's leading version byte is not one this build reads —
    /// expected after an upgrade that changed the layout; treat as "start
    /// fresh", not as data loss.
    #[error("unsupported syncer snapshot version: {0}")]
    UnsupportedVersion(u8),
    /// The snapshot holds more peer-graph pairs than the provided
    /// [`SyncSlots`] can hold.
    #[error("snapshot does not fit in the provided syncer slots")]
    OutOfSlots,
}

/// Snapshot format version; the blob's first byte. Bump when the layout
/// below changes — rkyv archives are not self-describing.
pub(super) const SNAPSHOT_VERSION: u8 = 1;

/// Timer mode; the blob's second byte. Deadlines stored as `T`.
pub(super) const MODE_ABSOLUTE: u8 = 0;
/// Timer mode; the blob's second byte. Deadlines stored as offsets-from-save.
pub(super) const MODE_RELATIVE: u8 = 1;

impl<A: Clone + Ord, T: SyncInstant> Syncer<A, T> {
    /// Reconstructs a syncer from a snapshot blob into fresh [`HeapSlots`];
    /// see [`load_in`](Self::load_in).
    pub fn load(bytes: &[u8], now: T) -> Result<Self, SnapshotError>
    where
        A: rkyv::Archive,
        A::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<A, Strategy<Pool, RancorError>>,
        T: rkyv::Archive,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<T, Strategy<Pool, RancorError>>,
    {
        Self::load_in(bytes, now, HeapSlots::new())
    }
}

impl<A: Clone + Ord, T: SyncInstant, S: SyncSlots<A, T>> Syncer<A, T, S> {
    /// Serializes durable state — schedules, subscriptions in both
    /// directions, tracked outbound requests, and limits — storing deadlines
    /// **as `T`**, and returns an opaque, versioned blob for
    /// [`load`](Self::load). (Persistence is the one part of the machine
    /// that allocates.)
    ///
    /// Correct only when `T`'s epoch is stable across restarts (wall-clock
    /// instants). **A monotonic `T` saved absolutely reloads as garbage
    /// deadlines after reboot, and `load` cannot detect that** — use
    /// [`save_relative`](Self::save_relative) for monotonic clocks.
    pub fn save_absolute(&self) -> Result<Vec<u8>, SnapshotError>
    where
        A: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
        T: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
    {
        encode(MODE_ABSOLUTE, &self.to_state(|at| at))
    }

    /// Serializes durable state like [`save_absolute`](Self::save_absolute),
    /// but stores each deadline as a [`Duration`] offset from `now`
    /// (already-due deadlines become zero). For process-monotonic clocks:
    /// [`load`](Self::load) re-anchors the offsets onto its own `now`.
    pub fn save_relative(&self, now: T) -> Result<Vec<u8>, SnapshotError>
    where
        A: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
    {
        encode(
            MODE_RELATIVE,
            &self.to_state(|at| at.saturating_duration_since(now)),
        )
    }

    /// Reconstructs a syncer from a snapshot blob, storing its state in the
    /// caller-supplied `slots` (any existing contents are cleared).
    ///
    /// The version and timer mode are read from the blob: absolute deadlines
    /// are used as stored (`now` is ignored), relative offsets re-anchor
    /// onto `now`. The bytes are validated; an unrecognized version is
    /// [`SnapshotError::UnsupportedVersion`] (treat as "start fresh") and a
    /// snapshot with more peer-graph pairs than `slots` can hold is
    /// [`SnapshotError::OutOfSlots`]. Due-but-undrained one-shots are not
    /// persisted; scheduled work regenerates from the restored timers.
    pub fn load_in(bytes: &[u8], now: T, slots: S) -> Result<Self, SnapshotError>
    where
        A: rkyv::Archive,
        A::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<A, Strategy<Pool, RancorError>>,
        T: rkyv::Archive,
        T::Archived: for<'a> CheckBytes<HighValidator<'a, RancorError>>
            + rkyv::Deserialize<T, Strategy<Pool, RancorError>>,
    {
        let Some((&version, rest)) = bytes.split_first() else {
            return Err(truncated());
        };
        if version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(version));
        }
        let Some((&mode, payload)) = rest.split_first() else {
            return Err(truncated());
        };
        // The payload sits at arbitrary alignment inside the blob and rkyv
        // validates alignment, so copy it into aligned storage first.
        let mut aligned = AlignedVec::<16>::new();
        aligned.extend_from_slice(payload);
        match mode {
            MODE_ABSOLUTE => {
                let state = rkyv::from_bytes::<State<A, T>, RancorError>(&aligned)
                    .map_err(SnapshotError::Decode)?;
                Self::from_state(state, |at| at, slots)
            }
            MODE_RELATIVE => {
                let state = rkyv::from_bytes::<State<A, Duration>, RancorError>(&aligned)
                    .map_err(SnapshotError::Decode)?;
                Self::from_state(state, |offset| now.saturating_add(offset), slots)
            }
            unknown => Err(SnapshotError::Decode(RancorError::new(
                BlobFormatError::UnknownMode(unknown),
            ))),
        }
    }

    /// Flattens the durable state into entry vectors, converting each stored
    /// deadline with `conv`. Transient one-shots (queued pushes, pulled-
    /// forward hellos, cancels) are not stored.
    fn to_state<Time>(&self, conv: impl Fn(T) -> Time) -> State<A, Time>
    where
        A: Clone,
    {
        let mut state = State {
            max_push_subs: u64::try_from(self.limits.max_push_subs).unwrap_or(u64::MAX),
            max_hello_subs: u64::try_from(self.limits.max_hello_subs).unwrap_or(u64::MAX),
            min_delay: self.limits.min_delay,
            max_sub_duration: self.limits.max_sub_duration,
            peers: Vec::new(),
            push_subs: Vec::new(),
            hello_subs: Vec::new(),
            push_reqs: Vec::new(),
            hello_reqs: Vec::new(),
        };
        self.slots.for_each(|slot| {
            let graph_id = slot.graph_id();
            if let Some(poll) = &slot.poll {
                state.peers.push(PeerEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    interval: poll.config.interval,
                    sync_now: poll.config.sync_now,
                    sync_on_hello: poll.config.sync_on_hello,
                    next_sync: poll.next_sync.map(&conv),
                });
            }
            if let Some(sub) = &slot.push_sub {
                state.push_subs.push(PushSubEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    expires_at: conv(sub.expires_at),
                    remaining_bytes: sub.remaining_bytes,
                });
            }
            if let Some(sub) = &slot.hello_sub {
                state.hello_subs.push(HelloSubEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    graph_change_debounce: sub.graph_change_debounce,
                    schedule_delay: sub.schedule_delay,
                    next_change_allowed: sub.next_change_allowed.map(&conv),
                    expires_at: conv(sub.expires_at),
                    next_hello: conv(sub.next_hello),
                });
            }
            if let Some(PushReq::Active {
                remain_open_secs,
                max_bytes,
                renew_at,
            }) = &slot.push_req
            {
                state.push_reqs.push(PushReqEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    remain_open_secs: *remain_open_secs,
                    max_bytes: *max_bytes,
                    renew_at: conv(*renew_at),
                });
            }
            if let Some(HelloReq::Active {
                graph_change_delay,
                duration,
                schedule_delay,
                renew_at,
            }) = &slot.hello_req
            {
                state.hello_reqs.push(HelloReqEntry {
                    graph_id,
                    peer: slot.peer().clone(),
                    graph_change_delay: *graph_change_delay,
                    duration: *duration,
                    schedule_delay: *schedule_delay,
                    renew_at: conv(*renew_at),
                });
            }
        });
        state
    }

    /// Rebuilds a syncer from flattened state into `slots`, converting each
    /// stored deadline with `conv`. Delays are re-clamped against the
    /// restored limits so the drain-termination invariant holds even for a
    /// blob this build did not write.
    fn from_state<Time: Copy>(
        state: State<A, Time>,
        conv: impl Fn(Time) -> T,
        slots: S,
    ) -> Result<Self, SnapshotError> {
        let mut syncer = Self::with_limits_in(
            Limits {
                max_push_subs: usize::try_from(state.max_push_subs).unwrap_or(usize::MAX),
                max_hello_subs: usize::try_from(state.max_hello_subs).unwrap_or(usize::MAX),
                min_delay: state.min_delay,
                max_sub_duration: state.max_sub_duration,
            },
            slots,
        );
        syncer.slots.retain(|_| false);
        // `with_limits_in` floored `min_delay`; clamp with what it kept.
        let limits = syncer.limits;
        for entry in state.peers {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.poll = Some(PollState {
                config: PeerConfig {
                    interval: entry.interval.map(|iv| limits.clamp_delay(iv)),
                    sync_now: entry.sync_now,
                    sync_on_hello: entry.sync_on_hello,
                },
                next_sync: entry.next_sync.map(&conv),
            });
        }
        for entry in state.push_subs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.push_sub = Some(PushSub {
                expires_at: conv(entry.expires_at),
                remaining_bytes: entry.remaining_bytes,
                push_due: None,
            });
        }
        for entry in state.hello_subs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.hello_sub = Some(HelloSub {
                graph_change_debounce: limits.clamp_delay(entry.graph_change_debounce),
                schedule_delay: limits.clamp_delay(entry.schedule_delay),
                next_change_allowed: entry.next_change_allowed.map(&conv),
                expires_at: conv(entry.expires_at),
                next_hello: conv(entry.next_hello),
            });
        }
        for entry in state.push_reqs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.push_req = Some(PushReq::Active {
                remain_open_secs: entry.remain_open_secs.max(1),
                max_bytes: entry.max_bytes,
                renew_at: conv(entry.renew_at),
            });
        }
        for entry in state.hello_reqs {
            let slot = syncer
                .slots
                .get_or_insert(entry.graph_id, &entry.peer)
                .map_err(|OutOfSlots| SnapshotError::OutOfSlots)?;
            slot.hello_req = Some(HelloReq::Active {
                graph_change_delay: limits.clamp_delay(entry.graph_change_delay),
                duration: limits.clamp_lifetime(entry.duration),
                schedule_delay: limits.clamp_delay(entry.schedule_delay),
                renew_at: conv(entry.renew_at),
            });
        }
        Ok(syncer)
    }
}

/// A snapshot blob defect detected before rkyv validation.
#[derive(Debug)]
enum BlobFormatError {
    /// Shorter than the version + mode header.
    Truncated,
    /// The mode byte is neither absolute nor relative.
    UnknownMode(u8),
}

impl fmt::Display for BlobFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "snapshot shorter than its header"),
            Self::UnknownMode(mode) => write!(f, "unknown snapshot timer mode: {mode}"),
        }
    }
}

impl core::error::Error for BlobFormatError {}

fn truncated() -> SnapshotError {
    SnapshotError::Decode(RancorError::new(BlobFormatError::Truncated))
}

/// Prepends the version and mode header to the rkyv-serialized `state`.
fn encode<S>(mode: u8, state: &S) -> Result<Vec<u8>, SnapshotError>
where
    S: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, RancorError>>,
{
    let payload = rkyv::to_bytes::<RancorError>(state).map_err(SnapshotError::Encode)?;
    let mut blob = Vec::with_capacity(payload.len().saturating_add(2));
    blob.push(SNAPSHOT_VERSION);
    blob.push(mode);
    blob.extend_from_slice(&payload);
    Ok(blob)
}

/// Durable state flattened for rkyv, with deadlines of type `Time` (`T` in
/// an absolute snapshot, offset [`Duration`]s in a relative one). Stored as
/// per-role entry vectors and rebuilt on load, sidestepping archived-map
/// key-ordering constraints.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct State<A, Time> {
    max_push_subs: u64,
    max_hello_subs: u64,
    min_delay: Duration,
    max_sub_duration: Duration,
    peers: Vec<PeerEntry<A, Time>>,
    push_subs: Vec<PushSubEntry<A, Time>>,
    hello_subs: Vec<HelloSubEntry<A, Time>>,
    push_reqs: Vec<PushReqEntry<A, Time>>,
    hello_reqs: Vec<HelloReqEntry<A, Time>>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PeerEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    interval: Option<Duration>,
    sync_now: bool,
    sync_on_hello: bool,
    next_sync: Option<Time>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PushSubEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    expires_at: Time,
    remaining_bytes: u64,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct HelloSubEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    graph_change_debounce: Duration,
    schedule_delay: Duration,
    next_change_allowed: Option<Time>,
    expires_at: Time,
    next_hello: Time,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct PushReqEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    remain_open_secs: u64,
    max_bytes: u64,
    renew_at: Time,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
struct HelloReqEntry<A, Time> {
    graph_id: GraphId,
    peer: A,
    graph_change_delay: Duration,
    duration: Duration,
    schedule_delay: Duration,
    renew_at: Time,
}
