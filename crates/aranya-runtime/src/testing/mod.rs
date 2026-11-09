//! Runtime testing support.

#![cfg(any(test, feature = "testing"))]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

pub mod braid;
pub mod dsl;
pub mod protocol;
pub mod vm;

use alloc::{
    format,
    string::{String, ToString as _},
    vec,
};
use core::time::Duration;

use aranya_crypto::Rng;
use buggy::Bug;

use crate::{
    ClientState, CmdId, GraphId, MAX_SYNC_MESSAGE_SIZE, RuntimeBuffers, StorageProvider, SyncError,
    mem_spill,
    policy::{PolicyStore, Sink},
    sync::{Inbound, PeerConfig, SyncContext, Syncer, SyncerError},
};

/// The clock for [`pull_in_process`]. It never advances: every pull is due at
/// once, and nothing times out.
pub const IN_PROCESS_NOW: Duration = Duration::ZERO;

/// One side of a [`pull_in_process`]: a peer id, its syncer, and its client.
pub type Side<'a, A, PS, SP> = (A, &'a mut Syncer<A, Duration>, &'a mut ClientState<PS, SP>);

/// `requester` pulls `graph_id` from `responder` within one process: each
/// request goes straight to the responder's syncer and the reply straight
/// back, until the responder has nothing more to send or `max_exchanges`
/// have run. `on_request` sees each encoded request.
///
/// Both syncers keep their caches for the pair, so later pulls in either
/// direction build on this one. Returns the number of commands committed.
pub fn pull_in_process<A, PS, SP, K>(
    graph_id: GraphId,
    (requester, request_syncer, request_client): Side<'_, A, PS, SP>,
    (responder, response_syncer, response_client): Side<'_, A, PS, SP>,
    sink: &mut K,
    buffers: &mut RuntimeBuffers<SP::Segment>,
    max_exchanges: u64,
    mut on_request: impl FnMut(&[u8]),
) -> Result<usize, SyncerError>
where
    A: Clone + Eq,
    PS: PolicyStore,
    SP: StorageProvider,
    K: Sink<PS::Effect>,
{
    let now = IN_PROCESS_NOW;
    let (mut request, mut reply) = (
        vec![0u8; MAX_SYNC_MESSAGE_SIZE],
        vec![0u8; MAX_SYNC_MESSAGE_SIZE],
    );
    let bug = |msg| SyncerError::from(SyncError::from(Bug::new(msg)));

    request_syncer.sync_now(&responder, graph_id, now)?;

    let mut received = 0usize;
    for _ in 0..max_exchanges {
        let mut cx = SyncContext {
            client: &mut *request_client,
            sink: &mut *sink,
            buffers: &mut *buffers,
            rng: &Rng,
            make_spill: mem_spill,
        };
        let Some(outbound) = request_syncer.next_outbound(now, &mut cx, &mut request)? else {
            break;
        };
        if *outbound.peer() != responder {
            return Err(bug("only the responder is due"));
        }
        let request = request
            .get(..outbound.len())
            .ok_or_else(|| bug("request fits its buffer"))?;
        on_request(request);

        let mut response_cx = SyncContext {
            client: &mut *response_client,
            sink: &mut *sink,
            buffers: &mut *buffers,
            rng: &Rng,
            make_spill: mem_spill,
        };
        let Inbound::Reply { len } = response_syncer.handle_incoming(
            requester.clone(),
            request,
            &mut response_cx,
            &mut reply,
        )?
        else {
            return Err(bug("a poll is answered"));
        };
        let reply = reply
            .get(..len)
            .ok_or_else(|| bug("reply fits its buffer"))?;

        let mut cx = SyncContext {
            client: &mut *request_client,
            sink: &mut *sink,
            buffers: &mut *buffers,
            rng: &Rng,
            make_spill: mem_spill,
        };
        if let Inbound::Committed { count } =
            request_syncer.handle_reply(outbound.into_token(), reply, now, &mut cx)?
        {
            received = received
                .checked_add(count)
                .ok_or_else(|| bug("count fits"))?;
        }
    }
    // Leave nothing due, so a pull cut short by `max_exchanges` does not
    // resume in a later pull with another peer.
    request_syncer.add_peer(responder, graph_id, PeerConfig::default(), now)?;
    Ok(received)
}

/// Derives a [`CmdId`] from some data.
pub fn hash_for_testing_only(data: &[u8]) -> CmdId {
    use aranya_crypto::dangerous::spideroak_crypto::{hash::Hash as _, rust::Sha256};
    Sha256::hash(data).into_array().0.into()
}

pub fn short_b58(id: CmdId) -> String {
    #![allow(clippy::arithmetic_side_effects)]
    let b58 = id.to_string();
    let trimmed = b58.trim_start_matches('1');
    let len = trimmed.len();
    if len == 0 {
        "1".into()
    } else if len > 8 {
        format!("..{}", &trimmed[len - 6..])
    } else {
        trimmed.into()
    }
}
