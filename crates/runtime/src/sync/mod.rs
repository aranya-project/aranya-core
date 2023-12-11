//! Interface for syncing state between clients.

// use std::sync::{Arc, Mutex};
use alloc::{sync::Arc, vec};
use core::mem;

use buggy::{Bug, BugExt};
use heapless::Vec;
use postcard::{from_bytes, take_from_bytes, to_slice, Error as PostcardError};
use serde::{Deserialize, Serialize};
use spin::Mutex;

use crate::{
    command::{Command, Id, Priority},
    engine::EngineError,
    storage::{Location, Segment, Storage, StorageError, StorageProvider, MAX_COMMAND_LENGTH},
    ClientError, Prior, Sink,
};

// TODO: These should all be compile time parameters

/// The maximum number of samples in a request
const COMMAND_SAMPLE_MAX: usize = 100;

/// The maximum number of missing segments that can be requested
/// in a single message
const REQUEST_MISSING_MAX: usize = 100;

/// The maximum number of commands in a response
const COMMAND_RESPONSE_MAX: usize = 100;

/// The maximum number of segments which can be stored to send
const SEGMENT_BUFFER_MAX: usize = 100;

/// The maximum size of a sync message
// TODO: Use postcard to calculate max size (which accounts for overhead)
// https://docs.rs/postcard/latest/postcard/experimental/max_size/index.html
pub const MAX_SYNC_MESSAGE_SIZE: usize = 1024 + MAX_COMMAND_LENGTH * COMMAND_RESPONSE_MAX;

/// Represents high-level data of a command.
#[derive(Serialize, Deserialize, Debug)]
pub struct CommandMeta {
    priority: Priority,
    parent: Prior<Id>,
    policy_length: u32,
    length: u32,
}

// TODO: Use compile-time args. This initial definition results in this clippy warning:
// https://rust-lang.github.io/rust-clippy/master/index.html#large_enum_variant.
// As the buffer consts will be compile-time variables in the future, we will be
// able to tune these buffers for smaller footprints. Right now, this enum is not
// suitable for small devices (`SyncResponse` is 8448 bytes).
#[derive(Serialize, Deserialize, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SyncMessage {
    /// Initiate a new Sync
    SyncRequest {
        /// A new random value produced by a cryptographically secure RNG.
        session_id: u128,
        /// Specifies the graph to be synced.
        storage_id: Id,
        /// Specifies the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
        /// Sample of the commands held by the requester. The responder should
        /// respond with any commands that the requester may not have based on
        /// the provided sample. When sending commands ancestors must be sent
        /// before descendents.
        commands: Vec<Id, COMMAND_SAMPLE_MAX>,
    },

    /// Sent in response to a `SyncRequest`
    SyncResponse {
        /// A random-value produced by a cryptographically secure RNG.
        session_id: u128,
        /// If the responder intends to send a value of command bytes
        /// greater than the responder's configured maximum, the responder
        /// will send more than one `SyncResponse`. The first message has an
        /// index of 1, and each following is incremented.
        index: u64,
        /// Commands that the responder believes the requester does not have.
        commands: Vec<CommandMeta, COMMAND_RESPONSE_MAX>,
    },

    /// End a sync session if `SyncRequest.max_bytes` has been reached or
    /// there are no remaining commands to send.
    SyncEnd {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Largest index of any `SyncResponse`
        max_index: u64,
        /// Set `true` if this message was sent due to reaching the `max_bytes`
        /// budget.
        remaining: bool,
    },

    /// Sent by the requester if it deduces a `SyncResponse` message has been
    /// dropped.
    RequestMissing {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// `SyncResponse` indexes that the requester has not received.
        indexes: Vec<u64, REQUEST_MISSING_MAX>,
    },

    /// Message to request the responder resumes sending `SyncResponse`s
    /// following the specified message. This may be sent after a requester
    /// timeout or after a `SyncEnd` has been sent.
    SyncResume {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Indicates the last response message the requester received.
        response_index: u64,
        /// Updates the maximum number of bytes worth of commands that
        /// the requester wishes to receive.
        max_bytes: u64,
    },

    /// Message sent by a responder after a sync has been completed, but before
    /// the session has ended, if it has new commands in it's graph. If a
    /// requester wishes to respond to this message, it should do so with a
    /// new `SyncRequest`. This message may use the existing `session_id`.
    Offer {
        /// A random-value produced by a cryptographically secure RNG
        /// corresponding to the `session_id` in the initial `SyncRequest`.
        session_id: u128,
        /// Head of the branch the responder wishes to send.
        head: Id,
    },

    /// Message sent by either requester or responder to indicate the session
    /// has been terminated or the `session_id` is no longer valid.
    EndSession { session_id: u128 },
}

impl SyncMessage {
    pub fn session_id(&self) -> u128 {
        match self {
            SyncMessage::SyncRequest { session_id, .. } => *session_id,
            SyncMessage::SyncResponse { session_id, .. } => *session_id,
            SyncMessage::SyncEnd { session_id, .. } => *session_id,
            SyncMessage::RequestMissing { session_id, .. } => *session_id,
            SyncMessage::SyncResume { session_id, .. } => *session_id,
            SyncMessage::Offer { session_id, .. } => *session_id,
            SyncMessage::EndSession { session_id, .. } => *session_id,
        }
    }
}

#[derive(Debug)]
pub enum SyncError {
    UnexpectedMessage,
    SessionMismatch,
    MissingSyncResponse,
    SessionState,
    StorageError,
    InternalError,
    NotReady,
    SerilizeError,
    EngineError,
    NetworkError,
    ClientError,
    CryptoError,
    Bug(Bug),
}

use core::convert::Infallible;

impl From<Bug> for SyncError {
    fn from(error: Bug) -> Self {
        SyncError::Bug(error)
    }
}

impl From<Infallible> for SyncError {
    fn from(_error: Infallible) -> Self {
        SyncError::InternalError
    }
}

impl From<StorageError> for SyncError {
    fn from(_error: StorageError) -> Self {
        SyncError::StorageError
    }
}

impl From<EngineError> for SyncError {
    fn from(_error: EngineError) -> Self {
        SyncError::EngineError
    }
}

impl From<PostcardError> for SyncError {
    fn from(_error: PostcardError) -> Self {
        SyncError::SerilizeError
    }
}

impl From<ClientError> for SyncError {
    fn from(_error: ClientError) -> Self {
        SyncError::ClientError
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SyncCommand<'a> {
    priority: Priority,
    id: Id,
    parent: Prior<Id>,
    policy: Option<&'a [u8]>,
    data: &'a [u8],
}

impl<'a> Command<'a> for SyncCommand<'a> {
    fn priority(&self) -> Priority {
        self.priority.clone()
    }

    fn id(&self) -> Id {
        self.id
    }

    fn parent(&self) -> Prior<Id> {
        self.parent
    }

    fn policy(&self) -> Option<&'a [u8]> {
        self.policy
    }

    fn bytes(&self) -> &'a [u8] {
        self.data
    }
}

pub trait SyncState {
    /// Return thge session id for this state;
    fn session_id(&self) -> u128;

    /// Receive a sync message. Returns an option
    /// of a slive of up parsed protocol messages.
    fn receive<'a>(
        &mut self,
        message: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError>;

    /// Returns true if poll would proxuce a message.
    fn ready(&self) -> bool;

    /// Write a syc message in to the target buffer. Returns the number
    /// of bytes written.
    fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRequesterState {
    New,
    Start,
    Waiting,
    Idle,
    Closed,
    Resync,
    PartialSync,
    Reset,
}

// The length of the Out Of Order buffer
const OOO_LEN: usize = 4;
pub struct SyncRequester<'a> {
    session_id: u128,
    storage_id: Id,
    state: SyncRequesterState,
    max_bytes: u64,
    next_index: u64,
    #[allow(unused)] // TODO(jdygert): Figure out what this is for...
    ooo_buffer: [Option<&'a [u8]>; OOO_LEN],
}

impl SyncRequester<'_> {
    pub fn new(session_id: u128, storage_id: Id) -> Self {
        SyncRequester {
            session_id,
            storage_id,
            state: SyncRequesterState::New,
            max_bytes: 0,
            next_index: 0,
            ooo_buffer: core::array::from_fn(|_| None),
        }
    }

    pub fn end_session(session_id: u128, target: &mut [u8]) -> Result<usize, SyncError> {
        let message = SyncMessage::EndSession { session_id };

        let written = to_slice(&message, target)?;

        Ok(written.len())
    }

    fn resume(&mut self, max_bytes: u64, target: &mut [u8]) -> Result<usize, SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Resync | SyncRequesterState::Idle
        ) {
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Waiting;
        let message = SyncMessage::SyncResume {
            session_id: self.session_id,
            response_index: self
                .next_index
                .checked_sub(1)
                .assume("next_index must be positive")?,
            max_bytes,
        };

        let written = to_slice(&message, target)?;

        Ok(written.len())
    }

    fn start(
        &mut self,
        max_bytes: u64,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        if !matches!(
            self.state,
            SyncRequesterState::Start | SyncRequesterState::New
        ) {
            self.state = SyncRequesterState::Reset;
            return Err(SyncError::SessionState);
        }

        self.state = SyncRequesterState::Start;
        self.max_bytes = max_bytes;

        let mut commands: Vec<Id, COMMAND_SAMPLE_MAX> = Vec::new();

        match provider.get_storage(&self.storage_id) {
            Err(StorageError::NoSuchStorage) => (),
            Err(_) => {
                return Err(SyncError::StorageError);
            }
            Ok(storage) => {
                let head = storage.get_head()?;

                let mut current = vec![head];

                // Here we just get the first command from the most reaseant
                // COMMAND_SAMPLE_MAX segments in the graph. This is probbly
                // not the best strategy as if you are far enough ahead of
                // the other client they will just send you everything they have.
                while commands.len() < COMMAND_SAMPLE_MAX && !current.is_empty() {
                    let mut next = alloc::vec::Vec::new(); //BUG not constant memory

                    'current: for location in &current {
                        let segment = storage.get_segment(location)?;

                        let head = segment.head();
                        if commands.push(head.id()).is_err() {
                            // This should be impossible
                            return Err(SyncError::InternalError);
                        }
                        next.extend(segment.prior());
                        if commands.len() >= COMMAND_SAMPLE_MAX {
                            break 'current;
                        }
                    }

                    current = next.to_vec();
                }
            }
        }

        let message = SyncMessage::SyncRequest {
            session_id: self.session_id,
            storage_id: self.storage_id,
            max_bytes,
            commands,
        };

        let written = to_slice(&message, target)?;

        Ok(written.len())
    }
}

impl SyncState for SyncRequester<'_> {
    fn session_id(&self) -> u128 {
        self.session_id
    }

    fn receive<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError> {
        let (message, remaining): (SyncMessage, &'a [u8]) = take_from_bytes(data)?;

        if message.session_id() != self.session_id {
            return Err(SyncError::SessionMismatch);
        }

        let result = match message {
            SyncMessage::SyncResponse {
                index, commands, ..
            } => {
                if !matches!(
                    self.state,
                    SyncRequesterState::Start | SyncRequesterState::Waiting
                ) {
                    return Err(SyncError::SessionState);
                }

                if index != self.next_index {
                    self.state = SyncRequesterState::Resync;
                    return Err(SyncError::MissingSyncResponse);
                }
                self.next_index = self
                    .next_index
                    .checked_add(1)
                    .assume("next_index + 1 mustn't overflow")?;
                self.state = SyncRequesterState::Waiting;

                let mut result = Vec::new();
                let mut start: usize = 0;
                for meta in commands {
                    let policy_len = meta.policy_length as usize;

                    let policy = match policy_len == 0 {
                        true => None,
                        false => {
                            let end = start
                                .checked_add(policy_len)
                                .assume("start + policy_len mustn't overflow")?;
                            let policy = &remaining[start..end];
                            start = end;
                            Some(policy)
                        }
                    };

                    let len = meta.length as usize;
                    let end = start
                        .checked_add(len)
                        .assume("start + len mustn't overflow")?;
                    let payload = &remaining[start..end];
                    start = end;

                    // TODO(eric): fix this
                    let id = Id::hash_for_testing_only(payload);

                    let command = SyncCommand {
                        id,
                        priority: meta.priority,
                        parent: meta.parent,
                        policy,
                        data: payload,
                    };

                    result.push(command).or(Err(SyncError::InternalError))?;
                }

                Some(result)
            }

            SyncMessage::SyncEnd { max_index, .. } => {
                if !matches!(
                    self.state,
                    SyncRequesterState::Start | SyncRequesterState::Waiting
                ) {
                    return Err(SyncError::SessionState);
                }

                if max_index
                    != self
                        .next_index
                        .checked_sub(1)
                        .assume("next_index must be positive")?
                {
                    self.state = SyncRequesterState::Resync;
                    return Err(SyncError::MissingSyncResponse);
                }

                self.state = SyncRequesterState::PartialSync;

                None
            }

            SyncMessage::Offer { .. } => {
                if self.state != SyncRequesterState::Idle {
                    return Err(SyncError::SessionState);
                }
                self.state = SyncRequesterState::Resync;

                None
            }

            SyncMessage::EndSession { .. } => {
                self.state = SyncRequesterState::Closed;
                None
            }

            _ => {
                self.state = SyncRequesterState::Reset;
                return Err(SyncError::UnexpectedMessage);
            }
        };

        Ok(result)
    }

    fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        use SyncRequesterState as S;
        let result = match self.state {
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => {
                return Err(SyncError::NotReady)
            }
            S::New => {
                self.state = S::Start;
                self.start(self.max_bytes, target, provider)?
            }
            S::Resync => self.resume(self.max_bytes, target)?,
            S::Reset => {
                self.state = S::Closed;
                Self::end_session(self.session_id, target)?
            }
        };

        Ok(result)
    }

    fn ready(&self) -> bool {
        use SyncRequesterState as S;
        match self.state {
            S::New | S::Resync | S::Reset => true,
            S::Start | S::Waiting | S::Idle | S::Closed | S::PartialSync => false,
        }
    }
}

#[derive(Debug)]
enum SyncResponderState {
    New,
    Start,
    Send,
    Idle,
    Reset,
    Stopped,
}

pub struct SyncResponder {
    session_id: u128,
    storage_id: Option<Id>,
    state: SyncResponderState,
    bytes_sent: u64,
    next_send: usize,
    has: Vec<Id, COMMAND_SAMPLE_MAX>,
    to_send: Vec<Location, SEGMENT_BUFFER_MAX>,
}

impl SyncResponder {
    pub fn new(session_id: u128) -> Self {
        SyncResponder {
            session_id,
            storage_id: None,
            state: SyncResponderState::New,
            bytes_sent: 0,
            next_send: 0,
            has: Vec::new(),
            to_send: Vec::new(),
        }
    }

    fn find_needed_segments(
        commands: &[Id],
        storage: &impl Storage,
    ) -> Result<Vec<Location, SEGMENT_BUFFER_MAX>, SyncError> {
        let mut have_locations = alloc::vec::Vec::new(); //BUG: not constant size
        for id in commands {
            let Some(location) = storage.get_location(id)? else {
                // Note: We could use things we don't
                // have as a hint to know we should
                // preform a sync request.
                continue;
            };

            have_locations.push(location);
        }

        let mut heads = alloc::vec::Vec::new();
        heads.push(storage.get_head()?);

        let mut result = Vec::new();

        while !heads.is_empty() {
            let current = mem::take(&mut heads);
            'heads: for head in current {
                let segment = storage.get_segment(&head)?;

                for location in &have_locations {
                    if segment.contains(location) {
                        if location != &segment.head_location() {
                            result
                                .push(location.clone())
                                .or(Err(SyncError::InternalError))?;
                        }
                        continue 'heads;
                    }
                }
                heads.extend(segment.prior());

                let location = segment.first_location();
                result.push(location).or(Err(SyncError::InternalError))?;
            }
        }
        result.reverse();
        Ok(result)
    }

    fn get_next(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        let Some(storage_id) = self.storage_id.as_ref() else {
            self.state = SyncResponderState::Reset;
            return Err(SyncError::InternalError);
        };

        let storage = match provider.get_storage(storage_id) {
            Ok(s) => s,
            Err(e) => {
                self.state = SyncResponderState::Reset;
                return Err(e.into());
            }
        };

        let index = self.next_send;
        self.next_send = self
            .next_send
            .checked_add(1)
            .assume("next_send + 1 mustn't overflow")?;

        if self.next_send >= self.to_send.len() {
            self.state = SyncResponderState::Idle;
        }

        let Some(location) = self.to_send.get(index) else {
            self.state = SyncResponderState::Reset;
            return Err(SyncError::InternalError);
        };

        let Ok(segment) = storage.get_segment(location) else {
            self.state = SyncResponderState::Reset;
            return Err(SyncError::StorageError);
        };

        let found = segment.get_from(location);

        let mut commands = Vec::new();
        for command in &found {
            let mut policy_length = 0;

            if let Some(policy) = command.policy() {
                policy_length = policy.len() as u32;
            }

            let meta = CommandMeta {
                priority: command.priority(),
                parent: command.parent(),
                policy_length,
                length: command.bytes().len() as u32,
            };

            // FIXME(jdygert): This will reasonably happen, should not just error.
            commands.push(meta).or(Err(SyncError::InternalError))?;
        }

        let message = SyncMessage::SyncResponse {
            session_id: self.session_id,
            index: index as u64,
            commands,
        };

        let mut length = write(target, message)?;

        for command in found {
            if let Some(policy) = command.policy() {
                let end = length
                    .checked_add(policy.len())
                    .assume("length + policy.len() mustn't overflow")?;
                target[length..end].clone_from_slice(policy);
                length = end;
            }

            let bytes = command.bytes();

            let end = length
                .checked_add(bytes.len())
                .assume("length + bytes.len() mustn't overflow")?;
            target[length..end].clone_from_slice(bytes);
            length = end;
        }

        Ok(length)
    }
}

impl SyncState for SyncResponder {
    fn session_id(&self) -> u128 {
        self.session_id
    }

    fn receive<'a>(
        &mut self,
        data: &'a [u8],
    ) -> Result<Option<Vec<SyncCommand<'a>, COMMAND_RESPONSE_MAX>>, SyncError> {
        use SyncMessage::*;

        let message: SyncMessage = from_bytes(data)?;

        match message {
            // We should not receive these.
            SyncResponse { .. } | SyncEnd { .. } | Offer { .. } => {
                self.state = SyncResponderState::Reset;
            }

            SyncRequest {
                storage_id,
                max_bytes,
                commands,
                ..
            } => {
                self.state = SyncResponderState::Start;
                self.storage_id = Some(storage_id);
                self.bytes_sent = max_bytes;
                self.to_send = Vec::new();
                self.has = commands;
                self.next_send = 0;
            }
            RequestMissing { .. } => {
                todo!()
            }
            SyncResume { .. } => {
                todo!()
            }
            EndSession { .. } => {
                self.state = SyncResponderState::Stopped;
            }
        };

        Ok(None)
    }

    fn ready(&self) -> bool {
        use SyncResponderState::*;
        match self.state {
            Reset | Start | Send => true,
            New | Idle | Stopped => false,
        }
    }

    fn poll(
        &mut self,
        target: &mut [u8],
        provider: &mut impl StorageProvider,
    ) -> Result<usize, SyncError> {
        use SyncResponderState as S;
        let length = match self.state {
            S::New | S::Idle | S::Stopped => {
                return Err(SyncError::NotReady);
            }
            S::Start => {
                let Some(storage_id) = self.storage_id.as_ref() else {
                    self.state = S::Reset;
                    return Err(SyncError::InternalError);
                };

                let storage = match provider.get_storage(storage_id) {
                    Ok(s) => s,
                    Err(e) => {
                        self.state = S::Reset;
                        return Err(e.into());
                    }
                };

                self.state = S::Send;
                self.to_send = SyncResponder::find_needed_segments(&self.has, storage)?;

                self.get_next(target, provider)?
            }
            S::Send => self.get_next(target, provider)?,
            S::Reset => {
                self.state = S::Stopped;
                let message = SyncMessage::EndSession {
                    session_id: self.session_id,
                };
                write(target, message)?
            }
        };

        Ok(length)
    }
}

fn write(target: &mut [u8], message: SyncMessage) -> Result<usize, SyncError> {
    let written = to_slice(&message, target)?;

    Ok(written.len())
}

/// Wraps a Sink in an Arc<Mutex<>>
///
/// Many of our APIs expect a sink. When using multithreaded code it's necessary to
/// wrap the Sink in an Arc<Mutex<>>. WrappedSink functions as a sink while locking
/// the Arc<Mutex<>> as necessary. This allows our APIs to work in single and
/// multithreaded environments.
#[derive(Debug)]
pub struct LockedSink<T> {
    sink: Arc<Mutex<T>>,
}

impl<T> Clone for LockedSink<T> {
    fn clone(&self) -> Self {
        LockedSink::new(self.sink.clone())
    }
}

impl<T> LockedSink<T> {
    pub fn new(sink: Arc<Mutex<T>>) -> LockedSink<T> {
        LockedSink { sink }
    }
}

/// Keeps track of the expectations needed for tests.
pub trait Expectation<E> {
    /// Adds a new expectation
    fn add_expectation(&mut self, expect: E);
    /// Returns the number of expections that have not been used.
    fn count(&self) -> usize;
}

impl<T, E> Expectation<E> for LockedSink<T>
where
    T: Sink<E> + Expectation<E>,
{
    fn add_expectation(&mut self, expect: E) {
        let mut s = self.sink.lock();
        s.add_expectation(expect)
    }

    fn count(&self) -> usize {
        let s = self.sink.lock();
        s.count()
    }
}

impl<T, E> Sink<E> for LockedSink<T>
where
    T: Sink<E>,
{
    fn begin(&mut self) {
        let mut s = self.sink.lock();
        s.begin()
    }

    fn consume(&mut self, effect: E) {
        let mut s = self.sink.lock();
        s.consume(effect);
    }

    fn rollback(&mut self) {
        let mut s = self.sink.lock();
        s.rollback()
    }

    fn commit(&mut self) {
        let mut s = self.sink.lock();
        s.commit()
    }
}
