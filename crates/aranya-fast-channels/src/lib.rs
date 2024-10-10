//! `aranya-fast-channels` implements Aranya Fast Channels (AFC).
//!
//! # Overview
//!
//! APS provides a high-throughput, low latency encryption engine
//! protected by Aranya's policy rules. Data encrypted with (or
//! decrypted by) the engine is sent out of band (not though
//! Aranya itself), making it suitable for encrypting network
//! streams and other high-throughput data.
//!
//! APS can be configured to use custom cryptography and random
//! number generation.
//!
//! # Usage
//!
//! APS uses the client-daemon model, with APS being the
//! "client" and Aranya being the "daemon." However, this is
//! merely a logical distinction; for instance, it's possible for
//! both to be in the same process, just running as different
//! threads (or tasks).
//!
//! All APS operations are handled by the [`Client`], which
//! communicates with the daemon over [`AfcState`] and
//! [`AranyaState`]. By default, APS provides a state
//! implementation backed by shared memory.
//!
//! # Example
//!
//! The following example demonstrates two [`Client`]s encrypting
//! data for each other. In practice, the two clients are almost
//! always on different machines. The example also uses shared
//! memory for the state, but in practice anything supported by
//! Aranya can be used.
//!
//! ```
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! # #[cfg(all(feature = "posix", not(feature = "moonshot")))]
//! # {
//! use aranya_fast_channels::{
//!     AfcState,
//!     AranyaState,
//!     Channel,
//!     ChannelId,
//!     Client,
//!     Directed,
//!     Error,
//!     Label,
//!     NodeId,
//!     crypto::Aes256Gcm,
//!     shm::{Flag, Mode, Path, ReadState, WriteState},
//! };
//! use aranya_crypto::{
//!     afc::{
//!         BidiChannel,
//!         BidiKeys,
//!         BidiSecrets,
//!         RawOpenKey,
//!         RawSealKey,
//!     },
//!     Csprng,
//!     EncryptionKey,
//!     Engine,
//!     Id,
//!     IdentityKey,
//!     Random,
//!     Rng,
//!     rust::HkdfSha256,
//!     default::{DefaultCipherSuite, DefaultEngine},
//! };
//!
//! type E = DefaultEngine;
//! type CS = DefaultCipherSuite;
//!
//! // The maximum number of channels supported by the shared
//! // memory.
//! //
//! // You can use any value, this is just an example.
//! const MAX_CHANS: usize = 42;
//!
//! let aranya_client_a: WriteState<CS, Rng> = {
//!     let path = Path::from_bytes(b"/afc_doc_client_a\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     # aranya_fast_channels::shm::unlink(path);
//!     WriteState::open(
//!         path,
//!         Flag::Create,
//!         Mode::ReadWrite,
//!         MAX_CHANS,
//!         Rng,
//!     )
//!     .map_err(Error::SharedMem)?
//! };
//! let user1_node_id = NodeId::new(1);
//!
//! let aranya_client_b: WriteState<CS, Rng> = {
//!     let path = Path::from_bytes(b"/afc_doc_client_b\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     # aranya_fast_channels::shm::unlink(path);
//!     WriteState::open(
//!         path,
//!         Flag::Create,
//!         Mode::ReadWrite,
//!         MAX_CHANS,
//!         Rng,
//!     )
//!     .map_err(Error::SharedMem)?
//! };
//! let user2_node_id = NodeId::new(2);
//!
//! let (mut eng, _) = E::from_entropy(Rng);
//!
//! let user1_id = IdentityKey::<CS>::new(&mut eng).id()?;
//! let user1_enc_sk = EncryptionKey::<CS>::new(&mut eng);
//!
//! let user2_id = IdentityKey::<CS>::new(&mut eng).id()?;
//! let user2_enc_sk = EncryptionKey::<CS>::new(&mut eng);
//!
//! // The label used for encryption and decryption.
//! //
//! // The value (12) should come from the label definition in
//! // the Aranya policy file.
//! const TOP_SECRET: Label = Label::new(12);
//!
//! let ch1 = BidiChannel {
//!     parent_cmd_id: Id::random(&mut eng),
//!     our_sk: &user1_enc_sk,
//!     our_id: user1_id,
//!     their_pk: &user2_enc_sk.public()?,
//!     their_id: user2_id,
//!     label: TOP_SECRET.to_u32(),
//! };
//! let BidiSecrets { author, peer } =
//!     BidiSecrets::new(&mut eng, &ch1)?;
//!
//! // Inform user1 about user2.
//! let (seal, open) = BidiKeys::from_author_secret(&ch1, author)?
//!     .into_raw_keys();
//! aranya_client_a.add(
//!     ChannelId::new(user2_node_id, TOP_SECRET),
//!     Directed::Bidirectional { seal, open },
//! );
//!
//! let ch2 = BidiChannel {
//!     parent_cmd_id: ch1.parent_cmd_id,
//!     our_sk: &user2_enc_sk,
//!     our_id: user2_id,
//!     their_pk: &user1_enc_sk.public()?,
//!     their_id: user1_id,
//!     label: TOP_SECRET.to_u32(),
//! };
//!
//! // Inform user2 about user1.
//! let (seal, open) = BidiKeys::from_peer_encap(&ch2, peer)?
//!     .into_raw_keys();
//! aranya_client_b.add(
//!     ChannelId::new(user1_node_id, TOP_SECRET),
//!     Directed::Bidirectional { seal, open },
//! );
//!
//! let mut afc_client_a = {
//!     let path = Path::from_bytes(b"/afc_doc_client_a\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     let state = ReadState::open(
//!         path,
//!         Flag::OpenOnly,
//!         Mode::ReadWrite,
//!         MAX_CHANS,
//!     )
//!     .map_err(Error::SharedMem)?;
//!     Client::<ReadState<CS>>::new(state)
//! };
//! let mut afc_client_b = {
//!     let path = Path::from_bytes(b"/afc_doc_client_b\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     let state = ReadState::open(
//!         path,
//!         Flag::OpenOnly,
//!         Mode::ReadWrite,
//!         MAX_CHANS,
//!     )
//!     .map_err(Error::SharedMem)?;
//!     Client::<ReadState<CS>>::new(state)
//! };
//!
//! const GOLDEN: &str = "hello from APS!";
//!
//! // Have user1 encrypt data for user2.
//! let ciphertext = {
//!     let id = ChannelId::new(user2_node_id, TOP_SECRET);
//!     // Encryption has a little overhead, so make sure the
//!     // ouput buffer is large enough.
//!     let mut dst = vec![0u8; GOLDEN.len() + Client::<ReadState<CS>>::OVERHEAD];
//!     afc_client_a.seal(id, &mut dst[..], GOLDEN.as_bytes())?;
//!     dst
//! };
//!
//! // Here is where you'd send ciphertext over the network, or
//! // whatever makes sense for your application.
//!
//! // Have user2 decrypt the data from user1.
//! let (label, plaintext) = {
//!     let mut dst = vec![0u8; ciphertext.len() - Client::<ReadState<CS>>::OVERHEAD];
//!     let label = afc_client_b.open(user1_node_id, &mut dst[..], &ciphertext[..])?;
//!     (label, dst)
//! };
//!
//! // At this point we can now make a decision on what to do
//! // with plaintext based on the label. We know it came from
//! // `user1_node_id` and we know it has the label `TOP_SECRET`.
//! // Both of those facts (`user1_node_id` and `TOP_SECRET`)
//! // have been cryptographically verified, so we can make
//! // decisions based on them. For example, we could forward the
//! // plaintext data on to another system that ingests "top
//! // secret" data.
//! assert_eq!(label, TOP_SECRET);
//! assert_eq!(plaintext, GOLDEN.as_bytes());
//!
//! # }
//! # Ok(())
//! # }
//! ```

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(feature = "allocator_api", feature(allocator_api))]
#![cfg_attr(
    feature = "core_intrinsics",
    allow(internal_features),
    feature(core_intrinsics)
)]
#![cfg_attr(feature = "try_find", feature(try_find))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![deny(
    clippy::alloc_instead_of_core,
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::implicit_saturating_sub,
    clippy::ptr_as_ptr,
    clippy::transmute_ptr_to_ptr,
    clippy::wildcard_imports,
    clippy::undocumented_unsafe_blocks,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::string_slice,
    clippy::unimplemented,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![cfg_attr(not(any(feature = "std", test)), deny(clippy::std_instead_of_core))]

#[cfg(feature = "alloc")]
extern crate alloc;

#[macro_use]
mod features;

mod buf;
mod client;
pub mod crypto;
pub mod errno;
mod error;
mod header;
pub mod memory;
mod mutex;
pub mod rust;
pub mod shm;
mod state;
pub mod testing;
mod util;

pub use buf::*;
pub use client::*;
pub use error::*;
pub use header::*;
pub use state::*;
#[cfg(feature = "unsafe_debug")]
pub use util::init_debug_logging;