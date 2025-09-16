//! The core library for Aranya Fast Channels (AFC).
//!
//! # Overview
//!
//! AFC provides a high-throughput, low latency encryption engine
//! protected by Aranya's policy rules. Data encrypted with (or
//! decrypted by) the engine is sent out of band (not though
//! Aranya itself), making it suitable for encrypting network
//! streams and other high-throughput data.
//!
//! AFC can be configured to use custom cryptography and random
//! number generation.
//!
//! # Usage
//!
//! AFC uses the client-daemon model, with AFC being the
//! "client" and Aranya being the "daemon." However, this is
//! merely a logical distinction; for instance, it's possible for
//! both to be in the same process, just running as different
//! threads (or tasks).
//!
//! All AFC operations are handled by the [`Client`], which
//! communicates with the daemon over [`AfcState`] and
//! [`AranyaState`]. By default, AFC provides a state
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
//! # #[cfg(all(feature = "posix", not(feature = "trng")))]
//! # {
//! use aranya_crypto::{
//!     Csprng, EncryptionKey, Engine, IdentityKey, Random, Rng,
//!     afc::{BidiChannel, BidiKeys, BidiSecrets, RawOpenKey, RawSealKey},
//!     dangerous::spideroak_crypto::rust::HkdfSha256,
//!     default::{DefaultCipherSuite, DefaultEngine},
//!     policy::{CmdId, LabelId},
//! };
//! use aranya_fast_channels::{
//!     AfcState, AranyaState, Channel, ChannelId, Client, Directed, Error,
//!     crypto::Aes256Gcm,
//!     shm::{Flag, Mode, Path, ReadState, WriteState},
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
//!     WriteState::open(path, Flag::Create, Mode::ReadWrite, MAX_CHANS, Rng)
//!         .map_err(Error::SharedMem)?
//! };
//!
//! let aranya_client_b: WriteState<CS, Rng> = {
//!     let path = Path::from_bytes(b"/afc_doc_client_b\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     # aranya_fast_channels::shm::unlink(path);
//!     WriteState::open(path, Flag::Create, Mode::ReadWrite, MAX_CHANS, Rng)
//!         .map_err(Error::SharedMem)?
//! };
//!
//! let (mut eng, _) = E::from_entropy(Rng);
//!
//! let device1_id = IdentityKey::<CS>::new(&mut eng).id()?;
//! let device1_enc_sk = EncryptionKey::<CS>::new(&mut eng);
//!
//! let device2_id = IdentityKey::<CS>::new(&mut eng).id()?;
//! let device2_enc_sk = EncryptionKey::<CS>::new(&mut eng);
//!
//! // The label ID used for encryption and decryption.
//! let label_id = LabelId::random(&mut Rng);
//!
//! let ch1 = BidiChannel {
//!     parent_cmd_id: CmdId::random(&mut eng),
//!     our_sk: &device1_enc_sk,
//!     our_id: device1_id,
//!     their_pk: &device2_enc_sk.public()?,
//!     their_id: device2_id,
//!     label_id,
//! };
//! let BidiSecrets { author, peer } = BidiSecrets::new(&mut eng, &ch1)?;
//!
//! let client_a_channel_id = ChannelId::new(30);
//!
//! // Inform device1 about device2.
//! let (seal, open) = BidiKeys::from_author_secret(&ch1, author)?.into_raw_keys();
//! aranya_client_a.add(
//!     client_a_channel_id,
//!     Directed::Bidirectional { seal, open },
//!     label_id,
//! );
//!
//! let ch2 = BidiChannel {
//!     parent_cmd_id: ch1.parent_cmd_id,
//!     our_sk: &device2_enc_sk,
//!     our_id: device2_id,
//!     their_pk: &device1_enc_sk.public()?,
//!     their_id: device1_id,
//!     label_id,
//! };
//!
//! let client_b_channel_id = ChannelId::new(42);
//!
//! // Inform device2 about device1.
//! let (seal, open) = BidiKeys::from_peer_encap(&ch2, peer)?.into_raw_keys();
//! aranya_client_b.add(
//!     client_b_channel_id,
//!     Directed::Bidirectional { seal, open },
//!     label_id,
//! );
//!
//! let mut afc_client_a = {
//!     let path = Path::from_bytes(b"/afc_doc_client_a\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     let state = ReadState::open(path, Flag::OpenOnly, Mode::ReadWrite, MAX_CHANS)
//!         .map_err(Error::SharedMem)?;
//!     Client::<ReadState<CS>>::new(state)
//! };
//! let mut afc_client_b = {
//!     let path = Path::from_bytes(b"/afc_doc_client_b\x00")
//!         .map_err(|err| Error::SharedMem(err.into()))?;
//!     let state = ReadState::open(path, Flag::OpenOnly, Mode::ReadWrite, MAX_CHANS)
//!         .map_err(Error::SharedMem)?;
//!     Client::<ReadState<CS>>::new(state)
//! };
//!
//! const GOLDEN: &str = "hello from APS!";
//!
//! // Have device1 encrypt data for device2.
//! let ciphertext = {
//!     // Encryption has a little overhead, so make sure the
//!     // ouput buffer is large enough.
//!     let mut dst = vec![0u8; GOLDEN.len() + Client::<ReadState<CS>>::OVERHEAD];
//!     afc_client_a.seal(client_a_channel_id, &mut dst[..], GOLDEN.as_bytes())?;
//!     dst
//! };
//!
//! // Here is where you'd send ciphertext over the network, or
//! // whatever makes sense for your application.
//!
//! // Have device2 decrypt the data from device1.
//! let (seq, plaintext) = {
//!     let mut dst = vec![0u8; ciphertext.len() - Client::<ReadState<CS>>::OVERHEAD];
//!     let (_, seq) = afc_client_b.open(client_b_channel_id, &mut dst[..], &ciphertext[..])?;
//!     (seq, dst)
//! };
//!
//! // TODO(Steve): update?
//! // At this point we can now make a decision on what to do
//! // with plaintext based on the label. We know it came from
//! // `device1` and we know it has the label `label_id`.
//! // Both of those facts (`device1` and `label_id`)
//! // have been cryptographically verified, so we can make
//! // decisions based on them. For example, we could forward the
//! // plaintext data on to another system that ingests "top
//! // secret" data.
//! assert_eq!(seq, 0);
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
#![warn(
    clippy::alloc_instead_of_core,
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
    missing_docs
)]
#![cfg_attr(not(any(feature = "std", test)), deny(clippy::std_instead_of_core))]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "https://github.com/aranya-project/aranya-core/issues/253"
)]

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
