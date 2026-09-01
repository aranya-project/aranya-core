#[doc(inline)]
pub use aranya_crypto::afc::Seq;
use aranya_crypto::{
    afc::{AuthData, OpenKey, SealKey},
    policy::LabelId,
    zeroize::Zeroize as _,
};
use buggy::BugExt as _;

#[allow(unused_imports)]
use crate::features::*;
use crate::{
    buf::Buf,
    error::Error,
    header::{DataHeader, Header, HeaderError, MsgType, Version},
    replay::{DEFAULT_REPLAY_WINDOW, ReplayWindow},
    state::{AfcState, LocalChannelId},
    util::debug,
};

/// Client is a connection to Aranya.
///
/// See the crate documentation for more information.
#[derive(Debug)]
pub struct Client<S> {
    state: S,
    /// The [`ReplayWindow`] size for new [`OpenCtx`]s.
    replay_window: u16,
}

impl<S> Client<S> {
    /// Create a [`Client`] with the [`DEFAULT_REPLAY_WINDOW`].
    pub const fn new(state: S) -> Self {
        Self {
            state,
            replay_window: DEFAULT_REPLAY_WINDOW,
        }
    }

    /// Create a [`Client`] whose [`OpenCtx`]s use a
    /// [`ReplayWindow`] of `size` frames.
    ///
    /// `size` must be in `1..=MAX_REPLAY_WINDOW`; larger windows
    /// tolerate deeper reordering at a cost of one bit per
    /// position. See [`ReplayWindow`] for details.
    ///
    /// [`MAX_REPLAY_WINDOW`]: crate::MAX_REPLAY_WINDOW
    pub fn with_replay_window(state: S, size: u16) -> Result<Self, Error> {
        ReplayWindow::validate(size)?;
        Ok(Self {
            state,
            replay_window: size,
        })
    }

    /// Returns the current state.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Returns the [`ReplayWindow`] size used for new
    /// [`OpenCtx`]s.
    pub const fn replay_window(&self) -> u16 {
        self.replay_window
    }
}

/// Opening context with replay protection.
///
/// Wraps the state's [`AfcState::OpenCtx`] together with the
/// channel's [`ReplayWindow`]. Created by
/// [`Client::setup_open_ctx`].
#[derive(Debug)]
pub struct OpenCtx<C> {
    inner: C,
    window: ReplayWindow,
}

impl<C> OpenCtx<C> {
    /// Returns the underlying [`AfcState::OpenCtx`].
    pub const fn inner(&self) -> &C {
        &self.inner
    }

    /// Returns the underlying [`AfcState::OpenCtx`].
    pub const fn inner_mut(&mut self) -> &mut C {
        &mut self.inner
    }

    /// Returns the channel's [`ReplayWindow`].
    pub const fn window(&self) -> &ReplayWindow {
        &self.window
    }
}

impl<S: AfcState> Client<S> {
    /// The number of additional octets required to encrypt
    /// plaintext data.
    pub const OVERHEAD: usize = match Self::TAG_SIZE.checked_add(DataHeader::PACKED_SIZE) {
        Some(n) => n,
        None => panic!("`SealKey::OVERHEAD` + `DataHeader::PACKED_SIZE` overflows"),
    };

    /// The size in octets of `SealKey`'s auth overhead.
    const TAG_SIZE: usize = SealKey::<S::CipherSuite>::OVERHEAD;

    #[cold]
    fn unlikely<T>(v: T) -> T {
        v
    }

    /// Set up the seal context for the given channel.
    ///
    /// This must only be called once for any given channel ID. Failure to
    /// do so will result in repeated usage of sequence numbers and thus a
    /// repeated use of a nonce. This will open the channel up to a variety
    /// of attacks and remove any security guarantees.
    pub fn setup_seal_ctx(&self, id: LocalChannelId) -> Result<S::SealCtx, Error> {
        self.state.setup_seal_ctx(id)
    }

    /// Set up the open context for the given channel.
    ///
    /// The returned context carries the channel's
    /// [`ReplayWindow`]. It should be created once per channel
    /// per process and reused for every frame on that channel:
    /// a fresh context has no history, so frames received before
    /// it was created can be accepted again (once each) until the
    /// window catches up. This is the same class of exposure the
    /// seal side accepts for its own sequence counter.
    pub fn setup_open_ctx(&self, id: LocalChannelId) -> Result<OpenCtx<S::OpenCtx>, Error> {
        let inner = self.state.setup_open_ctx(id)?;
        Ok(OpenCtx {
            inner,
            // `replay_window` was validated at construction.
            window: ReplayWindow::new_unchecked(self.replay_window),
        })
    }

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + Client::OVERHEAD` bytes
    /// long.
    pub fn seal(
        &self,
        ctx: &mut S::SealCtx,
        dst: &mut [u8],
        plaintext: &[u8],
    ) -> Result<Header, Error> {
        // Is `dst` large enough?
        let ciphertext_len = plaintext
            .len()
            .checked_add(Self::OVERHEAD)
            .ok_or_else(|| Self::unlikely(Error::InputTooLarge))?;
        // Limit `dst` to just the bytes that we're writing to.
        let dst = dst
            .get_mut(..ciphertext_len)
            .ok_or_else(|| Self::unlikely(Error::BufferTooSmall))?;

        // For performance reasons, we arrange the ciphertext
        // like so:
        //    ciphertext || tag || header
        let (out, header) = dst
            .split_last_chunk_mut()
            .assume("we've already checked that `dst` contains enough space")?;

        self.do_seal(ctx, header, |aead, ad| {
            aead.seal(out, plaintext, ad).map_err(Into::into)
        })
        // This isn't necessary since AEAD encryption shouldn't
        // leak any plaintext on failure, but it doesn't hurt to
        // be extra careful.
        .inspect_err(|_| {
            dst.zeroize();
            Self::unlikely(());
        })
    }

    /// Encrypts and authenticates `data` for a channel.
    ///
    /// The resulting ciphertext is written in-place to `data`.
    pub fn seal_in_place<T: Buf>(
        &self,
        ctx: &mut S::SealCtx,
        data: &mut T,
    ) -> Result<Header, Error> {
        // Ensure we have space for the header and tag. Don't
        // over allocate, though, since we don't know if we'll be
        // performing future allocations.
        data.try_reserve_exact(Self::OVERHEAD)?;

        // Append zeros for the tag and header.
        data.try_resize(data.len() + Self::OVERHEAD, 0)?;

        // We've padded data, so split it into chunks.
        //
        // For performance reasons, we arrange the ciphertext
        // like so:
        //    ciphertext || tag || header
        let (rest, header) = data
            .split_last_chunk_mut()
            .assume("we've already checked that `data` can fit a header")?;
        let (out, tag) = rest
            .split_at_mut_checked(rest.len() - Self::TAG_SIZE)
            .assume("we've already checked that `data` can fit a tag")?;

        self.do_seal(ctx, header, |aead, ad| {
            aead.seal_in_place(out, tag, ad).map_err(Into::into)
        })
        // This isn't strictly necessary since AEAD
        // encryption shouldn't leak any plaintext on
        // failure, but it doesn't hurt to be extra careful.
        .inspect_err(|_| {
            data.zeroize();
            Self::unlikely(());
        })
    }

    /// Initializes `header` and invokes `f` with the key for
    /// `id`.
    fn do_seal<F>(
        &self,
        ctx: &mut S::SealCtx,
        header: &mut [u8; DataHeader::PACKED_SIZE],
        f: F,
    ) -> Result<Header, Error>
    where
        F: FnOnce(
            /* aead: */ &mut SealKey<S::CipherSuite>,
            /* ad: */ &AuthData,
        ) -> Result<Seq, Error>,
    {
        let seq = self.state.seal(ctx, |aead, label_id| {
            let ad = AuthData {
                // TODO(eric): update `AuthData` to use `u16`.
                version: u32::from(Version::current().to_u16()),
                label_id,
            };
            f(aead, &ad)
        })??;
        debug!("seq={seq}");

        DataHeader { seq }.encode(header)?;

        Ok(Header {
            version: Version::current(),
            msg_type: MsgType::Data,
        })
    }

    /// Decrypts and authenticates `ciphertext` received from
    /// from `peer`.
    ///
    /// The resulting plaintext is written to `dst`, which must
    /// be at least `ciphertext.len() - Client::OVERHEAD` bytes
    /// long.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    ///
    /// The sequence number is checked against the context's
    /// [`ReplayWindow`] before any cryptographic work is done;
    /// a duplicate or too-old frame fails with
    /// [`Error::ReplayedSeq`]. The window is only advanced after
    /// the ciphertext has been authenticated.
    pub fn open(
        &self,
        ctx: &mut OpenCtx<S::OpenCtx>,
        dst: &mut [u8],
        ciphertext: &[u8],
    ) -> Result<(LabelId, Seq), Error> {
        // NB: For performance reasons, `data` is arranged
        // like so:
        //    ciphertext || tag || header

        let (seq, ciphertext) = {
            let (ciphertext, header) = ciphertext
                .split_last_chunk()
                .ok_or(HeaderError::InvalidSize)?;
            let DataHeader { seq, .. } = DataHeader::try_parse(header)?;

            (seq, ciphertext)
        };
        debug!(
            "seq={seq} ciphertext=[{:?}; {}]",
            ciphertext.as_ptr(),
            ciphertext.len()
        );

        // Reject replays before doing any cryptographic work.
        ctx.window.check(seq)?;

        let plaintext_len = ciphertext
            .len()
            .checked_sub(Self::TAG_SIZE)
            // We're missing an authentication tag, so by
            // definition we cannot authenticate the ciphertext.
            .ok_or(Error::Authentication)?;
        if unlikely!(dst.len() < plaintext_len) {
            // Not enough room to write plaintext.
            return Err(Error::BufferTooSmall);
        }

        let label_id = self
            .do_open(&mut ctx.inner, seq, |aead, ad, seq| {
                aead.open(dst, ciphertext, ad, seq)?;
                Ok(ad.label_id)
            })
            // For safety's sake, overwrite the output buffer if
            // decryption fails. A good AEAD implementation
            // should already do this, but it doesn't hurt to be
            // extra careful.
            .inspect_err(|_| dst.zeroize())?;

        // The frame is authentic, so record it. Doing this only
        // after authentication means a forged frame cannot move
        // the window.
        ctx.window.commit(seq);

        // We were able to decrypt the message, meaning the label
        // is indeed valid.
        Ok((label_id, seq))
    }

    /// Decrypts and authenticates the ciphertext `data` received
    /// from `peer`.
    ///
    /// The resulting plaintext is written in-place to `data`,
    /// which will be truncated to exactly the length of the
    /// plaintext.
    ///
    /// It returns the cryptographically verified label and
    /// sequence number associated with the ciphertext.
    ///
    /// The sequence number is checked against the context's
    /// [`ReplayWindow`] before any cryptographic work is done;
    /// a duplicate or too-old frame fails with
    /// [`Error::ReplayedSeq`]. The window is only advanced after
    /// the ciphertext has been authenticated.
    pub fn open_in_place<T: Buf>(
        &self,
        ctx: &mut OpenCtx<S::OpenCtx>,
        data: &mut T,
    ) -> Result<(LabelId, Seq), Error> {
        // NB: For performance reasons, `data` is arranged
        // like so:
        //    ciphertext || tag || header

        let (seq, ciphertext) = {
            let (ciphertext, header) = data
                .split_last_chunk_mut()
                .ok_or(HeaderError::InvalidSize)?;
            let DataHeader { seq, .. } = DataHeader::try_parse(header)?;

            (seq, ciphertext)
        };

        let plaintext_len = ciphertext
            .len()
            .checked_sub(Self::TAG_SIZE)
            // We're missing an authentication tag, so by
            // definition we cannot authenticate the ciphertext.
            .ok_or(Error::Authentication)?;
        let (out, tag) = ciphertext
            .split_at_mut_checked(plaintext_len)
            .ok_or(Error::Authentication)?;
        debug!("data=[{:?}; {}]", out.as_ptr(), out.len());

        // Reject replays before doing any cryptographic work.
        ctx.window.check(seq)?;

        let label_id = self
            .do_open(&mut ctx.inner, seq, |aead, ad, seq| {
                aead.open_in_place(out, tag, ad, seq)?;
                Ok(ad.label_id)
            })
            // On success, get rid of the header and tag.
            .inspect(|_| data.truncate(plaintext_len))
            // For safety's sake, overwrite the output buffer if
            // decryption fails. A good AEAD implementation should
            // already do this, but it doesn't hurt to be extra
            // careful.
            .inspect_err(|_| data.zeroize())?;

        // The frame is authentic, so record it. Doing this only
        // after authentication means a forged frame cannot move
        // the window.
        ctx.window.commit(seq);

        // We were able to decrypt the message, meaning the label
        // is indeed valid.
        Ok((label_id, seq))
    }

    /// Invokes `f` with the key for `id`.
    fn do_open<F, T>(&self, ctx: &mut S::OpenCtx, seq: Seq, f: F) -> Result<T, Error>
    where
        F: FnOnce(
            /* aead: */ &OpenKey<S::CipherSuite>,
            /* ad: */ &AuthData,
            /* seq: */ Seq,
        ) -> Result<T, Error>,
    {
        self.state.open(ctx, |aead, label_id| {
            let ad = AuthData {
                // TODO(eric): update `AuthData` to use `u16`.
                version: u32::from(Version::current().to_u16()),
                label_id,
            };
            f(aead, &ad, seq)
        })?
    }
}

/// An APS message.
pub struct Message<'a> {
    /// The header prefixed to each message.
    pub header: Header,
    /// The contents of the message.
    pub payload: Payload<'a>,
}

impl<'a> Message<'a> {
    /// Parses a message from `buf`.
    pub fn try_parse(buf: &'a [u8]) -> Result<Self, ParseError> {
        let (header, payload) = buf.split_first_chunk().ok_or(HeaderError::InvalidSize)?;
        let header = Header::try_parse(header)?;
        let payload = match header.msg_type {
            MsgType::Data => Payload::Data(payload),
            MsgType::Control => Payload::Control(payload),
        };
        Ok(Self { header, payload })
    }
}

/// An error from [`Message::try_parse`].
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ParseError {
    /// The header is invalid.
    #[error(transparent)]
    Header(#[from] HeaderError),
}

/// The payload of a [`Message`].
pub enum Payload<'a> {
    /// A data message containing ciphertext.
    Data(&'a [u8]),
    /// An Aranya command.
    Control(&'a [u8]),
}
