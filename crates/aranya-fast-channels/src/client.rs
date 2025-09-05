#[doc(inline)]
pub use aranya_crypto::afc::Seq;
use aranya_crypto::{
    afc::{AuthData, OpenKey, SealKey},
    policy::LabelId,
    zeroize::Zeroize,
};
use buggy::BugExt;

#[allow(unused_imports)]
use crate::features::*;
use crate::{
    buf::Buf,
    error::Error,
    header::{DataHeader, Header, HeaderError, MsgType, Version},
    state::{AfcState, ChannelId},
    util::debug,
};

/// Client is a connection to Aranya.
///
/// See the crate documentation for more information.
#[derive(Debug)]
pub struct Client<S> {
    state: S,
}

impl<S> Client<S> {
    /// Create a [`Client`].
    pub const fn new(state: S) -> Self {
        Client { state }
    }

    /// Returns the current state.
    pub fn state(&self) -> &S {
        &self.state
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

    /// Encrypts and authenticates `plaintext` for a channel.
    ///
    /// The resulting ciphertext is written to `dst`, which must
    /// be at least `plaintext.len() + Client::OVERHEAD` bytes
    /// long.
    pub fn seal(
        &mut self,
        id: ChannelId,
        label_id: LabelId,
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

        self.do_seal(id, label_id, header, |aead, ad| {
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
        &mut self,
        id: ChannelId,
        label_id: LabelId,
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
        #[allow(clippy::incompatible_msrv)] // clippy#12280
        let (out, tag) = rest
            .split_at_mut_checked(rest.len() - Self::TAG_SIZE)
            .assume("we've already checked that `data` can fit a tag")?;

        self.do_seal(id, label_id, header, |aead, ad| {
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
        &mut self,
        id: ChannelId,
        label_id: LabelId,
        header: &mut [u8; DataHeader::PACKED_SIZE],
        f: F,
    ) -> Result<Header, Error>
    where
        F: FnOnce(
            /* aead: */ &mut SealKey<S::CipherSuite>,
            /* ad: */ &AuthData,
        ) -> Result<Seq, Error>,
    {
        debug!("finding seal info: id={id}");

        let seq = self.state.seal(id, label_id, |aead| {
            debug!("encrypting id={id}");

            let ad = AuthData {
                // TODO(eric): update `AuthData` to use `u16`.
                version: u32::from(Version::current().to_u16()),
                label_id,
            };
            f(aead, &ad)
        })??;
        debug!("seq={seq}");

        DataHeader { seq, label_id }.encode(header)?;

        Ok(Header {
            version: Version::current(),
            msg_type: MsgType::Data,
            label_id,
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
    pub fn open(
        &self,
        channel_id: ChannelId,
        label_id: LabelId,
        dst: &mut [u8],
        ciphertext: &[u8],
    ) -> Result<(LabelId, Seq), Error> {
        // NB: For performance reasons, `data` is arranged
        // like so:
        //    ciphertext || tag || header

        let (label_id, seq, ciphertext) = {
            let (ciphertext, header) = ciphertext
                .split_last_chunk()
                .ok_or(HeaderError::InvalidSize)?;
            let DataHeader {
                label_id: label_id_from_header,
                seq,
                ..
            } = DataHeader::try_parse(header)?;

            if label_id_from_header != label_id {
                return Err(Error::InvalidLabel(label_id_from_header, label_id));
            }

            (label_id_from_header, seq, ciphertext)
        };
        debug!(
            "label_id={label_id}  seq={seq} ciphertext=[{:?}; {}] channel_id={channel_id}",
            ciphertext.as_ptr(),
            ciphertext.len()
        );

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

        self.do_open(channel_id, label_id, seq, |aead, ad, seq| {
            aead.open(dst, ciphertext, ad, seq).map_err(Into::into)
        })
        // For safety's sake, overwrite the output buffer if
        // decryption fails. A good AEAD implementation
        // should already do this, but it doesn't hurt to be
        // extra careful.
        .inspect_err(|_| dst.zeroize())?;

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
    pub fn open_in_place<T: Buf>(
        &self,
        channel_id: ChannelId,
        label_id: LabelId,
        data: &mut T,
    ) -> Result<(LabelId, Seq), Error> {
        // NB: For performance reasons, `data` is arranged
        // like so:
        //    ciphertext || tag || header

        // Split `data` into its components.
        let (label_id, seq, out, tag) = {
            let (rest, header) = data
                .split_last_chunk_mut()
                .ok_or(HeaderError::InvalidSize)?;
            let DataHeader {
                label_id: label_id_from_header,
                seq,
                ..
            } = DataHeader::try_parse(header)?;

            if label_id != label_id_from_header {
                return Err(Error::InvalidLabel(label_id_from_header, label_id));
            }

            #[allow(clippy::incompatible_msrv)] // clippy#12280
            let (ciphertext, tag) = rest
                .split_at_mut_checked(rest.len() - Self::TAG_SIZE)
                // Missing an authentication tag, so by
                // definition we cannot authenticate the
                // ciphertext.
                .ok_or(Error::Authentication)?;
            (label_id_from_header, seq, ciphertext, tag)
        };
        debug!(
            "channel_id={channel_id} label_id={label_id} data=[{:?}; {}]",
            out.as_ptr(),
            out.len()
        );

        let plaintext_len = out.len();
        self.do_open(channel_id, label_id, seq, |aead, ad, seq| {
            aead.open_in_place(out, tag, ad, seq).map_err(Into::into)
        })
        // On success, get rid of the header and tag.
        .inspect(|()| data.truncate(plaintext_len))
        // For safety's sake, overwrite the output buffer if
        // decryption fails. A good AEAD implementation should
        // already do this, but it doesn't hurt to be extra
        // careful.
        .inspect_err(|_| data.zeroize())?;

        // We were able to decrypt the message, meaning the label
        // is indeed valid.
        Ok((label_id, seq))
    }

    /// Invokes `f` with the key for `id`.
    fn do_open<F, T>(&self, id: ChannelId, label_id: LabelId, seq: Seq, f: F) -> Result<T, Error>
    where
        F: FnOnce(
            /* aead: */ &OpenKey<S::CipherSuite>,
            /* ad: */ &AuthData,
            /* seq: */ Seq,
        ) -> Result<T, Error>,
    {
        debug!("decrypting: id={id}");

        let ad = AuthData {
            // TODO(eric): update `AuthData` to use `u16`.
            version: u32::from(Version::current().to_u16()),
            label_id,
        };
        self.state.open(id, label_id, |aead| f(aead, &ad, seq))?
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
