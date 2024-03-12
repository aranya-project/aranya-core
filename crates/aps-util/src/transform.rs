use core::convert::Infallible;

use crypto::{
    aps::{
        BidiAuthorSecret, BidiChannel, BidiKeys, BidiPeerEncap, OpenKey, RawOpenKey, RawSealKey,
        SealKey, UniAuthorSecret, UniChannel, UniOpenKey, UniPeerEncap, UniSealKey,
    },
    CipherSuite,
};

/// Like [`TryFrom`], but with a different spelling.
pub trait Transform<T>: Sized {
    /// The error returned from [`transform`][Self::transform].
    type Error: trouble::Error;

    /// Transforms `value` into `Self`.
    fn transform(value: T) -> Result<Self, Self::Error>;
}

impl<C, T> Transform<(C, T)> for (C, T) {
    type Error = Infallible;

    fn transform(value: (C, T)) -> Result<Self, Self::Error> {
        Ok(value)
    }
}

// TODO(eric): I'm not sure we need this impl since we only
// really care about `Transform<(C, T)> -> (S, O)`.
impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiAuthorSecret<CS>)> for BidiKeys<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_author_secret(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiAuthorSecret<CS>)>
    for (SealKey<CS>, OpenKey<CS>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_author_secret(ch, secret)?.into_keys()
    }
}

impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiAuthorSecret<CS>)>
    for (RawSealKey<CS>, RawOpenKey<CS>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(BidiKeys::from_author_secret(ch, secret)?.into_raw_keys())
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for UniSealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        Self::from_author_secret(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for UniOpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        Self::from_author_secret(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for SealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        UniSealKey::from_author_secret(ch, secret)?.into_key()
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for OpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        UniOpenKey::from_author_secret(ch, secret)?.into_key()
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for RawSealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(UniSealKey::from_author_secret(ch, secret)?.into_raw_key())
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniAuthorSecret<CS>)> for RawOpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniAuthorSecret<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(UniOpenKey::from_author_secret(ch, secret)?.into_raw_key())
    }
}

// TODO(eric): I'm not sure we need this impl since we only
// really care about `Transform<(C, T)> -> (S, O)`.
impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiPeerEncap<CS>)> for BidiKeys<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_peer_encap(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiPeerEncap<CS>)>
    for (SealKey<CS>, OpenKey<CS>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_peer_encap(ch, secret)?.into_keys()
    }
}

impl<CS: CipherSuite> Transform<(&BidiChannel<'_, CS>, BidiPeerEncap<CS>)>
    for (RawSealKey<CS>, RawOpenKey<CS>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, CS>, BidiPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(BidiKeys::from_peer_encap(ch, secret)?.into_raw_keys())
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for UniSealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        Self::from_peer_encap(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for UniOpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        Self::from_peer_encap(ch, secret)
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for SealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        UniSealKey::from_peer_encap(ch, secret)?.into_key()
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for OpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        UniOpenKey::from_peer_encap(ch, secret)?.into_key()
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for RawSealKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(UniSealKey::from_peer_encap(ch, secret)?.into_raw_key())
    }
}

impl<CS: CipherSuite> Transform<(&UniChannel<'_, CS>, UniPeerEncap<CS>)> for RawOpenKey<CS> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, CS>, UniPeerEncap<CS>),
    ) -> Result<Self, Self::Error> {
        Ok(UniOpenKey::from_peer_encap(ch, secret)?.into_raw_key())
    }
}
