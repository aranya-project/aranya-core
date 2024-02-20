use core::convert::Infallible;

use crypto::{
    aps::{
        BidiAuthorSecret, BidiChannel, BidiKeys, BidiPeerEncap, OpenKey, RawOpenKey, RawSealKey,
        SealKey, UniAuthorSecret, UniChannel, UniOpenKey, UniPeerEncap, UniSealKey,
    },
    Engine,
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
impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiAuthorSecret<E>)> for BidiKeys<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_author_secret(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiAuthorSecret<E>)>
    for (SealKey<E>, OpenKey<E>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_author_secret(ch, secret)?.into_keys()
    }
}

impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiAuthorSecret<E>)>
    for (RawSealKey<E>, RawOpenKey<E>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        Ok(BidiKeys::from_author_secret(ch, secret)?.into_raw_keys())
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for UniSealKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        Self::from_author_secret(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for UniOpenKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        Self::from_author_secret(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for SealKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        UniSealKey::from_author_secret(ch, secret)?.into_key()
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for OpenKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        UniOpenKey::from_author_secret(ch, secret)?.into_key()
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for RawSealKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        Ok(UniSealKey::from_author_secret(ch, secret)?.into_raw_key())
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniAuthorSecret<E>)> for RawOpenKey<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&UniChannel<'_, E>, UniAuthorSecret<E>),
    ) -> Result<Self, Self::Error> {
        Ok(UniOpenKey::from_author_secret(ch, secret)?.into_raw_key())
    }
}

// TODO(eric): I'm not sure we need this impl since we only
// really care about `Transform<(C, T)> -> (S, O)`.
impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiPeerEncap<E>)> for BidiKeys<E> {
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiPeerEncap<E>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_peer_encap(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiPeerEncap<E>)>
    for (SealKey<E>, OpenKey<E>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiPeerEncap<E>),
    ) -> Result<Self, Self::Error> {
        BidiKeys::from_peer_encap(ch, secret)?.into_keys()
    }
}

impl<E: Engine + ?Sized> Transform<(&BidiChannel<'_, E>, BidiPeerEncap<E>)>
    for (RawSealKey<E>, RawOpenKey<E>)
{
    type Error = crypto::Error;

    fn transform(
        (ch, secret): (&BidiChannel<'_, E>, BidiPeerEncap<E>),
    ) -> Result<Self, Self::Error> {
        Ok(BidiKeys::from_peer_encap(ch, secret)?.into_raw_keys())
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for UniSealKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        Self::from_peer_encap(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for UniOpenKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        Self::from_peer_encap(ch, secret)
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for SealKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        UniSealKey::from_peer_encap(ch, secret)?.into_key()
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for OpenKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        UniOpenKey::from_peer_encap(ch, secret)?.into_key()
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for RawSealKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        Ok(UniSealKey::from_peer_encap(ch, secret)?.into_raw_key())
    }
}

impl<E: Engine + ?Sized> Transform<(&UniChannel<'_, E>, UniPeerEncap<E>)> for RawOpenKey<E> {
    type Error = crypto::Error;

    fn transform((ch, secret): (&UniChannel<'_, E>, UniPeerEncap<E>)) -> Result<Self, Self::Error> {
        Ok(UniOpenKey::from_peer_encap(ch, secret)?.into_raw_key())
    }
}
