use core::num::NonZeroUsize;

/// Not a valid `Text` value.
#[derive(Clone, Debug, thiserror::Error)]
#[error(transparent)]
pub struct InvalidText(pub(crate) InvalidTextRepr);

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum InvalidTextRepr {
    /// Text contained nul byte.
    #[error("text contained nul byte at index {index}")]
    ContainsNul {
        /// Index of first nul byte.
        index: usize,
    },
}

/// Not a valid `Identifier` value.
#[derive(Clone, Debug, thiserror::Error)]
#[error(transparent)]
pub struct InvalidIdentifier(pub(crate) InvalidIdentifierRepr);

#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum InvalidIdentifierRepr {
    /// Identifier must start with alphabetic character.
    #[error("identifier must not be empty")]
    NotEmpty,
    /// Identifier must start with alphabetic character.
    #[error("identifier must start with alphabetic character")]
    InitialNotAlphabetic,
    /// Identifier contained invalid character.
    #[error("identifier contained invalid character at index {index}")]
    TrailingNotValid {
        /// Index of first invalid character.
        index: NonZeroUsize,
    },
}
