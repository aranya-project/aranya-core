/// A diagnostic error.
#[derive(Copy, Clone, Debug)]
pub struct Error {
    /// The error message.
    pub msg: &'static str,
    /// A label describing the section of code that failed.
    pub label: Option<&'static str>,
    /// A hint, warning, etc.
    pub note: Option<&'static str>,
}

/// Static errors produced by this crate.
pub static ERRORS: &[Error] = &[];
