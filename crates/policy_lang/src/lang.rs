pub mod ast;
mod parse;

pub use parse::{
    extract_policy, get_pratt_parser, parse_expression, parse_policy_document, parse_policy_str,
    ParseError, ParseErrorKind, PolicyParser, Rule,
};

/// Policy language version
#[derive(Debug, Clone, PartialEq, Copy)]
pub enum Version {
    /// Version 3, the initial version of the "new" policy language.
    V3,
}

/// This supports the command-line tools, allowing automatic conversion
/// between string arguments and the enum.
impl std::str::FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "v3" => Ok(Version::V3),
            _ => Err(format!("unkown version: {}", s)),
        }
    }
}
