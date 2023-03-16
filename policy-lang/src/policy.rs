mod parse;
pub mod ast;

pub use parse::{
    PolicyParser,
    Rule,
    ParseError,
    get_pratt_parser,
    parse_policy_str,
    parse_expression,
    parse_policy_document,
    extract_policy,
};

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum Version {
    V3,
}

impl std::str::FromStr for Version {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "v3" => Ok(Version::V3),
            _ => Err(format!("unkown version: {}", s)),
        }
    }
}