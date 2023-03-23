pub mod ast;
mod parse;

pub use parse::{
    extract_policy, get_pratt_parser, parse_expression, parse_policy_document, parse_policy_str,
    ParseError, PolicyParser, Rule,
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
