#![cfg(test)]
#![allow(clippy::panic)]

use pest::Parser as _;

use super::{Pair, PolicyParser, Result, Rule};

#[test]
fn parse_field() -> Result<()> {
    let mut pairs = PolicyParser::parse(Rule::field_definition, "bar: int")?;

    let tokens: Vec<Pair> = pairs.next().unwrap().into_inner().collect();
    assert_eq!(tokens[0].as_rule(), Rule::identifier);
    assert_eq!(tokens[0].as_str(), "bar");
    assert_eq!(tokens[1].as_rule(), Rule::int_t);
    assert_eq!(tokens[1].as_str(), "int");
    Ok(())
}
