use ::markdown::{
    mdast::{Node, Yaml},
    to_mdast, ParseOptions,
};
use serde::Deserialize;

use crate::lang::{ast, parse_policy_str, ParseError, ParseErrorKind, Version};

#[derive(Deserialize)]
struct FrontMatter {
    #[serde(rename(deserialize = "policy-version"))]
    policy_version: String,
}

fn parse_front_matter(yaml: &Yaml) -> Result<Version, ParseError> {
    let fm: FrontMatter = serde_yaml::from_str(&yaml.value)
        .map_err(|e| ParseError::new(ParseErrorKind::FrontMatter, e.to_string(), None))?;
    let v = match fm.policy_version.as_str() {
        "3" => Version::V3,
        _ => {
            return Err(ParseError::new(
                ParseErrorKind::InvalidVersion,
                fm.policy_version,
                None,
            ))
        }
    };
    Ok(v)
}

fn extract_policy_from_markdown(node: &Node) -> Result<(String, Version), ParseError> {
    let mut policy_text = String::new();
    if let Node::Root(r) = node {
        let mut child_iter = r.children.iter();
        // The front matter should always be the first node below the
        // root.
        let version = if let Some(Node::Yaml(y)) = child_iter.next() {
            parse_front_matter(y)?
        } else {
            return Err(ParseError::new(
                ParseErrorKind::FrontMatter,
                String::from("No front matter found"),
                None,
            ));
        };

        // We are only looking for top level code blocks. If someone
        // sneaks one into a table or something we won't see it.
        for c in child_iter {
            if let Node::Code(c) = c {
                if let Some(lang) = &c.lang {
                    if lang == "policy" {
                        policy_text.push_str(&c.value);
                    }
                }
            }
        }
        Ok((policy_text, version))
    } else {
        Err(ParseError::new(
            ParseErrorKind::Unknown,
            String::from("Did not get Markdown Root node"),
            None,
        ))
    }
}

pub fn parse_policy_document(data: &str) -> Result<ast::Policy, ParseError> {
    let (policy_text, version) = extract_policy(data)?;
    parse_policy_str(&policy_text, version)
}

pub fn extract_policy(data: &str) -> Result<(String, Version), ParseError> {
    let mut parseoptions = ParseOptions::gfm();
    parseoptions.constructs.frontmatter = true;
    let tree = to_mdast(data, &parseoptions)
        .map_err(|s| ParseError::new(ParseErrorKind::Unknown, s, None))?;
    let (policy_text, version) = extract_policy_from_markdown(&tree)?;
    Ok((policy_text, version))
}
