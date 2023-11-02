use markdown::{
    mdast::{Node, Yaml},
    to_mdast, ParseOptions,
};
use policy_ast as ast;
use serde::Deserialize;

use crate::lang::{parse_policy_chunk, ParseError, ParseErrorKind, Version};

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

#[derive(Debug)]
pub struct PolicyChunk {
    pub text: String,
    pub offset: usize,
}

fn extract_policy_from_markdown(node: &Node) -> Result<(Vec<PolicyChunk>, Version), ParseError> {
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

        let mut chunks = vec![];

        // We are only looking for top level code blocks. If someone
        // sneaks one into a table or something we won't see it.
        for c in child_iter {
            if let Node::Code(c) = c {
                if let Some(lang) = &c.lang {
                    if lang == "policy" {
                        let position = c.position.as_ref().expect("no code block position");
                        // The starting position of the code block is
                        // the triple-backtick, so add three for the
                        // backticks, six for the language tag, and
                        // one newline.
                        let offset = position.start.offset + 10;
                        chunks.push(PolicyChunk {
                            text: c.value.clone(),
                            offset,
                        });
                    }
                }
            }
        }
        Ok((chunks, version))
    } else {
        Err(ParseError::new(
            ParseErrorKind::Unknown,
            String::from("Did not find Markdown Root node"),
            None,
        ))
    }
}

pub fn parse_policy_document(data: &str) -> Result<ast::Policy, ParseError> {
    let (chunks, version) = extract_policy(data)?;
    let mut policy = ast::Policy::new(version, data);
    for c in chunks {
        parse_policy_chunk(&c.text, &mut policy, c.offset)?;
    }
    Ok(policy)
}

pub fn extract_policy(data: &str) -> Result<(Vec<PolicyChunk>, Version), ParseError> {
    let mut parseoptions = ParseOptions::gfm();
    parseoptions.constructs.frontmatter = true;
    let tree = to_mdast(data, &parseoptions)
        .map_err(|s| ParseError::new(ParseErrorKind::Unknown, s, None))?;
    let (chunks, version) = extract_policy_from_markdown(&tree)?;
    Ok((chunks, version))
}