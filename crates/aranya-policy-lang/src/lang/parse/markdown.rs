use aranya_policy_ast as ast;
use buggy::BugExt as _;
use markdown::{
    ParseOptions,
    mdast::{Node, Yaml},
    to_mdast,
};
use serde::Deserialize;

use super::{ParseError, ParseErrorKind, Version, parse_policy_chunk};
use crate::lang::parse::ReportCell;

#[derive(Deserialize)]
struct FrontMatter {
    #[serde(rename(deserialize = "policy-version"))]
    policy_version: String,
}

fn parse_front_matter(yaml: &Yaml) -> Result<Version, ParseError<'static>> {
    let fm: FrontMatter = serde_yaml::from_str(&yaml.value)
        .map_err(|e| ParseError::new(ParseErrorKind::FrontMatter, e.to_string(), None))?;
    let v = match fm.policy_version.as_str() {
        "2" => Version::V2,
        v => {
            return Err(ParseError::new(
                ParseErrorKind::InvalidVersion {
                    found: v.to_string(),
                    required: Version::V2,
                },
                Version::help_message(),
                None,
            ));
        }
    };
    Ok(v)
}

#[derive(Debug)]
pub struct PolicyChunk {
    pub text: String,
    pub start: ChunkOffset,
}

#[derive(Default, Debug)]
pub struct ChunkOffset {
    /// 0-based line offset of policy code within document.
    pub line: usize,
    /// 0-based byte offset of policy code within document.
    pub byte: usize,
}

fn extract_policy_from_markdown(
    node: &Node,
) -> Result<(Vec<PolicyChunk>, Version), ParseError<'static>> {
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
                        let point = &c.position.as_ref().expect("no code block position").start;

                        // The 1-based start line of the code block is
                        // the 0-based start line of the policy code.
                        let line = point.line;

                        // The starting position of the code block is
                        // the triple-backtick, so add three for the
                        // backticks, six for the language tag, and
                        // one newline.
                        let byte = point
                            .offset
                            .checked_add(10)
                            .assume("start.offset + 10 must not wrap")?;

                        chunks.push(PolicyChunk {
                            text: c.value.clone(),
                            start: ChunkOffset { line, byte },
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

/// Parses a Markdown policy document into an AST. This AST will likely be further processed
/// by the [`Compiler`](../../policy_vm/struct.Compiler.html).
pub fn parse_policy_document(data: &str) -> Result<ast::Policy, ReportCell> {
    let (chunks, version) = extract_policy(data).map_err(ParseError::into_report)?;
    if chunks.is_empty() {
        return Err(ParseError::new(
            ParseErrorKind::Unknown,
            String::from("No policy code found in Markdown document"),
            None,
        )
        .into_report());
    }
    let mut policy = ast::Policy::new(version, data);
    for c in chunks {
        parse_policy_chunk(&c.text, &mut policy, c.start)?;
    }
    Ok(policy)
}

/// Extract the policy chunks from a Markdown policy document. Returns the chunks plus the
/// policy version.
fn extract_policy(data: &str) -> Result<(Vec<PolicyChunk>, Version), ParseError<'_>> {
    let mut parseoptions = ParseOptions::gfm();
    parseoptions.constructs.frontmatter = true;
    let tree = to_mdast(data, &parseoptions)
        .map_err(|s| ParseError::new(ParseErrorKind::Unknown, s.to_string(), None))?;
    let (chunks, version) = extract_policy_from_markdown(&tree)?;
    Ok((chunks, version))
}
