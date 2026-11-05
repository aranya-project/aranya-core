#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use aranya_policy_ast::Version;
use aranya_policy_lang::lang::{parse_policy_document, parse_policy_str};
use tryfn::{Case, Data, Harness};

fn main() {
    Harness::new("tests/data", setup, test)
        .select(["*.policy", "*.md"])
        .test();
}

fn setup(path: PathBuf) -> Case {
    Case {
        name: get_name(&path).unwrap(),
        expected: Data::read_from(&path.with_extension("snap"), None).raw(),
        fixture: path,
    }
}

fn test(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).context("could not read source file")?;
    let res = match path.extension().and_then(|ext| ext.to_str()) {
        Some("policy") => parse_policy_str(&text, Version::V2),
        Some("md") => parse_policy_document(&text),
        _ => bail!("unknown extension {:?}", path.extension()),
    };
    Ok(match res {
        Ok(ast) => format!("{ast:#?}\n"),
        Err(err) => format!("{err}\n"),
    })
}

fn get_name(path: &Path) -> Result<String> {
    Ok(path
        .strip_prefix("tests/data/")?
        .with_extension("")
        .to_string_lossy()
        .into_owned())
}
