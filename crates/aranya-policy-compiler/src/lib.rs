//! The Aranya policy compiler.
//!
//! See [the policy book](https://aranya-project.github.io/policy-book/) for more information on
//! the policy language.

#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod compile;
mod tests;
mod tracer;
pub mod validate;

pub use compile::*;
pub use tracer::*;

// Stub for review purposes - this will be removed in the stacked PR
pub mod obligation {
    use std::collections::BTreeMap;

    use aranya_policy_ast::{Identifier, VType, thir};

    /// The default limit on the number of exits recorded for one pure
    /// function. Functions with more are treated as unknown calls.
    pub const DEFAULT_MAX_EXIT_PATHS: usize = 64;

    /// The default limit on the number of distinct paths the analysis keeps
    /// at one point of a walk. Past it, the paths are joined into one, which
    /// keeps only what all of them know.
    pub const DEFAULT_MAX_PATHS: usize = 64;

    /// The parts of a fact's schema the analysis needs.
    #[derive(Debug)]
    pub(crate) struct FactSchema {
        /// The key fields, in schema order.
        pub(crate) keys: Vec<(Identifier, VType)>,
        /// How many value fields the fact has.
        pub(crate) values: usize,
    }

    /// A warning produced by the obligation analysis.
    pub struct ObligationWarning {}

    impl ObligationWarning {
        /// Render the warning as an annotated source snippet.
        ///
        /// `input` is the full policy source text.
        pub fn render(&self, _input: &str) -> String {
            String::new()
        }
    }

    /// Runs the obligation analysis for one policy.
    ///
    /// Function bodies are recorded as the compiler lowers them. Pure and
    /// finish functions are compiled before commands, so every body is
    /// recorded before any command block is analyzed.
    pub struct Analyzer {}

    impl Analyzer {
        pub(crate) fn new(
            _src: String,
            _globals: Vec<Identifier>,
            _facts: BTreeMap<Identifier, FactSchema>,
            _max_exit_paths: usize,
            _max_paths: usize,
        ) -> Self {
            Self {}
        }

        /// Record a finish function's lowered body.
        pub fn record_finish_function(
            &mut self,
            _name: Identifier,
            _args: Vec<Identifier>,
            _statements: Vec<thir::Statement>,
        ) {
        }

        /// Record a pure function's lowered body.
        pub(crate) fn record_pure_function(
            &mut self,
            _name: Identifier,
            _params: Vec<Identifier>,
            _statements: Vec<thir::Statement>,
        ) {
        }

        /// Analyze the lowered statements of a command `policy` or `recall`
        /// block.
        ///
        /// `empty_db` is true for the blocks of an `init` command, which always
        /// runs against an empty fact database: the runtime only accepts an
        /// init command as the root of the graph.
        pub fn analyze_block(
            &mut self,
            _statements: &[thir::Statement],
            _empty_db: bool,
            _command: Identifier,
        ) -> Vec<ObligationWarning> {
            Vec::new()
        }
    }

    /// Collapse warnings that differ only in their notes, as [`add_warning`]
    /// does.
    pub(crate) fn dedup_warnings(_warnings: Vec<ObligationWarning>) -> Vec<ObligationWarning> {
        Vec::new()
    }
}
