//! Differential testing of braid order against a naive reference oracle.
//!
//! The oracle ([`naive::naive_braid`]) lives in [`naive`], a standalone module
//! that shares no code with the production braid. The rest of this module is
//! the harness around it, split by concern:
//!
//! - [`shapes`] enumerates the graph shapes worth testing — pure combinatorics,
//!   no runtime dependencies ([`shapes::enumerate_braidable`]).
//! - [`policy`] is the minimal production plumbing that records evaluation
//!   order (the probe policy).
//! - [`harness`] builds a shape's production graph through the real
//!   client/sync machinery and diffs it against the oracle
//!   ([`harness::check_program`]).
//!
//! **Graph shape is the only variable, and only shapes a client can actually
//! hold are tested.** A peer's own commands form a chain, so a graph is never
//! wider than the peer count ([`shapes::PEERS`]); every such graph is reachable
//! because partial sync delivers any causal prefix (even a bare merge head). So
//! the realizable shapes are exactly the braidable prime blocks that
//! [`shapes::enumerate_braidable`] walks, and [`harness::shape_only_program`]
//! pairs each with a canonical distributed schedule that builds it.
//!
//! A mismatch implicates one of: the production braid walk, the incremental
//! composition of braids (LCA seeding, fact-index reuse across commits), the
//! sync protocol (segment selection, `PeerCache`), or the braid rules the
//! oracle encodes. All are findings worth investigating.

pub mod harness;
pub mod naive;
pub mod policy;
pub mod shapes;
