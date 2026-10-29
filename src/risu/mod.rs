//! `RISU`-style constrained-random instruction & system-state fuzzing engine.

pub mod encode;
mod fp_edges;
pub mod harness;
pub mod seed;
pub mod suite;

pub use harness::{BisectReport, RisuCase, RisuHarness};
pub use suite::Suite;
